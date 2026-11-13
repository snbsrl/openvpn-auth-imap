#!/usr/bin/env perl
#
# fake-imapd.pl - minimal IMAP server for testing openvpn-auth-imap.
#
# Implements just enough of RFC 3501 for a client to log in:
# CAPABILITY, STARTTLS, LOGIN, AUTHENTICATE PLAIN, NOOP, LOGOUT.
#
# Options:
#   --port N           listen port (0 = pick a free one)
#   --portfile FILE    write the chosen port here once listening
#   --log FILE         append one line per event (CONNECT, LOGIN_OK user, ...)
#   --user U:P         accepted credentials (repeatable)
#   --tls none|imaps|starttls
#   --cert FILE --key FILE   certificate for imaps/starttls
#   --auth login|plain|plain-only
#                      login: LOGIN only; plain: also advertise AUTH=PLAIN
#                      SASL-IR; plain-only: AUTH=PLAIN with LOGINDISABLED
#   --behaviour normal|hang|garbage|bye|preauth
#                      hang: accept the TCP connection, never greet
#                      garbage: send a non-IMAP reply and close
#                      bye: greet with "* BYE" (server unavailable)
#                      preauth: greet with "* PREAUTH" (already logged in,
#                        as an attacker injecting a greeting would)
#   --gssapi           also advertise AUTH=GSSAPI (always refused)
#   --delay SECONDS    wait this long before answering LOGIN/AUTHENTICATE
#   --no-logindisabled with --tls starttls: don't advertise LOGINDISABLED
#                      before TLS (LOGIN in clear text is still refused)
#
use strict;
use warnings;
use Fcntl qw(:flock);
use Getopt::Long;
use IO::Socket::INET;
use MIME::Base64 qw(decode_base64);
use POSIX qw(:sys_wait_h);

my %opt = (
    port      => 0,
    tls       => 'none',
    auth      => 'login',
    behaviour => 'normal',
    delay     => 0,
    logindisabled => 1,
);
my @users;
GetOptions(\%opt, 'port=i', 'portfile=s', 'log=s', 'tls=s', 'cert=s',
           'key=s', 'auth=s', 'behaviour=s', 'delay=f', 'logindisabled!', 'gssapi',
           'user=s' => \@users)
    or die "bad options\n";

my %users = map { my ($u, $p) = split /:/, $_, 2; ($u => $p) } @users;

if ($opt{tls} ne 'none') {
    require IO::Socket::SSL;
    die "--cert and --key required for TLS\n" unless $opt{cert} && $opt{key};
}

sub logmsg {
    my ($msg) = @_;
    return unless $opt{log};
    open my $fh, '>>', $opt{log} or return;
    flock $fh, LOCK_EX;
    print $fh "$msg\n";
    close $fh;
}

sub start_tls {
    my ($s) = @_;
    my $ok = IO::Socket::SSL->start_SSL(
        $s,
        SSL_server    => 1,
        SSL_cert_file => $opt{cert},
        SSL_key_file  => $opt{key},
    );
    logmsg($ok ? 'TLS_OK' : 'TLS_FAIL');
    return $ok;
}

# Unbuffered I/O through method calls, so the same code works before and
# after the socket is upgraded to TLS in place (STARTTLS).
my $rbuf = '';

sub send_line {
    my ($s, $line) = @_;
    my $data = "$line\r\n";
    while (length $data) {
        my $n = $s->syswrite($data);
        return unless defined $n && $n > 0;
        substr($data, 0, $n, '');
    }
}

sub read_line {
    my ($s) = @_;
    while ($rbuf !~ /\n/) {
        my $n = $s->sysread(my $chunk, 4096);
        return unless $n;
        $rbuf .= $chunk;
    }
    $rbuf =~ s/^(.*?)\r?\n//s;
    return $1;
}

# Parse IMAP astrings: atoms and quoted strings (with \" and \\ escapes).
sub parse_astrings {
    my ($str) = @_;
    my @out;
    while (length $str) {
        $str =~ s/^\s+//;
        last unless length $str;
        if ($str =~ s/^"((?:[^"\\]|\\.)*)"//) {
            (my $v = $1) =~ s/\\(.)/$1/g;
            push @out, $v;
        }
        elsif ($str =~ s/^([^\s"(){]+)//) {
            push @out, $1;
        }
        else {
            return;    # unsupported syntax (e.g. literals)
        }
    }
    return @out;
}

sub check_creds {
    my ($s, $tag, $user, $pass) = @_;
    select(undef, undef, undef, $opt{delay}) if $opt{delay};
    if (defined $user && defined $pass
        && exists $users{$user} && $users{$user} eq $pass) {
        logmsg("LOGIN_OK $user");
        send_line($s, "$tag OK LOGIN completed");
        return 1;
    }
    logmsg('LOGIN_FAIL ' . ($user // '?'));
    send_line($s, "$tag NO [AUTHENTICATIONFAILED] Invalid credentials");
    return 0;
}

sub handle_client {
    my ($s) = @_;
    alarm 30;    # never linger forever
    logmsg('CONNECT');

    if ($opt{behaviour} eq 'hang') {
        sleep 30;
        return;
    }
    if ($opt{behaviour} eq 'garbage') {
        send_line($s, "HTTP/1.0 400 Bad Request\r\n");
        return;
    }

    my $tls_active = 0;
    if ($opt{tls} eq 'imaps') {
        start_tls($s) or return;
        $tls_active = 1;
    }

    if ($opt{behaviour} eq 'bye') {
        send_line($s, '* BYE Server unavailable');
        return;
    }

    if ($opt{behaviour} eq 'preauth') {
        send_line($s, '* PREAUTH fake-imapd: already authenticated');
    }
    else {
        send_line($s, '* OK fake-imapd ready');
    }

    while (defined(my $line = read_line($s))) {
        my ($tag, $cmd, $rest) = $line =~ /^(\S+)\s+(\S+)\s*(.*)$/;
        unless (defined $cmd) {
            send_line($s, '* BAD Malformed command');
            next;
        }
        $cmd = uc $cmd;

        my $need_tls   = $opt{tls} eq 'starttls' && !$tls_active;
        my $login_off  = $need_tls || $opt{auth} eq 'plain-only';
        my $advertise_off = ($need_tls && $opt{logindisabled})
                            || $opt{auth} eq 'plain-only';

        if ($cmd eq 'CAPABILITY') {
            my @caps = ('IMAP4rev1');
            push @caps, 'STARTTLS'               if $need_tls;
            push @caps, 'AUTH=PLAIN', 'SASL-IR'
                if $opt{auth} =~ /^plain/ && !$need_tls;
            push @caps, 'AUTH=GSSAPI'            if $opt{gssapi};
            push @caps, 'LOGINDISABLED'          if $advertise_off;
            send_line($s, "* CAPABILITY @caps");
            send_line($s, "$tag OK CAPABILITY completed");
        }
        elsif ($cmd eq 'STARTTLS') {
            if ($need_tls) {
                send_line($s, "$tag OK Begin TLS negotiation now");
                logmsg('STARTTLS');
                $rbuf = '';    # discard anything sent in clear (RFC 3501 6.2.1)
                start_tls($s) or return;
                $tls_active = 1;
            }
            else {
                send_line($s, "$tag BAD STARTTLS not available");
            }
        }
        elsif ($cmd eq 'LOGIN') {
            if ($login_off) {
                logmsg('LOGIN_REFUSED');
                send_line($s, "$tag NO LOGIN disabled");
                next;
            }
            my ($u, $p) = parse_astrings($rest);
            check_creds($s, $tag, $u, $p);
        }
        elsif ($cmd eq 'AUTHENTICATE') {
            my ($mech, $ir) = split ' ', $rest, 2;
            if (uc($mech // '') eq 'GSSAPI') {
                logmsg('AUTH_GSSAPI');
                send_line($s, "$tag NO GSSAPI not available");
                next;
            }
            if ($opt{auth} !~ /^plain/ || uc($mech // '') ne 'PLAIN'
                || $need_tls) {
                send_line($s, "$tag NO Unsupported mechanism");
                next;
            }
            unless (defined $ir && length $ir) {
                send_line($s, '+ ');
                $ir = read_line($s);
                last unless defined $ir;
            }
            if ($ir eq '*') {
                send_line($s, "$tag BAD Authentication cancelled");
                next;
            }
            my (undef, $u, $p) = split /\0/, decode_base64($ir), 3;
            logmsg('AUTH_PLAIN');
            check_creds($s, $tag, $u, $p);
        }
        elsif ($cmd eq 'NOOP') {
            logmsg('NOOP');
            send_line($s, "$tag OK NOOP completed");
        }
        elsif ($cmd eq 'LOGOUT') {
            send_line($s, '* BYE Logging out');
            send_line($s, "$tag OK LOGOUT completed");
            last;
        }
        else {
            send_line($s, "$tag BAD Unknown command");
        }
    }
}

my $listen = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => $opt{port},
    Listen    => 32,
    ReuseAddr => 1,
    Proto     => 'tcp',
) or die "listen: $!\n";

if ($opt{portfile}) {
    open my $fh, '>', "$opt{portfile}.tmp" or die "portfile: $!\n";
    print $fh $listen->sockport, "\n";
    close $fh;
    rename "$opt{portfile}.tmp", $opt{portfile} or die "rename: $!\n";
}

$SIG{CHLD} = sub { 1 while waitpid(-1, WNOHANG) > 0 };
$SIG{TERM} = sub { exit 0 };

while (1) {
    my $client = $listen->accept or next;    # EINTR from SIGCHLD
    my $pid = fork;
    if (!defined $pid) {
        close $client;
        next;
    }
    if ($pid == 0) {
        close $listen;
        $SIG{TERM} = 'DEFAULT';
        handle_client($client);
        exit 0;
    }
    close $client;
}
