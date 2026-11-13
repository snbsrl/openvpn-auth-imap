#!/usr/bin/env perl
#
# Regression tests for openvpn-auth-imap.
# Runs fake IMAP servers (t/fake-imapd.pl) and drives the plugin through
# t/test-harness exactly as OpenVPN would.
#
#   make test            or     PLUGIN=... HARNESS=... prove -v t/
#
use strict;
use warnings;
use File::Temp qw(tempdir);
use FindBin;
use IO::Socket::INET;
use POSIX qw(:sys_wait_h);
use Test::More;
use Time::HiRes qw(time sleep);

my $root    = "$FindBin::Bin/..";
my $plugin  = $ENV{PLUGIN}  // "$root/openvpn-auth-imap.so";
my $harness = $ENV{HARNESS} // "$FindBin::Bin/test-harness";
my $imapd   = "$FindBin::Bin/fake-imapd.pl";

-f $plugin  or BAIL_OUT("plugin not built: $plugin (run make)");
-x $harness or BAIL_OUT("harness not built: $harness (run make test)");

my $dir = tempdir(CLEANUP => 1);
my @server_pids;

END {
    local $?;
    kill 'TERM', @server_pids if @server_pids;
    waitpid($_, 0) for @server_pids;
}

my %USERS = (
    'alice'             => 'wonderland',
    'bob@example.com'   => 'builder',
    'carol'             => q{p@ss "quoted" \back\slash and spaces},
);
# 'dave' exists only on the second server ($s2) in the failover tests.

# ------------------------------------------------------------------ #
# helpers                                                             #
# ------------------------------------------------------------------ #

my $server_seq = 0;

sub start_server {
    my (%a) = @_;
    my $name     = 'srv' . ++$server_seq;
    my $portfile = "$dir/$name.port";
    my $log      = "$dir/$name.log";
    open my $fh, '>', $log or die;
    close $fh;

    my $users = $a{users} // \%USERS;
    my @cmd = ($^X, $imapd, '--portfile', $portfile, '--log', $log,
               map { ('--user', "$_:$users->{$_}") } sort keys %$users);
    push @cmd, '--tls', $a{tls}             if $a{tls};
    push @cmd, '--cert', $a{cert}, '--key', $a{key} if $a{cert};
    push @cmd, '--auth', $a{auth}           if $a{auth};
    push @cmd, '--behaviour', $a{behaviour} if $a{behaviour};
    push @cmd, '--delay', $a{delay}         if $a{delay};
    push @cmd, '--no-logindisabled'         if $a{no_logindisabled};

    my $pid = fork // die "fork: $!";
    if ($pid == 0) {
        open STDOUT, '>', '/dev/null';
        exec @cmd or die "exec: $!";
    }
    push @server_pids, $pid;

    my $deadline = time + 10;
    sleep 0.05 until -s $portfile || time > $deadline;
    open my $pf, '<', $portfile or die "server $name did not start\n";
    chomp(my $port = <$pf>);
    return { name => $name, port => $port, log => $log, pid => $pid };
}

sub dead_port {
    my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                  Listen => 1) or die;
    my $p = $s->sockport;
    close $s;
    return $p;
}

sub log_lines {
    my ($srv) = @_;
    open my $fh, '<', $srv->{log} or return ();
    chomp(my @l = <$fh>);
    return @l;
}

sub clear_log {
    my ($srv) = @_;
    open my $fh, '>', $srv->{log} or die;
    close $fh;
}

sub url { my ($srv, $scheme) = @_; ($scheme // 'imap') . "://127.0.0.1:$srv->{port}" }

# Run the harness; returns hashref { rc, out, err, secs }.
sub auth {
    my (%a) = @_;
    my @cmd = ($harness, '--plugin', $plugin,
               '--user', $a{user}, '--pass', $a{pass});
    push @cmd, '--sync'               if $a{sync};
    push @cmd, '--count', $a{count}   if $a{count};
    push @cmd, '--wait',  $a{wait}    if $a{wait};
    push @cmd, map { ('--env', $_) } @{ $a{env} // [] };
    push @cmd, '--', @{ $a{args} // [] };

    my $errfile = "$dir/harness.err";
    my $t0 = time;
    my $pid = open(my $out, '-|') // die "fork: $!";
    if ($pid == 0) {
        open STDERR, '>', $errfile;
        exec @cmd or die "exec: $!";
    }
    local $/;
    my $stdout = <$out> // '';
    close $out;
    my $rc = $? >> 8;
    my $secs = time - $t0;
    open my $ef, '<', $errfile;
    my $stderr = <$ef> // '';
    return { rc => $rc, out => $stdout, err => $stderr, secs => $secs };
}

sub accepts {
    my ($name, %a) = @_;
    my $r = auth(%a);
    is($r->{rc}, 0, "$name: accepted") or diag($r->{out} . $r->{err});
    return $r;
}

sub rejects {
    my ($name, %a) = @_;
    my $r = auth(%a);
    is($r->{rc}, 1, "$name: rejected") or diag($r->{out} . $r->{err});
    return $r;
}

# ------------------------------------------------------------------ #
# servers                                                             #
# ------------------------------------------------------------------ #

my $s1   = start_server();
my $s2   = start_server(users => { dave => 'only-on-second', alice => 'other-pw' });
my $hang = start_server(behaviour => 'hang');
my $junk = start_server(behaviour => 'garbage');
my $bye  = start_server(behaviour => 'bye');
my $sasl = start_server(auth => 'plain-only');
my $dead = dead_port();

# ------------------------------------------------------------------ #
subtest 'configuration' => sub {
    my $r = auth(user => 'alice', pass => 'x', args => []);
    is($r->{rc}, 2, 'no server configured -> open fails');
    like($r->{err}, qr/no IMAP server configured/, '... with a clear message');

    for my $bad ('match-cert=yes', 'match-cert=', 'cert-map=',
                 'server=ftp://host', 'server=imap://', 'server=imap://h:0',
                 'server=imap://h:99999', 'server=imap://h/INBOX',
                 'server=imap://h?x', 'server=imap://u@h',
                 'server=imaps://[::1', 'server=mail.example.com',
                 'server=mail.example.com:993', 'server=://h',
                 'policy=random', 'timeout=0', 'domain=a/b',
                 'frobnicate=1', 'noequals') {
        my $r = auth(user => 'alice', pass => 'x',
                     args => ['server=imap://127.0.0.1:1', $bad]);
        is($r->{rc}, 2, "rejects bad argument '$bad'");
    }

    my @many = map { "server=imap://127.0.0.1:$dead" } 1 .. 17;
    is(auth(user => 'a', pass => 'b', args => \@many)->{rc}, 2,
       'more than 16 servers -> open fails');

    $r = auth(user => 'a', pass => 'b', args => ['server=mail.example.com']);
    like($r->{err}, qr{expected imaps://host}, 'missing scheme explained');

    $r = auth(user => 'alice', pass => 'wonderland', sync => 1,
              args => ['server=imaps://[::1]:993', 'server=starttls://mx',
                       'server=IMAP://plainhost', 'server=imaps://mx2/',
                       'timeout=1']);
    like($r->{err}, qr{server 1: imaps://\[::1\]:993}, 'IPv6 literal parsed');
    like($r->{err}, qr{server 2: starttls://mx:143},   'starttls default port');
    like($r->{err}, qr{server 3: imap://plainhost:143},
         'scheme is case-insensitive, imap default port');
    like($r->{err}, qr{server 4: imaps://mx2:993},
         'trailing slash allowed, imaps default port');
    like($r->{err}, qr/clear text/, 'warns about clear-text mode');
};

# ------------------------------------------------------------------ #
subtest 'single server' => sub {
    my @a = (args => [ 'server=' . url($s1) ]);

    accepts('good password',  user => 'alice', pass => 'wonderland', @a);
    rejects('wrong password', user => 'alice', pass => 'Wonderland', @a);
    rejects('unknown user',   user => 'mallory', pass => 'x', @a);
    accepts('special characters are quoted correctly',
            user => 'carol', pass => $USERS{carol}, @a);
    accepts('username containing @',
            user => 'bob@example.com', pass => 'builder', @a);

    clear_log($s1);
    rejects('empty password', user => 'alice', pass => '', @a);
    rejects('control character in username',
            user => "alice\r\nA1 LOGIN x y", pass => 'wonderland', @a);
    rejects('control character in password',
            user => 'alice', pass => "wonder\nland", @a);
    rejects('overlong username', user => 'a' x 300, pass => 'x', @a);
    is(scalar(log_lines($s1)), 0,
       'malformed credentials never reach the server');
};

# ------------------------------------------------------------------ #
subtest 'domain=' => sub {
    my @a = (args => [ 'server=' . url($s1), 'domain=example.com' ]);
    accepts('bare username gets @domain',
            user => 'bob', pass => 'builder', @a);
    accepts('username with @ is left alone',
            user => 'bob@example.com', pass => 'builder', @a);
    clear_log($s1);
    rejects('alice becomes alice@example.com',
            user => 'alice', pass => 'wonderland', @a);
    ok((grep { $_ eq 'LOGIN_FAIL alice@example.com' } log_lines($s1)),
       'server saw the qualified name');
};

# ------------------------------------------------------------------ #
subtest 'match-cert' => sub {
    my $srv = 'server=' . url($s1);
    my $cn  = sub { "common_name=$_[0]" };
    my $not_contacted = sub {
        my ($what) = @_;
        is(scalar(grep { /^LOGIN/ } log_lines($s1)), 0,
           "$what: IMAP server not contacted");
    };

    accepts('certificate matches login', user => 'alice',
            pass => 'wonderland', env => [ $cn->('alice') ],
            args => [ $srv, 'match-cert=1' ]);

    clear_log($s1);
    my $r = rejects('certificate of another user', user => 'bob@example.com',
            pass => 'builder', env => [ $cn->('alice') ],
            args => [ $srv, 'match-cert=1' ]);
    like($r->{err}, qr/'bob\@example.com' .* does not match certificate 'alice'/,
         'mismatch logged with both names');
    $not_contacted->('mismatch');

    clear_log($s1);
    $r = rejects('no certificate name at all', user => 'alice',
            pass => 'wonderland', args => [ $srv, 'match-cert=1' ]);
    like($r->{err}, qr/no valid client certificate name/, '... logged');
    $not_contacted->('no certificate');

    rejects('certificate name with control characters', user => 'alice',
            pass => 'wonderland', env => [ $cn->("alice\nx") ],
            args => [ $srv, 'match-cert=1' ]);

    accepts('comparison is case-insensitive', user => 'bob@example.com',
            pass => 'builder', env => [ $cn->('Bob@Example.COM') ],
            args => [ $srv, 'match-cert=1' ]);

    accepts('domain= applied to certificate name', user => 'bob@example.com',
            pass => 'builder', env => [ $cn->('bob') ],
            args => [ $srv, 'match-cert=1', 'domain=example.com' ]);
    accepts('domain= applied to login', user => 'bob', pass => 'builder',
            env => [ $cn->('bob@example.com') ],
            args => [ $srv, 'match-cert=1', 'domain=example.com' ]);

    accepts('match-cert off by default: mismatch ignored', user => 'alice',
            pass => 'wonderland', env => [ $cn->('somebody-else') ],
            args => [ $srv ]);

    accepts('matching certificate still needs the right password',
            user => 'alice', pass => 'wonderland',
            env => [ $cn->('alice') ], sync => 1,
            args => [ $srv, 'match-cert=1' ]);
    rejects('matching certificate, wrong password', user => 'alice',
            pass => 'nope', env => [ $cn->('alice') ],
            args => [ $srv, 'match-cert=1' ]);
};

# ------------------------------------------------------------------ #
subtest 'cert-map' => sub {
    my $srv = 'server=' . url($s1);
    my $map = "$dir/cert-map";
    open my $fh, '>', $map or die;
    print $fh <<'MAP';
# common_name            imap-user
vpn-laptop-07            alice

   John Smith    carol
shared-kiosk             alice
shared-kiosk             bob@example.com
bob@example.com          alice
old-bob                  bob
MAP
    close $fh;

    my @m = ('match-cert=1', "cert-map=$map");
    my $try = sub {
        my ($verb, $name, $cnv, $user, $pass, @extra) = @_;
        my $f = $verb eq 'accept' ? \&accepts : \&rejects;
        $f->($name, user => $user, pass => $pass,
             env => [ "common_name=$cnv" ], args => [ $srv, @m, @extra ]);
    };

    my $r = auth(user => 'alice', pass => 'wonderland', sync => 1,
                 env => [ 'common_name=alice' ], args => [ $srv, @m ]);
    like($r->{err}, qr/6 cert-map entries/, 'map loaded: 6 entries');

    $try->(accept => 'mapped certificate, mapped user',
           'vpn-laptop-07', 'alice', 'wonderland');
    clear_log($s1);
    $try->(reject => 'mapped certificate, other user',
           'vpn-laptop-07', 'carol', $USERS{carol});
    is(scalar(log_lines($s1)), 0, 'IMAP server not contacted');

    $try->(accept => 'common name with spaces',
           'John Smith', 'carol', $USERS{carol});
    $try->(reject => 'common names compared exactly',
           'john smith', 'carol', $USERS{carol});

    $try->(accept => 'one certificate, several users (1)',
           'shared-kiosk', 'alice', 'wonderland');
    $try->(accept => 'one certificate, several users (2)',
           'shared-kiosk', 'bob@example.com', 'builder');
    $try->(reject => 'one certificate, several users: others refused',
           'shared-kiosk', 'carol', $USERS{carol});

    $try->(reject => 'mapped name as login is its mapped user, not itself',
           'bob@example.com', 'bob@example.com', 'builder');
    $try->(accept => '... logs in as the mapped user',
           'bob@example.com', 'bob@example.com', 'wonderland');
    $try->(accept => '... only the mapped user',
           'bob@example.com', 'alice', 'wonderland');

    # login equal to the certificate's common name uses the mapped user
    clear_log($s1);
    $try->(accept => 'common name as login: mapped user used',
           'vpn-laptop-07', 'vpn-laptop-07', 'wonderland');
    ok((grep { $_ eq 'LOGIN_OK alice' } log_lines($s1)),
       '... IMAP login as alice');
    $try->(accept => 'common name with spaces as login',
           'John Smith', 'John Smith', $USERS{carol});
    clear_log($s1);
    $try->(reject => 'common name mapping to several users',
           'shared-kiosk', 'shared-kiosk', 'wonderland');
    is(scalar(log_lines($s1)), 0, '... IMAP server not contacted');
    $try->(reject => 'only the certificate\'s own name is rewritten',
           'shared-kiosk', 'vpn-laptop-07', 'wonderland');
    $try->(accept => 'common name as login: domain= applied to mapped user',
           'old-bob', 'old-bob', 'builder', 'domain=example.com');

    $try->(accept => 'certificate not in map: direct comparison',
           'alice', 'alice', 'wonderland');
    $try->(reject => 'certificate not in map: mismatch',
           'carol', 'alice', 'wonderland');

    $try->(accept => 'domain= applied to mapped users',
           'old-bob', 'bob@example.com', 'builder', 'domain=example.com');
    $try->(accept => 'domain= applied to mapped users and login',
           'old-bob', 'bob', 'builder', 'domain=example.com');

    # deferred and synchronous paths behave the same
    $r = auth(user => 'carol', pass => $USERS{carol}, sync => 1,
              env => [ 'common_name=vpn-laptop-07' ], args => [ $srv, @m ]);
    is($r->{rc}, 1, 'synchronous mode applies the map too');
    $r = auth(user => 'vpn-laptop-07', pass => 'wonderland', sync => 1,
              env => [ 'common_name=vpn-laptop-07' ], args => [ $srv, @m ]);
    is($r->{rc}, 0, 'synchronous mode rewrites the common name too');
};

# ------------------------------------------------------------------ #
subtest 'cert-map configuration errors' => sub {
    my $srv = 'server=' . url($s1);
    my $write = sub {
        my ($name, $body) = @_;
        open my $fh, '>', "$dir/$name" or die;
        print $fh $body;
        close $fh;
        return "$dir/$name";
    };

    my $ok = $write->('ok.map', "a b\n");
    my $r = auth(user => 'a', pass => 'b', args => [ $srv, "cert-map=$ok" ]);
    is($r->{rc}, 2, 'cert-map without match-cert=1 fails');
    like($r->{err}, qr/cert-map= requires match-cert=1/, '... explained');

    $r = auth(user => 'a', pass => 'b',
              args => [ $srv, 'match-cert=1', "cert-map=$dir/missing" ]);
    is($r->{rc}, 2, 'missing map file fails at startup');
    like($r->{err}, qr/cannot open cert-map/, '... explained');

    my $bad = $write->('bad.map', "# ok\nalice alice\nlonely\n");
    $r = auth(user => 'a', pass => 'b',
              args => [ $srv, 'match-cert=1', "cert-map=$bad" ]);
    is($r->{rc}, 2, 'line with one field fails');
    like($r->{err}, qr/bad\.map:3: expected/, '... with file and line number');

    my $long = $write->('long.map', 'x' x 3000 . " alice\n");
    is(auth(user => 'a', pass => 'b',
            args => [ $srv, 'match-cert=1', "cert-map=$long" ])->{rc}, 2,
       'overlong line fails');

    my $ctl = $write->('ctl.map', "ali\x01ce alice\n");
    is(auth(user => 'a', pass => 'b',
            args => [ $srv, 'match-cert=1', "cert-map=$ctl" ])->{rc}, 2,
       'control characters fail');

    my $empty = $write->('empty.map', "# nothing yet\n\n");
    $r = auth(user => 'alice', pass => 'wonderland',
              env => [ 'common_name=alice' ],
              args => [ $srv, 'match-cert=1', "cert-map=$empty" ]);
    is($r->{rc}, 0, 'empty map is allowed (direct comparison)');
    like($r->{err}, qr/has no entries/, '... with a warning');

    my $crlf = $write->('crlf.map', "laptop\talice\r\n");
    is(auth(user => 'alice', pass => 'wonderland',
            env => [ 'common_name=laptop' ],
            args => [ $srv, 'match-cert=1', "cert-map=$crlf" ])->{rc}, 0,
       'tabs and CRLF line endings accepted');
};

# ------------------------------------------------------------------ #
subtest 'SASL PLAIN' => sub {
    clear_log($sasl);
    accepts('AUTHENTICATE PLAIN when LOGIN is disabled',
            user => 'carol', pass => $USERS{carol},
            args => [ 'server=' . url($sasl) ]);
    ok((grep { $_ eq 'AUTH_PLAIN' } log_lines($sasl)), 'used AUTHENTICATE');
    rejects('AUTHENTICATE PLAIN wrong password', user => 'alice', pass => 'x',
            args => [ 'server=' . url($sasl) ]);
};

# ------------------------------------------------------------------ #
subtest 'multiple servers: failover policy' => sub {
    clear_log($_) for $s1, $s2;

    accepts('first server down -> second accepts', user => 'dave',
            pass => 'only-on-second',
            args => [ "server=imap://127.0.0.1:$dead", 'server=' . url($s2) ]);

    accepts('first server sends garbage -> second accepts', user => 'dave',
            pass => 'only-on-second',
            args => [ 'server=' . url($junk), 'server=' . url($s2) ]);

    accepts('first server says BYE -> second accepts', user => 'dave',
            pass => 'only-on-second',
            args => [ 'server=' . url($bye), 'server=' . url($s2) ]);

    clear_log($_) for $s1, $s2;
    accepts('first server accepts -> second not contacted', user => 'alice',
            pass => 'wonderland',
            args => [ 'server=' . url($s1), 'server=' . url($s2) ]);
    is(scalar(log_lines($s2)), 0, 'second server untouched');

    clear_log($_) for $s1, $s2;
    rejects('first server rejects -> reject without trying second',
            user => 'dave', pass => 'only-on-second',
            args => [ 'server=' . url($s1), 'server=' . url($s2) ]);
    is(scalar(log_lines($s2)), 0, 'second server untouched on rejection');

    rejects('all servers down', user => 'alice', pass => 'wonderland',
            args => [ "server=imap://127.0.0.1:$dead",
                      'server=' . url($junk) ]);

    my $r = accepts('hanging server times out, then failover',
            user => 'dave', pass => 'only-on-second',
            args => [ 'server=' . url($hang), 'server=' . url($s2),
                      'timeout=2' ]);
    cmp_ok($r->{secs}, '<', 6, sprintf('finished in %.1fs', $r->{secs}));
    like($r->{err}, qr/timeout|timed out/i, 'timeout logged');
};

# ------------------------------------------------------------------ #
subtest 'multiple servers: any policy' => sub {
    my @both = ('server=' . url($s1), 'server=' . url($s2), 'policy=any');

    accepts('rejected by first, accepted by second',
            user => 'dave', pass => 'only-on-second', args => \@both);
    accepts('accepted by first',
            user => 'alice', pass => 'wonderland', args => \@both);
    accepts('password valid only on second server',
            user => 'alice', pass => 'other-pw', args => \@both);
    rejects('rejected by all', user => 'alice', pass => 'nope',
            args => \@both);
    rejects('rejected by one, other down', user => 'alice', pass => 'nope',
            args => [ 'server=' . url($s1), "server=imap://127.0.0.1:$dead",
                      'policy=any' ]);
};

# ------------------------------------------------------------------ #
subtest 'synchronous mode (no auth_control_file)' => sub {
    my @a = (sync => 1, args => [ "server=imap://127.0.0.1:$dead",
                                  'server=' . url($s1) ]);
    accepts('sync accept with failover', user => 'alice',
            pass => 'wonderland', @a);
    rejects('sync reject', user => 'alice', pass => 'bad', @a);
};

# ------------------------------------------------------------------ #
subtest 'concurrent deferred authentications' => sub {
    my $slow = start_server(delay => 1);
    my $r = auth(user => 'alice', pass => 'wonderland', count => 8,
                 args => [ 'server=' . url($slow) ]);
    is($r->{rc}, 0, '8 parallel logins all accepted') or diag $r->{out};
    is(scalar(() = $r->{out} =~ /ACCEPT/g), 8, 'eight results');
    cmp_ok($r->{secs}, '<', 4,
           sprintf('ran in parallel (%.1fs for 8 x 1s)', $r->{secs}));

    $r = auth(user => 'alice', pass => 'wrong', count => 4,
              args => [ 'server=' . url($slow) ]);
    is(scalar(() = $r->{out} =~ /REJECT/g), 4, 'parallel rejections');

    my $zombies = `ps -o stat= --ppid $$ 2>/dev/null` // '';
    unlike($zombies, qr/Z/, 'no zombie processes left behind');
};

# ------------------------------------------------------------------ #
SKIP: {
    my $have_ssl = eval { require IO::Socket::SSL; 1 };
    my $openssl  = `command -v openssl 2>/dev/null`;
    skip 'TLS tests need IO::Socket::SSL and openssl', 1
        unless $have_ssl && $openssl;

    subtest 'TLS' => sub {
        my ($cert, $key) = ("$dir/cert.pem", "$dir/key.pem");
        open(my $saved_err, '>&', \*STDERR) or die;
        open(STDERR, '>', '/dev/null') or die;    # hide openssl progress
        system('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
               '-days', '1', '-subj', '/CN=127.0.0.1',
               '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
               '-keyout', $key, '-out', $cert) == 0
            or return fail('could not create test certificate');
        # a second, unrelated CA
        my $other = "$dir/other.pem";
        system('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
               '-days', '1', '-subj', '/CN=other', '-keyout', "$dir/o.key",
               '-out', $other) == 0 or return fail('second cert');
        open(STDERR, '>&', $saved_err) or die;

        my $imaps = start_server(tls => 'imaps', cert => $cert, key => $key);
        # Dovecot-like: LOGINDISABLED before TLS, AUTH=PLAIN after
        my $stls  = start_server(tls => 'starttls', cert => $cert, key => $key,
                                 auth => 'plain');
        # LOGIN only, and LOGINDISABLED not advertised before TLS
        my $stls_login = start_server(tls => 'starttls', cert => $cert,
                                      key => $key, no_logindisabled => 1);
        # LOGIN only, LOGINDISABLED advertised before TLS
        my $stls_strict = start_server(tls => 'starttls', cert => $cert,
                                       key => $key);

        accepts('imaps with matching CA', user => 'alice',
                pass => 'wonderland',
                args => [ 'server=' . url($imaps, 'imaps'), "cafile=$cert" ]);
        rejects('imaps wrong password', user => 'alice', pass => 'x',
                args => [ 'server=' . url($imaps, 'imaps'), "cafile=$cert" ]);

        clear_log($imaps);
        my $r = rejects('imaps with untrusted certificate', user => 'alice',
                pass => 'wonderland',
                args => [ 'server=' . url($imaps, 'imaps'), "cafile=$other" ]);
        ok(!(grep { /^LOGIN/ } log_lines($imaps)),
           'no credentials sent to untrusted server');

        accepts('imaps with verify=0', user => 'alice', pass => 'wonderland',
                args => [ 'server=' . url($imaps, 'imaps'), 'verify=0' ]);

        clear_log($stls);
        accepts('starttls + AUTHENTICATE PLAIN', user => 'carol',
                pass => $USERS{carol},
                args => [ 'server=' . url($stls, 'starttls'), "cafile=$cert" ]);
        my @l = log_lines($stls);
        ok((grep { $_ eq 'STARTTLS' } @l),   'STARTTLS issued');
        ok((grep { $_ eq 'AUTH_PLAIN' } @l), 'authenticated after TLS');
        rejects('starttls + AUTHENTICATE PLAIN, wrong password',
                user => 'alice', pass => 'nope',
                args => [ 'server=' . url($stls, 'starttls'), "cafile=$cert" ]);

        clear_log($stls_login);
        accepts('starttls + LOGIN', user => 'carol', pass => $USERS{carol},
                args => [ 'server=' . url($stls_login, 'starttls'),
                          "cafile=$cert" ]);
        ok((grep { $_ eq 'LOGIN_OK carol' } log_lines($stls_login)),
           'LOGIN sent after TLS');

        TODO: {
            local $TODO = 'libcurl keeps LOGINDISABLED from the pre-TLS '
                        . 'CAPABILITY (seen with libcurl 8.5.0)';
            accepts('starttls + LOGIN when LOGINDISABLED was advertised '
                    . 'before TLS', user => 'alice', pass => 'wonderland',
                    args => [ 'server=' . url($stls_strict, 'starttls'),
                              "cafile=$cert" ]);
        }

        clear_log($s1);
        rejects('starttls against server without STARTTLS', user => 'alice',
                pass => 'wonderland',
                args => [ 'server=' . url($s1, 'starttls') ]);
        ok(!(grep { /^LOGIN/ } log_lines($s1)),
           'password not sent in clear text when STARTTLS is missing');

        my $other_srv = start_server(tls => 'imaps', cert => $other,
                                     key => "$dir/o.key");
        accepts('certificate failure on first server -> failover',
                user => 'alice', pass => 'wonderland',
                args => [ 'server=' . url($other_srv, 'imaps'),
                          'server=' . url($stls, 'starttls'),
                          "cafile=$cert" ]);
    };
}

done_testing();
