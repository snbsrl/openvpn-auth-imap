# openvpn-auth-imap

[![Release](https://img.shields.io/github/v/release/snbsrl/openvpn-auth-imap)](https://github.com/snbsrl/openvpn-auth-imap/releases/latest)
[![CI](https://github.com/snbsrl/openvpn-auth-imap/actions/workflows/ci.yml/badge.svg)](https://github.com/snbsrl/openvpn-auth-imap/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/snbsrl/openvpn-auth-imap)](LICENSE)

OpenVPN plugin that authenticates `auth-user-pass` clients by logging in to one or more IMAP servers with their username and password.

## Build and install

Dependencies (Debian/Ubuntu): `build-essential pkg-config libcurl4-openssl-dev libssl-dev openvpn`
(RHEL/Fedora: `gcc make pkgconf libcurl-devel openssl-devel openvpn-devel`)

```sh
make
sudo make install                                   # /usr/lib/openvpn/plugins
sudo make install PLUGIN_DIR=/opt/openvpn-auth-imap # or anywhere else
```

If `openvpn-plugin.h` lives elsewhere: `make OPENVPN_INC=/path/to/include`.

`make install` also installs the `openvpn-auth-imap(8)` man page under `/usr/share/man` (override with `MANDIR=`). To read it without installing: `man ./openvpn-auth-imap.8`.

## Server configuration

```
plugin /usr/lib/openvpn/plugins/openvpn-auth-imap.so server=imaps://mail1.example.com server=imaps://mail2.example.com domain=example.com

# Optional: no client certificates, username/password only
verify-client-cert none
username-as-common-name
```

Clients need `auth-user-pass` in their config. Use an absolute path on the `plugin` line if the plugin is not in OpenVPN's plugin directory. The file should be owned by root and not writable by other users. On SELinux systems, label a custom directory `lib_t`.

### Arguments

| Argument | Default | Meaning |
|---|---|---|
| `server=` | (required) | IMAP server URL, repeatable (max 16): `imaps://host[:port]` (default port 993), `starttls://host[:port]` (143) or `imap://host[:port]` (143, clear text). IPv6: `imaps://[2001:db8::1]` |
| `policy=` | `failover` | `failover`: try the next server only if one is unreachable or errors; a wrong password rejects at once. `any`: accept if any server accepts |
| `cafile=` | system store | CA bundle for verifying server certificates |
| `verify=` | `1` | `0` skips certificate checks (testing only). Only `0` and `1` are accepted |
| `domain=` | | Appended as `@domain` when the username has no `@` |
| `restrict-domain=` | `0` | `1` rejects logins that end up outside `domain=` (e.g. `bob@other.com`) before any server is contacted. Requires `domain=` |
| `timeout=` | `10` | Seconds allowed **per server** (1–300) |
| `max-pending=` | `64` | Logins checked in the background at the same time; further logins are rejected at once |
| `match-cert=` | `0` | `1` requires the login to match the client certificate (see below) |
| `cert-map=` | | File of certificates whose common name differs from the IMAP user; requires `match-cert=1` |

Invalid arguments stop OpenVPN at startup with an error message, rather than failing later at login time.

**Timing:** with `failover`, worst-case login time is roughly `timeout × number of servers`. Keep that well below OpenVPN's `hand-window` (60 s by default).

### Choosing a policy

Without `restrict-domain=1`, a username that already contains `@` is used as typed, so on an IMAP server hosting several domains every mailbox of every domain can log in to the VPN.

Use `failover` for redundant servers sharing one user database: a wrong password is final and isn't retried elsewhere. Use `any` when different servers hold different users (e.g. two mail domains). The server order then only affects speed.

## Binding logins to client certificates

With `match-cert=1`, a login is accepted only if the username matches the client certificate the connection was made with. A stolen password is then useless without the matching certificate, and one user's certificate can't be used with another user's password. Mismatches are rejected before any IMAP server is contacted.

```
plugin /usr/lib/openvpn/plugins/openvpn-auth-imap.so server=imaps://mail.example.com domain=example.com match-cert=1 cert-map=/etc/openvpn/cert-map
x509-username-field CN      # or emailAddress, or ext:subjectAltName
```

OpenVPN passes the certificate field chosen by `x509-username-field` to the plugin as `common_name`. The plugin compares it with the login:

- **Direct match:** the login must equal the common name, case-insensitively. `domain=` applies to both, so a certificate `alice` matches a login as `alice` or `alice@example.com`.
- **Mapped certificates:** for existing certificates whose common name isn't the user's email, list them in the `cert-map` file. A common name that appears in the map may log in **only** as its mapped users. Names not in the map use the direct match.
- **Logging in with the common name:** if the username typed is exactly the certificate's common name and that name is in the map, the plugin logs in to IMAP as the mapped user. If the name maps to several users the login is refused; type one of the mapped users instead.

`cert-map` format, one pair per line:

```
# common_name          imap-user
vpn-laptop-07          alice@example.com
# common names may contain spaces
John Smith             carol
# repeat a name to allow several users
shared-kiosk           alice@example.com
shared-kiosk           bob@example.com
```

The user is the last field on the line; everything before it is the common name. Common names are compared exactly (case-sensitive), users case-insensitively, and `domain=` applies to mapped users without `@`. Blank lines and lines starting with `#` are ignored; comments can't follow an entry on the same line.

The file is read once at startup, and a missing or malformed file stops OpenVPN with the file name and line number. Anyone who can write the file can bind any certificate to any user, so it must be owned by root (or the user OpenVPN runs as) and not world-writable; otherwise OpenVPN refuses to start. After editing it, restart OpenVPN or send it `SIGHUP`. If OpenVPN drops privileges (`user`/`group`), the file must be readable by that user for a `SIGHUP` reload to work.

**Requirements:**

- **Verified client certificates:** the binding is only meaningful because OpenVPN checks the certificate against your CA, so never combine `match-cert` with `verify-client-cert none`.
- **No `username-as-common-name`:** it replaces the certificate name with the typed username, which defeats the comparison.
- **Confirm with a real login:** the regression tests supply `common_name` the way OpenVPN does, but verify once with a real client that a mismatched login is refused on your OpenVPN version.

## How it works

OpenVPN calls the plugin with `username`, `password` and `auth_control_file`. The plugin double-forks, returns `DEFERRED` immediately, and the background process tries the servers through libcurl. It then writes `1` (accept) or `0` (reject) to the control file. The VPN server never blocks on IMAP. Without an `auth_control_file`, the check runs synchronously.

Passwords are never logged. Empty, overlong, or control-character-laden credentials are rejected before any server is contacted. With `starttls://`, the login is refused if the server doesn't offer STARTTLS, so passwords are never sent in clear text.

A login only counts as accepted if the password was actually sent (`LOGIN` or `AUTHENTICATE`) and the server answered OK. Only password-based SASL mechanisms are used (`PLAIN`, `LOGIN`, `CRAM-MD5`, `DIGEST-MD5`), falling back to the `LOGIN` command. Mechanisms like `GSSAPI` would authenticate with the VPN server's own credentials instead of the user's password. Proxy settings in OpenVPN's environment (`all_proxy`, `imap_proxy`, ...) are ignored, and TLS 1.2 is the minimum version.

### Brute force and lockouts

The IMAP server sees every login attempt as coming from the VPN server. If it locks out IP addresses after failed logins (fail2ban, Dovecot `auth_penalty`), a password-guessing client can lock out **all** VPN users. Throttle on the OpenVPN side instead: use `connect-freq` and `max-clients`, and point fail2ban at the plugin's `rejected by` log lines, which include the client address.

## Tests

```sh
make test
```

Requirements: Perl with `Test::More` (core). The TLS tests additionally need `IO::Socket::SSL` (`libio-socket-ssl-perl` / `perl-IO-Socket-SSL`) and the `openssl` command; they are skipped otherwise.

The suite runs without OpenVPN, root or network access:

- `t/fake-imapd.pl` is a small IMAP server (LOGIN, AUTHENTICATE PLAIN, STARTTLS, IMAPS). It can also misbehave on purpose: hang, send garbage, greet with BYE, or answer slowly.
- `t/test-harness.c` loads the plugin with `dlopen` and calls it exactly like OpenVPN: v3 open/func/close, environment variables, polling of auth control files.
- `t/regress.t` covers configuration parsing, credential quoting, input validation, `domain=`, certificate binding and `cert-map` parsing, SASL, both policies, failover on refused/garbage/BYE/hanging servers, timeouts, synchronous mode, 8 concurrent deferred logins, zombie reaping, and TLS: certificate verification, STARTTLS downgrade protection, and failover after a certificate failure.

To test an installed copy: `PLUGIN=/path/to/openvpn-auth-imap.so HARNESS=t/test-harness prove -v t/` (after `make t/test-harness`).

### Known limitation (libcurl)

Some STARTTLS servers advertise `LOGINDISABLED` before TLS and offer only `LOGIN` afterwards, with no SASL mechanisms. With these, libcurl 8.5.0 refuses to log in, so valid users are rejected. Servers that offer `AUTH=PLAIN` after STARTTLS (Dovecot, Cyrus and most others) work fine, as does `imaps://`. The test suite tracks this as a TODO test, which will report "unexpectedly succeeded" once your libcurl handles it. If you hit this, use `imaps://` (port 993).

## Testing your IMAP server by hand

```sh
curl -v --user 'alice@example.com:secret' -X NOOP imaps://mail.example.com/
```

If that succeeds, the plugin will accept the same credentials.
