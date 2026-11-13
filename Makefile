# Build and test the OpenVPN IMAP auth plugin
# Requires: libcurl and OpenSSL development files, openvpn-plugin.h
# Tests:    perl (Test::More), optionally IO::Socket::SSL + openssl for TLS
#
# On BSD systems you will typically want something like:
#   make OPENVPN_INC=/usr/local/include PLUGIN_DIR=/usr/local/lib/openvpn/plugins \
#        MANDIR=/usr/local/man

CC          ?= cc
OPENVPN_INC ?= /usr/include/openvpn
PLUGIN_DIR  ?= /usr/lib/openvpn/plugins
MANDIR      ?= /usr/share/man
DL_LIBS     ?= -ldl

CFLAGS  ?= -O2 -g
CFLAGS  += -std=c99 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -I$(OPENVPN_INC)
CURL_CFLAGS != pkg-config --cflags libcurl
CURL_LIBS   != pkg-config --libs libcurl

TARGET  = openvpn-auth-imap.so
MANPAGE = openvpn-auth-imap.8
HARNESS = t/test-harness

all: $(TARGET)

$(TARGET): openvpn-auth-imap.c
	$(CC) $(CFLAGS) -fPIC $(CURL_CFLAGS) -shared -o $@ openvpn-auth-imap.c $(LDFLAGS) $(CURL_LIBS)

$(HARNESS): t/test-harness.c
	$(CC) $(CFLAGS) -o $@ t/test-harness.c $(LDFLAGS) $(DL_LIBS)

test: $(TARGET) $(HARNESS)
	PLUGIN=`pwd`/$(TARGET) HARNESS=`pwd`/$(HARNESS) prove -v t/

install: $(TARGET)
	install -d $(DESTDIR)$(PLUGIN_DIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(PLUGIN_DIR)/
	install -d $(DESTDIR)$(MANDIR)/man8
	install -m 0644 $(MANPAGE) $(DESTDIR)$(MANDIR)/man8/

lint-man:
	mandoc -Tlint $(MANPAGE)

clean:
	rm -f $(TARGET) $(HARNESS)

.PHONY: all test install lint-man clean
