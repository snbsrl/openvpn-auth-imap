# Build and test the OpenVPN IMAP auth plugin
# Requires: libcurl and OpenSSL development files, openvpn-plugin.h
# Tests:    perl (Test::More), optionally IO::Socket::SSL + openssl for TLS
.RECIPEPREFIX = >

CC          ?= cc
OPENVPN_INC ?= /usr/include/openvpn
PLUGIN_DIR  ?= /usr/lib/openvpn/plugins

CFLAGS  ?= -O2 -g
CFLAGS  += -std=c99 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -I$(OPENVPN_INC)
CURL_CFLAGS := $(shell pkg-config --cflags libcurl)
CURL_LIBS   := $(shell pkg-config --libs libcurl)

TARGET  = openvpn-auth-imap.so
HARNESS = t/test-harness

all: $(TARGET)

$(TARGET): openvpn-auth-imap.c
> $(CC) $(CFLAGS) -fPIC $(CURL_CFLAGS) -shared -o $@ $< $(LDFLAGS) $(CURL_LIBS)

$(HARNESS): t/test-harness.c
> $(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -ldl

test: $(TARGET) $(HARNESS)
> PLUGIN=$(CURDIR)/$(TARGET) HARNESS=$(CURDIR)/$(HARNESS) prove -v t/

install: $(TARGET)
> install -d $(DESTDIR)$(PLUGIN_DIR)
> install -m 0755 $(TARGET) $(DESTDIR)$(PLUGIN_DIR)/

clean:
> rm -f $(TARGET) $(HARNESS)

.PHONY: all test install clean
