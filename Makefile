CC ?= cc
CPPFLAGS += -Isrc
CFLAGS ?= -O2 -g
LDFLAGS ?=
LDLIBS ?=
WARNINGS = -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wcast-qual -Wformat=2 \
	-Wstrict-prototypes -Wmissing-prototypes
ifeq ($(shell uname -s),Linux)
HARDENING_CPPFLAGS = -D_FORTIFY_SOURCE=2
HARDENING_CFLAGS = -fstack-protector-strong -fPIE
HARDENING_LDFLAGS = -pie -Wl,-z,relro,-z,now,-z,noexecstack
endif
BUILD_DIR = build
ifeq ($(OS),Windows_NT)
EXEEXT = .exe
LDLIBS += -lws2_32
endif
PROGRAM = faqproxy$(EXEEXT)
TARGET = $(BUILD_DIR)/$(PROGRAM)
UNIT_TARGET = $(BUILD_DIR)/test_nq_protocol$(EXEEXT)
SOURCES = src/faqproxy.c src/nq_protocol.c
PREFIX ?= /usr/local
DESTDIR ?=

.PHONY: all clean compile-tests install test sanitize

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(SOURCES) src/nq_protocol.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(HARDENING_CPPFLAGS) $(CFLAGS) $(HARDENING_CFLAGS) $(WARNINGS) \
		$(SOURCES) $(LDFLAGS) $(HARDENING_LDFLAGS) $(LDLIBS) -o $@

$(UNIT_TARGET): tests/test_nq_protocol.c src/nq_protocol.c src/nq_protocol.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(HARDENING_CPPFLAGS) $(CFLAGS) $(HARDENING_CFLAGS) $(WARNINGS) \
		tests/test_nq_protocol.c src/nq_protocol.c $(LDFLAGS) $(HARDENING_LDFLAGS) \
		$(LDLIBS) -o $@

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(PROGRAM)

compile-tests: $(TARGET) $(UNIT_TARGET)

test: compile-tests
	$(UNIT_TARGET)
	python3 tests/test_cli.py $(TARGET)
	python3 tests/test_e2e.py $(TARGET)
	python3 tests/test_hardening.py $(TARGET)

sanitize: CFLAGS = -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
sanitize: clean test

clean:
	rm -rf $(BUILD_DIR)
