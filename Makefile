CC ?= cc
CPPFLAGS ?= -Isrc
CFLAGS ?= -O2 -g
WARNINGS = -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow
BUILD_DIR = build
TARGET = $(BUILD_DIR)/faqproxy
UNIT_TARGET = $(BUILD_DIR)/test_nq_protocol
SOURCES = src/faqproxy.c src/nq_protocol.c

.PHONY: all clean test sanitize

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(SOURCES) src/nq_protocol.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(SOURCES) -o $@

$(UNIT_TARGET): tests/test_nq_protocol.c src/nq_protocol.c src/nq_protocol.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) tests/test_nq_protocol.c src/nq_protocol.c -o $@

test: $(TARGET) $(UNIT_TARGET)
	$(UNIT_TARGET)
	python3 tests/test_e2e.py $(TARGET)

sanitize: CFLAGS = -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
sanitize: clean test

clean:
	rm -rf $(BUILD_DIR)
