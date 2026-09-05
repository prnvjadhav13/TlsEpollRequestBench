CXX ?= g++
CPPFLAGS ?=
CXXFLAGS ?=
LDFLAGS ?=
LDLIBS ?=

COMMON_FLAGS := -std=c++23 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -pthread
OPENSSL_CPPFLAGS := $(shell pkg-config --cflags openssl)
OPENSSL_LIBS := $(shell pkg-config --libs openssl)
CPPFLAGS += $(OPENSSL_CPPFLAGS)
CPPFLAGS += -I. -Iinclude
LDLIBS += $(OPENSSL_LIBS)

COMMON_HEADERS := tcp_common_config.h secure_transport.h
COMMON_SOURCES := secure_transport.cpp src/runtime/bounded_executor.cpp
SERVER_HEADERS := $(COMMON_HEADERS) server_protocol.h tcp_server_epoll.h

BUILD_DIR := build
DEBUG_DIR := $(BUILD_DIR)/debug
SANITIZER_DIR := $(BUILD_DIR)/sanitizer
PRODUCTION_DIR := $(BUILD_DIR)/production
PERFORMANCE_DIR := $(BUILD_DIR)/performance

DEBUG_FLAGS := -Og -g3 -D_GLIBCXX_ASSERTIONS -fno-omit-frame-pointer
SANITIZER_FLAGS := -O1 -g3 -D_GLIBCXX_ASSERTIONS -fno-omit-frame-pointer \
	-fsanitize=address,undefined
SANITIZER_LDFLAGS := -fsanitize=address,undefined
PRODUCTION_FLAGS := -O2 -DNDEBUG -D_FORTIFY_SOURCE=3 \
	-fstack-protector-strong -fstack-clash-protection -fPIE
PRODUCTION_LDFLAGS := -Wl,-z,relro,-z,now -pie
PERFORMANCE_FLAGS := -O3 -DNDEBUG -march=native -flto
PERFORMANCE_LDFLAGS := -flto

.DEFAULT_GOAL := production

.PHONY: all debug development sanitizer production release performance test clean help

all: debug sanitizer production performance

development: debug

release: production

debug: $(DEBUG_DIR)/tcp_server_epoll $(DEBUG_DIR)/tcp_client

sanitizer: $(SANITIZER_DIR)/tcp_server_epoll $(SANITIZER_DIR)/tcp_client

production: $(PRODUCTION_DIR)/tcp_server_epoll $(PRODUCTION_DIR)/tcp_client

performance: $(PERFORMANCE_DIR)/tcp_server_epoll $(PERFORMANCE_DIR)/tcp_client

test: $(DEBUG_DIR)/runtime_contract_test
	$(DEBUG_DIR)/runtime_contract_test

$(DEBUG_DIR) $(SANITIZER_DIR) $(PRODUCTION_DIR) $(PERFORMANCE_DIR):
	mkdir -p $@

$(DEBUG_DIR)/tcp_server_epoll: tcp_server_epoll.cpp $(COMMON_SOURCES) $(SERVER_HEADERS) Makefile | $(DEBUG_DIR)
	$(CXX) $(CPPFLAGS) $(COMMON_FLAGS) $(CXXFLAGS) $(DEBUG_FLAGS) tcp_server_epoll.cpp $(COMMON_SOURCES) -o $@ $(LDFLAGS) $(LDLIBS)

$(DEBUG_DIR)/tcp_client: tcp_client.cpp $(COMMON_SOURCES) $(COMMON_HEADERS) Makefile | $(DEBUG_DIR)
	$(CXX) $(CPPFLAGS) $(COMMON_FLAGS) $(CXXFLAGS) $(DEBUG_FLAGS) tcp_client.cpp $(COMMON_SOURCES) -o $@ $(LDFLAGS) $(LDLIBS)

$(DEBUG_DIR)/runtime_contract_test: tests/runtime_contract_test.cpp src/runtime/bounded_executor.cpp include/epoll_runtime/bounded_executor.h include/epoll_runtime/completion_queue.h include/epoll_runtime/connection_id.h include/epoll_runtime/protocol.h Makefile | $(DEBUG_DIR)
	$(CXX) $(CPPFLAGS) $(COMMON_FLAGS) $(CXXFLAGS) $(DEBUG_FLAGS) tests/runtime_contract_test.cpp src/runtime/bounded_executor.cpp -o $@ $(LDFLAGS)

$(SANITIZER_DIR)/tcp_server_epoll: tcp_server_epoll.cpp $(COMMON_SOURCES) $(SERVER_HEADERS) Makefile | $(SANITIZER_DIR)
	$(CXX) $(CPPFLAGS) $(COMMON_FLAGS) $(CXXFLAGS) $(SANITIZER_FLAGS) tcp_server_epoll.cpp $(COMMON_SOURCES) -o $@ $(LDFLAGS) $(SANITIZER_LDFLAGS) $(LDLIBS)

$(SANITIZER_DIR)/tcp_client: tcp_client.cpp $(COMMON_SOURCES) $(COMMON_HEADERS) Makefile | $(SANITIZER_DIR)
	$(CXX) $(CPPFLAGS) $(COMMON_FLAGS) $(CXXFLAGS) $(SANITIZER_FLAGS) tcp_client.cpp $(COMMON_SOURCES) -o $@ $(LDFLAGS) $(SANITIZER_LDFLAGS) $(LDLIBS)

$(PRODUCTION_DIR)/tcp_server_epoll: tcp_server_epoll.cpp $(COMMON_SOURCES) $(SERVER_HEADERS) Makefile | $(PRODUCTION_DIR)
	$(CXX) $(CPPFLAGS) $(COMMON_FLAGS) $(CXXFLAGS) $(PRODUCTION_FLAGS) tcp_server_epoll.cpp $(COMMON_SOURCES) -o $@ $(LDFLAGS) $(PRODUCTION_LDFLAGS) $(LDLIBS)

$(PRODUCTION_DIR)/tcp_client: tcp_client.cpp $(COMMON_SOURCES) $(COMMON_HEADERS) Makefile | $(PRODUCTION_DIR)
	$(CXX) $(CPPFLAGS) $(COMMON_FLAGS) $(CXXFLAGS) $(PRODUCTION_FLAGS) tcp_client.cpp $(COMMON_SOURCES) -o $@ $(LDFLAGS) $(PRODUCTION_LDFLAGS) $(LDLIBS)

$(PERFORMANCE_DIR)/tcp_server_epoll: tcp_server_epoll.cpp $(COMMON_SOURCES) $(SERVER_HEADERS) Makefile | $(PERFORMANCE_DIR)
	$(CXX) $(CPPFLAGS) $(COMMON_FLAGS) $(CXXFLAGS) $(PERFORMANCE_FLAGS) tcp_server_epoll.cpp $(COMMON_SOURCES) -o $@ $(LDFLAGS) $(PERFORMANCE_LDFLAGS) $(LDLIBS)

$(PERFORMANCE_DIR)/tcp_client: tcp_client.cpp $(COMMON_SOURCES) $(COMMON_HEADERS) Makefile | $(PERFORMANCE_DIR)
	$(CXX) $(CPPFLAGS) $(COMMON_FLAGS) $(CXXFLAGS) $(PERFORMANCE_FLAGS) tcp_client.cpp $(COMMON_SOURCES) -o $@ $(LDFLAGS) $(PERFORMANCE_LDFLAGS) $(LDLIBS)

clean:
	rm -rf -- $(BUILD_DIR)

help:
	@echo "Build targets:"
	@echo "  make debug         Development build with symbols and libstdc++ assertions"
	@echo "  make sanitizer     AddressSanitizer + UndefinedBehaviorSanitizer build"
	@echo "  make production    Optimized, portable, hardened production-test build (default)"
	@echo "  make performance   Maximum local-CPU optimization for benchmarking"
	@echo "  make test          Run reusable runtime contract tests"
	@echo "  make all           Build every variant"
	@echo "  make clean         Remove the build directory"
	@echo
	@echo "Override the compiler with: make CXX=/path/to/g++ <target>"
