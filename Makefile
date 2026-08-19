CXX ?= g++
CPPFLAGS ?=
CXXFLAGS ?=
LDFLAGS ?=

COMMON_FLAGS := -std=c++23 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -pthread
COMMON_HEADERS := tcp_common_config.h
SERVER_HEADERS := $(COMMON_HEADERS) tcp_server_epoll.h

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

.PHONY: all debug development sanitizer production release performance \
	all-variants clean help

all: production

development: debug

release: production

debug: $(DEBUG_DIR)/tcp_server_epoll $(DEBUG_DIR)/tcp_client

sanitizer: $(SANITIZER_DIR)/tcp_server_epoll $(SANITIZER_DIR)/tcp_client

production: $(PRODUCTION_DIR)/tcp_server_epoll $(PRODUCTION_DIR)/tcp_client

performance: $(PERFORMANCE_DIR)/tcp_server_epoll $(PERFORMANCE_DIR)/tcp_client

all-variants: debug sanitizer production performance

$(DEBUG_DIR) $(SANITIZER_DIR) $(PRODUCTION_DIR) $(PERFORMANCE_DIR):
	mkdir -p $@

$(DEBUG_DIR)/tcp_server_epoll: tcp_server_epoll.cpp $(SERVER_HEADERS) Makefile | $(DEBUG_DIR)
	$(CXX) $(CPPFLAGS) $(COMMON_FLAGS) $(CXXFLAGS) $(DEBUG_FLAGS) $< -o $@ $(LDFLAGS)

$(DEBUG_DIR)/tcp_client: tcp_client.cpp $(COMMON_HEADERS) Makefile | $(DEBUG_DIR)
	$(CXX) $(CPPFLAGS) $(COMMON_FLAGS) $(CXXFLAGS) $(DEBUG_FLAGS) $< -o $@ $(LDFLAGS)

$(SANITIZER_DIR)/tcp_server_epoll: tcp_server_epoll.cpp $(SERVER_HEADERS) Makefile | $(SANITIZER_DIR)
	$(CXX) $(CPPFLAGS) $(COMMON_FLAGS) $(CXXFLAGS) $(SANITIZER_FLAGS) $< -o $@ $(LDFLAGS) $(SANITIZER_LDFLAGS)

$(SANITIZER_DIR)/tcp_client: tcp_client.cpp $(COMMON_HEADERS) Makefile | $(SANITIZER_DIR)
	$(CXX) $(CPPFLAGS) $(COMMON_FLAGS) $(CXXFLAGS) $(SANITIZER_FLAGS) $< -o $@ $(LDFLAGS) $(SANITIZER_LDFLAGS)

$(PRODUCTION_DIR)/tcp_server_epoll: tcp_server_epoll.cpp $(SERVER_HEADERS) Makefile | $(PRODUCTION_DIR)
	$(CXX) $(CPPFLAGS) $(COMMON_FLAGS) $(CXXFLAGS) $(PRODUCTION_FLAGS) $< -o $@ $(LDFLAGS) $(PRODUCTION_LDFLAGS)

$(PRODUCTION_DIR)/tcp_client: tcp_client.cpp $(COMMON_HEADERS) Makefile | $(PRODUCTION_DIR)
	$(CXX) $(CPPFLAGS) $(COMMON_FLAGS) $(CXXFLAGS) $(PRODUCTION_FLAGS) $< -o $@ $(LDFLAGS) $(PRODUCTION_LDFLAGS)

$(PERFORMANCE_DIR)/tcp_server_epoll: tcp_server_epoll.cpp $(SERVER_HEADERS) Makefile | $(PERFORMANCE_DIR)
	$(CXX) $(CPPFLAGS) $(COMMON_FLAGS) $(CXXFLAGS) $(PERFORMANCE_FLAGS) $< -o $@ $(LDFLAGS) $(PERFORMANCE_LDFLAGS)

$(PERFORMANCE_DIR)/tcp_client: tcp_client.cpp $(COMMON_HEADERS) Makefile | $(PERFORMANCE_DIR)
	$(CXX) $(CPPFLAGS) $(COMMON_FLAGS) $(CXXFLAGS) $(PERFORMANCE_FLAGS) $< -o $@ $(LDFLAGS) $(PERFORMANCE_LDFLAGS)

clean:
	rm -rf -- $(BUILD_DIR)

help:
	@echo "Build targets:"
	@echo "  make debug         Development build with symbols and libstdc++ assertions"
	@echo "  make sanitizer     AddressSanitizer + UndefinedBehaviorSanitizer build"
	@echo "  make production    Optimized, portable, hardened production-test build (default)"
	@echo "  make performance   Maximum local-CPU optimization for benchmarking"
	@echo "  make all-variants  Build every variant"
	@echo "  make clean         Remove the build directory"
	@echo
	@echo "Override the compiler with: make CXX=/path/to/g++ <target>"
