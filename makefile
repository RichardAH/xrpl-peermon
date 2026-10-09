# peermon build.
#
#   make            build ./peermon
#   make info       show which compiler / protoc / protobuf the build resolved
#   make test       decoder tests        make e2e     end-to-end tests
#   make clean
#
# Overridable: CXX, CXXFLAGS, CPPFLAGS, LDFLAGS, LDLIBS, PROTOC, PKG_CONFIG

ifeq ($(origin CXX),default)
CXX = clang++
endif
CXXFLAGS ?= -g
CXXSTD := -std=c++20
PKG_CONFIG ?= pkg-config

HAVE_PKG_CONFIG := $(shell command -v $(PKG_CONFIG) 2>/dev/null)

# ---- protobuf ----------------------------------------------------------------
# ripple.pb.cc has to be generated, compiled and linked against ONE protobuf
# install. With a newer protobuf in /usr/local next to the distro's
# libprotobuf-dev, a plain `protoc` + `-lprotobuf` build mixes them: PATH and
# the compiler's include path prefer /usr/local, but the linker searches
# /usr/lib/<arch> first, giving undefined google::protobuf::internal::*
# references at link time. pkg-config also searches /usr/local first, so
# headers, libraries (including abseil, which protobuf >= 22 needs) and, by
# default, protoc itself all come from the install it finds.
ifneq ($(HAVE_PKG_CONFIG),)
PROTOBUF_VERSION := $(shell $(PKG_CONFIG) --modversion protobuf 2>/dev/null)
endif
ifneq ($(PROTOBUF_VERSION),)
PROTOBUF_PREFIX := $(shell $(PKG_CONFIG) --variable=prefix protobuf)
PROTOBUF_LIBDIR := $(shell $(PKG_CONFIG) --variable=libdir protobuf)
PROTOBUF_CFLAGS := $(shell $(PKG_CONFIG) --cflags protobuf)
PROTOBUF_LIBS   := $(shell $(PKG_CONFIG) --libs protobuf)
# Run against the library we linked even if it is not on the loader's path.
ifneq ($(filter-out /usr/lib% /lib%,$(PROTOBUF_LIBDIR)),)
PROTOBUF_LIBS   += -Wl,-rpath,$(PROTOBUF_LIBDIR)
endif
PROTOC ?= $(if $(wildcard $(PROTOBUF_PREFIX)/bin/protoc),$(PROTOBUF_PREFIX)/bin/protoc,protoc)
else
PROTOBUF_LIBS   := -lprotobuf
PROTOC ?= protoc
endif

# ---- other libraries ---------------------------------------------------------
DEP_PKGS := libsodium libsecp256k1 openssl
ifneq ($(HAVE_PKG_CONFIG),)
DEP_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(DEP_PKGS) 2>/dev/null)
DEP_LIBS   := $(shell $(PKG_CONFIG) --libs $(DEP_PKGS) 2>/dev/null)
endif
ifeq ($(DEP_LIBS),)
DEP_LIBS   := -lsecp256k1 -lsodium -lssl -lcrypto
endif

ALL_CPPFLAGS := $(CPPFLAGS) $(PROTOBUF_CFLAGS) $(DEP_CFLAGS)
ALL_LIBS     := $(LDFLAGS) $(DEP_LIBS) $(PROTOBUF_LIBS) $(LDLIBS)

# The .c sources are C++ (extern "C" blocks); say so instead of relying on the
# compiler treating .c as C++.
AS_CXX = -x c++ $(1) -x none

peermon: peermon.cpp ripple.pb.cc ripple.pb.h base58.c libbase58.h sha-256.c sha-256.h xd.h xd.c xd_defs.h stlookup.h .cxx-abi-flags
	$(CXX) $(CXXSTD) $$(cat .cxx-abi-flags) $(CXXFLAGS) $(ALL_CPPFLAGS) peermon.cpp ripple.pb.cc $(call AS_CXX,base58.c xd.c sha-256.c) $(ALL_LIBS) -o $@

# ---- toolchain stamp -----------------------------------------------------------
# Records the compiler, protoc and protobuf install. Generated code and the ABI
# probe below are redone when any of them changes (a ripple.pb.cc left over
# from another protobuf version fails to build or link). The stamp is only
# rewritten when its content changes, so unchanged builds stay no-ops.
TOOLCHAIN_STAMP_TEXT := $(CXX) $(shell $(CXX) --version 2>/dev/null | head -1) | $(PROTOC) $(shell $(PROTOC) --version 2>/dev/null) | $(PROTOBUF_VERSION) $(PROTOBUF_PREFIX)
.toolchain.stamp: FORCE
	@if [ "$$(cat $@ 2>/dev/null)" != '$(TOOLCHAIN_STAMP_TEXT)' ]; then echo '$(TOOLCHAIN_STAMP_TEXT)' > $@; fi

# ---- C++ ABI probe -------------------------------------------------------------
# Clang >= 18 mangles some template instantiations differently ("Tn" template
# parameter mangling) from GCC and older clang. Linking clang 18+ objects
# against an abseil (protobuf >= 22) built by those fails with undefined
# absl::...::LogMessage::operator<< references. If a minimal abseil logging
# program only links with -fclang-abi-compat=17, use that; otherwise add
# nothing (also the case for protobuf < 22, which has no abseil).
.cxx-abi-flags: .toolchain.stamp
	@printf '%s\n' '#include <absl/log/absl_log.h>' \
		'int main(int argc, char**) { ABSL_LOG(INFO) << (unsigned long)argc; return 0; }' > .cxx-abi-probe.cpp; \
	probe() { $(CXX) $(CXXSTD) $$1 $(ALL_CPPFLAGS) .cxx-abi-probe.cpp $(PROTOBUF_LIBS) -o .cxx-abi-probe > /dev/null 2>&1; }; \
	if probe "" || ! probe -fclang-abi-compat=17; then \
		: > $@; \
	else \
		echo "note: $(CXX) needs -fclang-abi-compat=17 to link against this abseil (built by GCC or clang < 18)"; \
		echo -fclang-abi-compat=17 > $@; \
	fi; \
	rm -f .cxx-abi-probe .cxx-abi-probe.cpp

# ---- generated protobuf code ---------------------------------------------------
# A pattern rule with two targets builds both with one protoc run.
%.pb.cc %.pb.h: %.proto .toolchain.stamp
	@# versions are compared as major.minor, ignoring pre-release suffixes ("30.0-dev" vs "30.0.0")
	@protoc_version=$$($(PROTOC) --version 2>/dev/null | sed 's/^libprotoc //'); \
	if [ -z "$$protoc_version" ]; then \
		echo "error: '$(PROTOC)' not found. Install protobuf-compiler or run make PROTOC=/path/to/protoc"; exit 1; \
	fi; \
	lib_version='$(PROTOBUF_VERSION)'; \
	if [ -n "$$lib_version" ]; then \
		major_minor() { echo "$$1" | sed 's/-.*//' | cut -d. -f1-2; }; \
		if [ "$$(major_minor "$$protoc_version")" != "$$(major_minor "$$lib_version")" ]; then \
			echo "error: $(PROTOC) is protoc $$protoc_version, but pkg-config found protobuf $$lib_version in $(PROTOBUF_PREFIX)."; \
			echo "       Generated code only compiles and links against its own protobuf version. Use a matching pair, e.g."; \
			echo "         make PROTOC=$(PROTOBUF_PREFIX)/bin/protoc"; \
			echo "         PKG_CONFIG_PATH=<prefix of that protoc>/lib/pkgconfig make"; \
			exit 1; \
		fi; \
	else \
		echo "warning: protobuf not found via pkg-config; using $(PROTOC) $$protoc_version with -lprotobuf."; \
		echo "         If linking fails with undefined google::protobuf symbols, protoc and libprotobuf differ."; \
	fi
	$(PROTOC) --cpp_out=. $<

info: .cxx-abi-flags
	@echo "CXX              $(CXX) ($$($(CXX) --version 2>/dev/null | head -1))"
	@echo "ABI flags        $$(cat .cxx-abi-flags)"
	@echo "pkg-config       $(if $(HAVE_PKG_CONFIG),$(HAVE_PKG_CONFIG),not found)"
	@echo "protoc           $(PROTOC) ($$($(PROTOC) --version 2>/dev/null || echo not found))"
	@echo "protobuf         $(if $(PROTOBUF_VERSION),$(PROTOBUF_VERSION) in $(PROTOBUF_PREFIX),not found via pkg-config)"
	@echo "protobuf libs    $(PROTOBUF_LIBS)"
	@echo "other libs       $(DEP_LIBS)"

# Regenerate xd_defs.h from rippled and xahaud source trees, e.g.
#   make defs XRPL_SRC=../rippled XAHAU_SRC=../xahaud
defs:
	./gen_defs.py --xrpl $(XRPL_SRC) --xahau $(XAHAU_SRC) > xd_defs.h.tmp && mv xd_defs.h.tmp xd_defs.h

# Decoder tests: decode codec-generated XRPL and Xahau vectors and compare.
tests/xd_decode: tests/xd_decode.cpp base58.c libbase58.h sha-256.c sha-256.h xd.h xd.c xd_defs.h
	$(CXX) $(CXXSTD) $(CXXFLAGS) $(CPPFLAGS) tests/xd_decode.cpp $(call AS_CXX,xd.c base58.c sha-256.c) $(LDFLAGS) $(LDLIBS) -o $@

test: tests/xd_decode
	python3 tests/run_tests.py

# End-to-end: peermon against a mock peer enforcing xahaud's handshake rules.
tests/mock_peer: tests/mock_peer.cpp ripple.pb.cc ripple.pb.h base58.c libbase58.h sha-256.c sha-256.h .cxx-abi-flags
	$(CXX) $(CXXSTD) $$(cat .cxx-abi-flags) $(CXXFLAGS) $(ALL_CPPFLAGS) tests/mock_peer.cpp ripple.pb.cc $(call AS_CXX,base58.c sha-256.c) $(ALL_LIBS) -o $@

e2e: peermon tests/mock_peer
	./tests/e2e.sh

clean:
	rm -f peermon ripple.pb.cc ripple.pb.h .toolchain.stamp .cxx-abi-flags tests/xd_decode tests/mock_peer

FORCE:
.PHONY: info defs test e2e clean FORCE
