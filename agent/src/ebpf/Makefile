# Copyright (c) 2022 Yunshan Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
endif

ARCH := $(shell uname -m)

CLANG ?= /usr/bin/clang
CC ?= gcc
OBJDIR ?= .
STATIC_OBJDIR := $(OBJDIR)/staticobjs

define compile_socket_trace_elf
	@echo "  COMPILE ELF kernel version $(1)"
	@cd kernel && make clean --no-print-directory && make socket_trace.elf $(2) --no-print-directory && cd ../
	@echo "  Generate file user/socket_trace_bpf_$(strip $1).c"
	@./tools/ebpftobuffer kernel/socket_trace.elf user/socket_trace_bpf_$(strip $1).c socket_trace_$(strip $1)_ebpf_data
endef

CURRDIR := $(PWD)
CLANG_VER := $(shell ${CLANG} --version | grep "version" | awk '{if ($$3!="version"){print $$3}else{exit -1}}' || ${CLANG} --version | grep "version" | awk '{if ($$4!="version"){print $$4}else{exit -1}}')
CLANG_VER_MAIN := $(shell ${CLANG} --version | grep "version" | awk '{print $$3}' | awk -F. '{print $$1}' | awk '{if (int($$0)!=0){print $$0}else{exit -1}}' || ${CLANG} --version | grep "version" | awk '{print $$4}' | awk -F. '{print $$1}' | awk '{if (int($$0)!=0){print $$0}else{exit -1}}')
LIBTRACE := libtrace.a
OBJS := user/elf.o \
	user/common.o \
	user/symbol.o \
	user/go_tracer.o \
	user/ssl_tracer.o \
	user/ring.o \
	user/btf_vmlinux.o \
	user/load.o \
	user/log.o \
	user/probe.o \
	user/tracer.o \
	user/table.o \
	user/socket.o \
	user/ctrl.o \
	user/offset.o

STATIC_OBJS := $(addprefix $(STATIC_OBJDIR)/,$(OBJS))
CFLAGS ?= -std=gnu99 -g -O2 -ffunction-sections -fdata-sections -fPIC -fno-omit-frame-pointer -Wall -Wno-strict-aliasing -Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers
# '-Wformat-truncation' : The warning was added in gcc7.1
GCC_VER_GTE71 := $(shell echo `gcc --version | grep ^gcc | cut -f3 -d' '|cut -f1-2 -d.` \>= 7.1 | sed -e 's/\./*100+/g' | bc )
ifeq ($(GCC_VER_GTE71),1)
  CFLAGS += -Wformat-truncation=0
endif

# -DBPF_DEBUG for parse and load ebpf probes.
CFLAGS += $(MACHINE_CFLAGS) -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -I.
all: build

ELFFILES = ./.data_done
$(ELFFILES):
	$(call msg,Clang/LLVM,,$(CLANG_VER))
	@if [ $(CLANG_VER_MAIN) -lt 10 ]; then \
                echo "  check llvm-clang fail. expect Clang/LLVM 10+" && exit 1; \
        fi
	@rm -rf data
	$(call msg,Tools,,tools/ebpftobuffer)
	@$(CC) tools/ebpftobuffer.c -o tools/ebpftobuffer
	$(call compile_socket_trace_elf, common)
	$(call compile_socket_trace_elf, 5_2_plus, LINUX_VER_5_2_PLUS=1)
	$(call compile_socket_trace_elf, kylin, LINUX_VER_KYLIN=1)
	@touch $(ELFFILES)

$(STATIC_OBJDIR) $(SHARED_OBJDIR):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@/user

$(STATIC_OBJDIR)/%.o: %.c | $(STATIC_OBJDIR)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

$(LIBTRACE): $(STATIC_OBJS)
	$(call msg,AR,$@)
	$(Q)$(AR) rcs $@ $^

build: $(ELFFILES) $(LIBTRACE)

tools: $(LIBTRACE)
	$(call msg,TOOLS,deepflow-ebpfctl)
	$(Q)$(CC) $(CFLAGS) --static -g -O2 user/ctrl_tracer.c user/ctrl.c $(LIBTRACE) -o deepflow-ebpfctl -lelf -lz -lpthread

rust-sample: $(ELFFILES) $(LIBTRACE)
	$(call msg,Current-DIR,,$(CURR))
	$(Q)rm -rf samples/rust/src/ebpf.rs
	$(Q)cp mod.rs samples/rust/src/ebpf.rs
	$(Q)rm -rf samples/rust/build.rs
	$(Q)rm -rf samples/rust/target
	@if [[ $(ARCH) == *"aarch64"* ]]; then \
            echo "  Architecture is aarch64"; \
            cp samples/rust/build-aarch64.rs samples/rust/build.rs; \
            cd samples/rust/ && cargo build --release --target aarch64-unknown-linux-musl && cd ../../; \
            echo "  samples/rust/target/aarch64-unknown-linux-musl/release/rust_sample"; \
        elif [[ $(ARCH) == *"x86_64"* ]]; then \
            echo "  Architecture is x86_64"; \
            cp samples/rust/build-x86.rs samples/rust/build.rs; \
            cd samples/rust/ && cargo build --release && cd ../../; \
            echo "  samples/rust/target/release/rust_sample"; \
        else \
            echo "  Error: Invalid arch. $(ARCH) is not support!"; \
            exit 1; \
        fi

clean:
	$(Q)$(MAKE) -C kernel clean --no-print-directory
	$(Q)$(MAKE) -C test clean --no-print-directory
	$(Q)rm -rf $(ELFFILES) data deepflow-ebpfctl $(STATIC_OBJDIR) $(LIBTRACE) *.a
	$(Q)rm -rf samples/rust/target

test: $(ELFFILES) $(LIBTRACE)
	$(Q)$(MAKE) -C test --no-print-directory

.PHONY: all build clean tools test

