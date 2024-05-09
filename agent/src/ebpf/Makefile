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
#
# gnu compile:
#     source /opt/rh/devtoolset-8/enable (need gcc8+)
#     make rust-sample
#
# musl compile: (x86_64)
#     source /opt/rh/devtoolset-11/enable (need gcc11+)
#     CC=musl-gcc CLANG=musl-clang make rust-sample
#

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
GNU_CC ?= gcc
MUSL_CC ?= musl-gcc
OBJDIR ?= .
STATIC_OBJDIR := $(OBJDIR)/staticobjs

define compile_socket_trace_elf
	@echo "  COMPILE ELF kernel version $(1)"
	@cd kernel && make clean --no-print-directory && make socket_trace.bpf.elf $(2) --no-print-directory && cd ../
	@echo "  Generate file user/socket_trace_bpf_$(strip $1).c"
	@./tools/bintobuffer kernel/socket_trace.bpf.elf user/socket_trace_bpf_$(strip $1).c socket_trace_$(strip $1)_ebpf_data
endef

define compile_perf_profiler_elf
	@echo "  COMPILE ELF kernel version $(1)"
	@cd kernel && make clean --no-print-directory && make perf_profiler.bpf.elf $(2) --no-print-directory && cd ../
	@echo "  Generate file user/perf_profiler_bpf_$(strip $1).c"
	@./tools/bintobuffer kernel/perf_profiler.bpf.elf user/perf_profiler_bpf_$(strip $1).c perf_profiler_$(strip $1)_ebpf_data
endef

define check_gcc_version
        @GCC_VER=`gcc --version | grep ^gcc | cut -f3 -d' '|cut -f1-2 -d.`; \
	VER_GTE112=`echo $${GCC_VER} \>= 11.2 | sed -e 's/\./*100+/g' | bc`; \
	VER_GTE80=`echo $${GCC_VER} \>= 8.0 | sed -e 's/\./*100+/g' | bc`; \
	if [ $${VER_GTE80} -eq 0 ]; then \
            echo "Error: GCC version is less than 8.0.0"; \
            exit 1; \
        fi; \
	if [ $(1) -eq 1 -a $${VER_GTE112} -eq 0 ]; then \
	    echo "Error: musl compile need less than 11.2.0"; \
	    exit 1; \
        fi;
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
	user/offset.o \
	user/mem.o \
	user/vec.o \
	user/bihash.o \
	user/profile/profile_common.o \
	$(patsubst %.c,%.o,$(wildcard user/profile/extended/*.c)) \
	user/profile/perf_profiler.o \
	user/profile/stringifier.o \
	user/profile/java/df_jattach.o \
	user/profile/java/gen_syms_file.o

JAVA_TOOL := deepflow-jattach
JAVA_AGENT_VERSION := 1
JAVA_AGENT_GNU_SO := df_java_agent_v$(JAVA_AGENT_VERSION).so
JAVA_AGENT_MUSL_SO := df_java_agent_musl_v$(JAVA_AGENT_VERSION).so
JAVA_AGENT_SO := $(JAVA_AGENT_GNU_SO) $(JAVA_AGENT_MUSL_SO)
JAVA_AGENT_SRC := user/profile/java/agent.c
JAVA_AGENT_MACROS := -DAGENT_LIB_NAME="\"$(JAVA_AGENT_GNU_SO)\"" -DAGENT_MUSL_LIB_NAME="\"$(JAVA_AGENT_MUSL_SO)\""

STATIC_OBJS := $(addprefix $(STATIC_OBJDIR)/,$(OBJS))
CFLAGS ?= -std=gnu99 -g -O2 -ffunction-sections -fdata-sections -fPIC -Wall -Wno-strict-aliasing -Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers
# '-Wformat-truncation' : The warning was added in gcc7.1
GCC_VER_GTE71 := $(shell echo `gcc --version | grep ^gcc | cut -f3 -d' '|cut -f1-2 -d.` \>= 7.1 | sed -e 's/\./*100+/g' | bc )
ifeq ($(GCC_VER_GTE71),1)
  CFLAGS += -Wformat-truncation=0
endif
CFLAGS += $(JAVA_AGENT_MACROS)

# -DBPF_DEBUG for parse and load ebpf probes.
# -fsanitize=address: Enable the Address Sanitizer tool, which
#  can detect memory errors such as using uninitialized memory,
#  accessing freed memory, and so on.
# -fno-omit-frame-pointer: When a memory error is detected, print
#  the function call stack to facilitate locating the code line
#  where the error occurred.
# -DDF_MEM_DEBUG Used for memory leak detection, to check for memory
#  leak issues during the debugging phase.
CFLAGS += $(MACHINE_CFLAGS) -fno-omit-frame-pointer -I/usr/lib/jvm/java/include -I/usr/lib/jvm/java/include/linux -I.
ifeq ($(findstring musl,$(CC)),musl)
    IS_MUSL := 1
    ifeq ($(findstring aarch64,$(ARCH)),aarch64)
	CFLAGS += -DAARCH64_MUSL
    endif
else
    IS_MUSL := 0
endif

all: build

SOCKET_TRACE_ELFS := \
	user/socket_trace_bpf_common.c \
	user/socket_trace_bpf_3_10_0.c \
	user/socket_trace_bpf_5_2_plus.c \
	user/socket_trace_bpf_kylin.c

PERF_PROFILER_ELFS := user/perf_profiler_bpf_common.c

ELFFILES := $(SOCKET_TRACE_ELFS) $(PERF_PROFILER_ELFS)

tools/bintobuffer:
	$(call msg,TOOLS,tools/bintobuffer)
	@$(CC) tools/bintobuffer.c -o tools/bintobuffer

define check_clang
	$(call msg,Clang/LLVM,,$(CLANG_VER))
	@if [ $(CLANG_VER_MAIN) -lt 10 ]; then \
                echo "  check llvm-clang fail. expect Clang/LLVM 10+" && exit 1; \
        fi
	@rm -rf data
endef

user/socket_trace_bpf_common.c: tools/bintobuffer kernel/socket_trace.bpf.c
	$(call check_clang)
	$(call compile_socket_trace_elf, common)

user/socket_trace_bpf_3_10_0.c: tools/bintobuffer kernel/socket_trace.bpf.c
	$(call check_clang)
	$(call compile_socket_trace_elf, 3_10_0, LINUX_VER_3_10_0=1)

user/socket_trace_bpf_5_2_plus.c: tools/bintobuffer kernel/socket_trace.bpf.c
	$(call check_clang)
	$(call compile_socket_trace_elf, 5_2_plus, LINUX_VER_5_2_PLUS=1)

user/socket_trace_bpf_kylin.c: tools/bintobuffer kernel/socket_trace.bpf.c
	$(call check_clang)
	$(call compile_socket_trace_elf, kylin, LINUX_VER_KYLIN=1)

user/perf_profiler_bpf_common.c: tools/bintobuffer kernel/perf_profiler.bpf.c
	$(call check_clang)
	$(call compile_perf_profiler_elf, common)

$(STATIC_OBJDIR) $(SHARED_OBJDIR):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@/user/profile/{java,extended}

$(STATIC_OBJDIR)/user/socket.o: user/socket.c $(SOCKET_TRACE_ELFS) | $(STATIC_OBJDIR)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

$(STATIC_OBJDIR)/user/profile/perf_profiler.o: user/profile/perf_profiler.c $(PERF_PROFILER_ELFS) | $(STATIC_OBJDIR)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

$(STATIC_OBJDIR)/%.o: %.c | $(STATIC_OBJDIR)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

$(LIBTRACE): $(STATIC_OBJS)
	$(call msg,AR,$@)
	$(Q)$(AR) rcs $@ $^

$(JAVA_AGENT_GNU_SO): tools/bintobuffer $(JAVA_AGENT_SRC)
	$(call msg,SO,$@)
	$(Q)$(GNU_CC) $(CFLAGS) -shared -o $@ $(JAVA_AGENT_SRC)
	@rm -rf user/profile/java_agent_so_gnu.c
	@./tools/bintobuffer ./$@ user/profile/java_agent_so_gnu.c java_agent_so_gnu

$(JAVA_AGENT_MUSL_SO): tools/bintobuffer $(JAVA_AGENT_SRC)
	$(call msg,SO,$@)
	$(Q)$(MUSL_CC) $(CFLAGS) -shared -o $@ $(JAVA_AGENT_SRC)
	@rm -rf user/profile/java_agent_so_musl.c
	@./tools/bintobuffer ./$@ user/profile/java_agent_so_musl.c java_agent_so_musl

build: $(ELFFILES) $(JAVA_TOOL) $(LIBTRACE)

tools: $(LIBTRACE)
	$(call msg,TOOLS,deepflow-ebpfctl)
	$(Q)$(CC) $(CFLAGS) --static -g -O2 user/ctrl_tracer.c user/ctrl.c $(LIBTRACE) -o deepflow-ebpfctl -lelf -lz -lpthread

$(JAVA_TOOL): $(JAVA_AGENT_SO) user/profile/java/df_jattach.c user/log.c user/common.c libs/jattach/build/libjattach.a
	$(call msg,TOOLS,$@)
	@$(GNU_CC) $(CFLAGS) -DJAVA_AGENT_ATTACH_TOOL user/profile/java/df_jattach.c user/log.c user/common.c libs/jattach/build/libjattach.a -o $@ -ldl -lpthread
	@rm -rf user/profile/deepflow_jattach_bin.c
	@./tools/bintobuffer ./$@ user/profile/deepflow_jattach_bin.c deepflow_jattach_bin

libs/jattach/build/libjattach.a:
	$(call msg,MAKE,$@)
	$(Q)patch -p1 -d libs/jattach -Ns --no-backup-if-mismatch <libs/0001-Add-compilation-for-static-lib.patch || true
	$(Q)$(MAKE) -sC libs/jattach dll --no-print-directory

rust-sample: .socket-tracer .profiler
socket-tracer: .socket-tracer
profiler: .profiler
.socket-tracer: $(ELFFILES) $(JAVA_TOOL) $(LIBTRACE)
	$(call msg,Current-DIR,,$(CURR))
	$(Q)rm -rf samples/rust/socket-tracer/src/ebpf.rs
	$(Q)cp mod.rs samples/rust/socket-tracer/src/ebpf.rs
	$(Q)rm -rf samples/rust/socket-tracer/target
	@if [[ $(ARCH) == *"aarch64"* ]]; then \
            echo "  Architecture is aarch64"; \
	    if [ $(IS_MUSL) -eq 1 ]; then \
                cd samples/rust/socket-tracer/ && cargo build --release --target aarch64-unknown-linux-musl && cd ../../; \
                echo "  samples/rust/socket-tracer/target/aarch64-unknown-linux-musl/release/rust_sample"; \
            else \
                cd samples/rust/socket-tracer/ && cargo build --release && cd ../../; \
                echo "  samples/rust/socket-tracer/target/release/socket_tracer"; \
            fi; \
        elif [[ $(ARCH) == *"x86_64"* ]]; then \
            echo "  Architecture is x86_64"; \
	    if [ $(IS_MUSL) -eq 1 ]; then \
                cd samples/rust/socket-tracer/ && RUSTFLAGS='-D warnings -C force-frame-pointers=yes' cargo build --release --target x86_64-unknown-linux-musl && cd ../../; \
		echo "  samples/rust/socket-tracer/target/x86_64-unknown-linux-musl/release/socket_tracer"; \
            else \
                cd samples/rust/socket-tracer/ && RUSTFLAGS=-Cforce-frame-pointers=yes cargo build --release && cd ../../; \
                echo "  samples/rust/socket-tracer/target/release/socket_tracer"; \
	    fi; \
        else \
            echo "  Error: Invalid arch. $(ARCH) is not support!"; \
            exit 1; \
        fi
	$(Q)touch .socket-tracer

.profiler: $(ELFFILES) $(JAVA_TOOL) $(LIBTRACE)
	$(call msg,Current-DIR,,$(CURR))
	$(Q)rm -rf samples/rust/profiler/src/ebpf.rs
	$(Q)cp mod.rs samples/rust/profiler/src/ebpf.rs
	$(Q)rm -rf samples/rust/profiler/target
	@if [[ $(ARCH) == *"aarch64"* ]]; then \
            echo "  Architecture is aarch64"; \
	    if [ $(IS_MUSL) -eq 1 ]; then \
                cd samples/rust/profiler/ && cargo build --release --target aarch64-unknown-linux-musl && cd ../../; \
                echo "  samples/rust/profiler/target/aarch64-unknown-linux-musl/release/profiler"; \
            else \
                cd samples/rust/profiler/ && cargo build --release && cd ../../; \
                echo "  samples/rust/profiler/target/release/profiler"; \
            fi; \
        elif [[ $(ARCH) == *"x86_64"* ]]; then \
            echo "  Architecture is x86_64"; \
	    if [ $(IS_MUSL) -eq 1 ]; then \
                cd samples/rust/profiler/ && cargo build --release --target x86_64-unknown-linux-musl && cd ../../; \
                echo "  samples/rust/profiler/target/x86_64-unknown-linux-musl/release/profiler"; \
	    else \
                cd samples/rust/profiler/ && RUSTFLAGS="-C force-frame-pointers=yes" cargo build --release && cd ../../; \
                echo "  samples/rust/profiler/target/release/profiler"; \
	    fi; \
        else \
            echo "  Error: Invalid arch. $(ARCH) is not support!"; \
            exit 1; \
        fi
	$(Q)touch .profiler

clean-sample:
	$(Q)rm -rf .profiler .socket-tracer
	$(Q)rm -rf samples/rust/socket-tracer/target
	$(Q)rm -rf samples/rust/profiler/target

clean:
	$(Q)$(MAKE) -C kernel clean --no-print-directory
	$(Q)$(MAKE) -C test clean --no-print-directory
	$(Q)$(MAKE) -C libs/jattach clean --no-print-directory
	$(Q)rm -rf $(ELFFILES) data deepflow-ebpfctl $(STATIC_OBJDIR) $(LIBTRACE) *.a
	$(Q)rm -rf .profiler .socket-tracer
	$(Q)rm -rf samples/rust/socket-tracer/target
	$(Q)rm -rf samples/rust/profiler/target
	$(Q)rm -rf $(JAVA_AGENT_SO) $(JAVA_TOOL) tools/bintobuffer

test: $(ELFFILES) $(LIBTRACE)
	$(Q)$(MAKE) -C test --no-print-directory

.PHONY: all build clean tools test rust-sample .socket-tracer .profiler

