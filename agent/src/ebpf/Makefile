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
LLVM_STRIP ?= /usr/bin/llvm-strip
LLVM_OBJDUMP ?= /usr/bin/llvm-objdump
VMLINUX_OBJDUMP ?= 1
OBJDIR ?= .
STATIC_OBJDIR := $(OBJDIR)/staticobjs
KERNEL_OUTPUT_DIR ?= .output

-include user/extended/feature.top.mk

VMLINUX_VARIANT_ARGS_common :=
VMLINUX_VARIANT_ARGS_3_10_0 := LINUX_VER_3_10_0=1
VMLINUX_VARIANT_ARGS_5_2_plus := LINUX_VER_5_2_PLUS=1
VMLINUX_VARIANT_ARGS_kfunc := LINUX_VER_KFUNC=1
VMLINUX_VARIANT_ARGS_kylin := LINUX_VER_KYLIN=1
VMLINUX_VARIANT_ARGS_rt := LINUX_VER_RT=1
VMLINUX_VARIANT_ARGS_kprobe := LINUX_VER_KPROBE=1

VMLINUX_KERNEL_BPF_SRCS := $(wildcard kernel/*.bpf.c)
VMLINUX_KERNEL_HDRS := kernel/config.h $(wildcard kernel/include/*.h)
TRACE_UTILS_HDRS := $(wildcard ../../crates/trace-utils/src/*.h)
VMLINUX_KERNEL_BUILD_DEPS := kernel/Makefile $(VMLINUX_KERNEL_BPF_SRCS) $(VMLINUX_KERNEL_HDRS) $(TRACE_UTILS_HDRS)

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
	user/utils.o \
	user/symbol.o \
	user/proc.o \
	user/go_tracer.o \
	user/ssl_tracer.o \
	user/unwind_tracer.o \
	user/ring.o \
	user/btf_core.o \
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
	user/mount.o \
	user/profile/profile_common.o \
	$(patsubst %.c,%.o,$(wildcard user/extended/*.c)) \
	$(patsubst %.c,%.o,$(wildcard user/extended/profile/*.c)) \
	user/profile/perf_profiler.o \
	user/profile/stringifier.o \
	user/profile/java/jvm_symbol_collect.o \
	user/profile/java/collect_symbol_files.o

JAVA_TOOL := deepflow-jattach
JAVA_AGENT_VERSION := 2
JAVA_AGENT_GNU_SO := df_java_agent_v$(JAVA_AGENT_VERSION).so
JAVA_AGENT_MUSL_SO := df_java_agent_musl_v$(JAVA_AGENT_VERSION).so
JAVA_AGENT_SO := $(JAVA_AGENT_GNU_SO) $(JAVA_AGENT_MUSL_SO)
JAVA_AGENT_SRC := user/profile/java/symbol_collect_agent.c
JAVA_AGENT_MACROS := -DAGENT_LIB_NAME="\"$(JAVA_AGENT_GNU_SO)\"" -DAGENT_MUSL_LIB_NAME="\"$(JAVA_AGENT_MUSL_SO)\""

STATIC_OBJS := $(addprefix $(STATIC_OBJDIR)/,$(OBJS))
CFLAGS ?= -std=gnu99 -g -O2 -ffunction-sections -fdata-sections -fPIC -Wall -Wno-strict-aliasing -Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers -I/usr/include/bcc -I../../../crates/trace-utils/src/
DEPFLAGS ?= -MMD -MP
# '-Wformat-truncation' : The warning was added in gcc7.1
GCC_VER_GTE71 := $(shell echo `gcc --version | grep ^gcc | cut -f3 -d' '|cut -f1-2 -d.` \>= 7.1 | sed -e 's/\./*100+/g' | bc )
ifeq ($(GCC_VER_GTE71),1)
  CFLAGS += -Wformat-truncation=0
endif
CFLAGS += $(JAVA_AGENT_MACROS)

# trace-utils header
CFLAGS += -I../../crates/trace-utils/src

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

SOCKET_TRACE_ELFS := user/socket_trace_bpf_common.c \
	user/socket_trace_bpf_3_10_0.c \
	user/socket_trace_bpf_5_2_plus.c \
	user/socket_trace_bpf_kfunc.c \
	user/socket_trace_bpf_kylin.c \
	user/socket_trace_bpf_rt.c \
	user/socket_trace_bpf_kprobe.c

PERF_PROFILER_ELFS := user/perf_profiler_bpf_common.c \
	user/perf_profiler_bpf_5_2_plus.c

ELFFILES := $(SOCKET_TRACE_ELFS) $(PERF_PROFILER_ELFS) $(AF_PACKET_FANOUT_ELFS)

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

kernel/$(KERNEL_OUTPUT_DIR)/%/socket_trace.bpf.elf.debug: $(VMLINUX_KERNEL_BUILD_DEPS)
	$(call check_clang)
	$(call msg,BPF,$@)
	$(Q)$(MAKE) -C kernel --no-print-directory \
		OUTPUT=$(KERNEL_OUTPUT_DIR)/$* \
		$(VMLINUX_VARIANT_ARGS_$*) \
		$(KERNEL_OUTPUT_DIR)/$*/socket_trace.bpf.elf.debug

kernel/$(KERNEL_OUTPUT_DIR)/%/perf_profiler.bpf.elf.debug: $(VMLINUX_KERNEL_BUILD_DEPS)
	$(call check_clang)
	$(call msg,BPF,$@)
	$(Q)$(MAKE) -C kernel --no-print-directory \
		OUTPUT=$(KERNEL_OUTPUT_DIR)/$* \
		$(VMLINUX_VARIANT_ARGS_$*) \
		$(KERNEL_OUTPUT_DIR)/$*/perf_profiler.bpf.elf.debug

kernel/$(KERNEL_OUTPUT_DIR)/%/socket_trace.bpf.elf: kernel/$(KERNEL_OUTPUT_DIR)/%/socket_trace.bpf.elf.debug
	$(call msg,STRIP,$@)
	$(Q)cp $< $@
	$(Q)$(LLVM_STRIP) -g $@

kernel/$(KERNEL_OUTPUT_DIR)/%/perf_profiler.bpf.elf: kernel/$(KERNEL_OUTPUT_DIR)/%/perf_profiler.bpf.elf.debug
	$(call msg,STRIP,$@)
	$(Q)cp $< $@
	$(Q)$(LLVM_STRIP) -g $@

kernel/$(KERNEL_OUTPUT_DIR)/%/socket_trace.bpf.objdump: kernel/$(KERNEL_OUTPUT_DIR)/%/socket_trace.bpf.elf.debug
	$(call msg,OBJDUMP,$@)
	$(Q)$(LLVM_OBJDUMP) --source --debug-vars --line-numbers --symbol-description $< > $@

kernel/$(KERNEL_OUTPUT_DIR)/%/perf_profiler.bpf.objdump: kernel/$(KERNEL_OUTPUT_DIR)/%/perf_profiler.bpf.elf.debug
	$(call msg,OBJDUMP,$@)
	$(Q)$(LLVM_OBJDUMP) --source --debug-vars --line-numbers --symbol-description $< > $@

VMLINUX_SOCKET_TRACE_VARIANTS := common 3_10_0 5_2_plus kfunc kylin rt kprobe
VMLINUX_PERF_PROFILER_VARIANTS := common 5_2_plus

VMLINUX_SOCKET_TRACE_ELF_DEBUGS := $(addprefix kernel/$(KERNEL_OUTPUT_DIR)/,$(addsuffix /socket_trace.bpf.elf.debug,$(VMLINUX_SOCKET_TRACE_VARIANTS)))
VMLINUX_PERF_PROFILER_ELF_DEBUGS := $(addprefix kernel/$(KERNEL_OUTPUT_DIR)/,$(addsuffix /perf_profiler.bpf.elf.debug,$(VMLINUX_PERF_PROFILER_VARIANTS)))

VMLINUX_SOCKET_TRACE_OBJDUMPS := $(VMLINUX_SOCKET_TRACE_ELF_DEBUGS:.elf.debug=.objdump)
VMLINUX_PERF_PROFILER_OBJDUMPS := $(VMLINUX_PERF_PROFILER_ELF_DEBUGS:.elf.debug=.objdump)

.SECONDARY: $(VMLINUX_SOCKET_TRACE_ELF_DEBUGS) $(VMLINUX_PERF_PROFILER_ELF_DEBUGS)

VMLINUX_KERNEL_OBJDUMP_FILES =
ifneq ($(VMLINUX_OBJDUMP),0)
VMLINUX_KERNEL_OBJDUMP_FILES += $(VMLINUX_SOCKET_TRACE_OBJDUMPS) $(VMLINUX_PERF_PROFILER_OBJDUMPS)
endif

user/socket_trace_bpf_common.c: kernel/$(KERNEL_OUTPUT_DIR)/common/socket_trace.bpf.elf tools/bintobuffer
	@echo "  Generate file $@"
	@./tools/bintobuffer $< $@ socket_trace_common_ebpf_data

user/socket_trace_bpf_3_10_0.c: kernel/$(KERNEL_OUTPUT_DIR)/3_10_0/socket_trace.bpf.elf tools/bintobuffer
	@echo "  Generate file $@"
	@./tools/bintobuffer $< $@ socket_trace_3_10_0_ebpf_data

user/socket_trace_bpf_5_2_plus.c: kernel/$(KERNEL_OUTPUT_DIR)/5_2_plus/socket_trace.bpf.elf tools/bintobuffer
	@echo "  Generate file $@"
	@./tools/bintobuffer $< $@ socket_trace_5_2_plus_ebpf_data

user/socket_trace_bpf_kfunc.c: kernel/$(KERNEL_OUTPUT_DIR)/kfunc/socket_trace.bpf.elf tools/bintobuffer
	@echo "  Generate file $@"
	@./tools/bintobuffer $< $@ socket_trace_kfunc_ebpf_data

user/socket_trace_bpf_kylin.c: kernel/$(KERNEL_OUTPUT_DIR)/kylin/socket_trace.bpf.elf tools/bintobuffer
	@echo "  Generate file $@"
	@./tools/bintobuffer $< $@ socket_trace_kylin_ebpf_data

user/socket_trace_bpf_rt.c: kernel/$(KERNEL_OUTPUT_DIR)/rt/socket_trace.bpf.elf tools/bintobuffer
	@echo "  Generate file $@"
	@./tools/bintobuffer $< $@ socket_trace_rt_ebpf_data

user/socket_trace_bpf_kprobe.c: kernel/$(KERNEL_OUTPUT_DIR)/kprobe/socket_trace.bpf.elf tools/bintobuffer
	@echo "  Generate file $@"
	@./tools/bintobuffer $< $@ socket_trace_kprobe_ebpf_data

user/perf_profiler_bpf_common.c: kernel/$(KERNEL_OUTPUT_DIR)/common/perf_profiler.bpf.elf tools/bintobuffer
	@echo "  Generate file $@"
	@./tools/bintobuffer $< $@ perf_profiler_common_ebpf_data

user/perf_profiler_bpf_5_2_plus.c: kernel/$(KERNEL_OUTPUT_DIR)/5_2_plus/perf_profiler.bpf.elf tools/bintobuffer
	@echo "  Generate file $@"
	@./tools/bintobuffer $< $@ perf_profiler_5_2_plus_ebpf_data

$(STATIC_OBJDIR) $(SHARED_OBJDIR):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@/user/profile/java
	$(Q)mkdir -p $@/user/extended/profile

$(STATIC_OBJDIR)/user/socket.o: user/socket.c $(SOCKET_TRACE_ELFS) | $(STATIC_OBJDIR)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(DEPFLAGS) -MF $(@:.o=.d) -MT $@ -c $< -o $@

$(STATIC_OBJDIR)/user/profile/perf_profiler.o: user/profile/perf_profiler.c $(PERF_PROFILER_ELFS) | $(STATIC_OBJDIR)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(DEPFLAGS) -MF $(@:.o=.d) -MT $@ -c $< -o $@

$(STATIC_OBJDIR)/%.o: %.c | $(STATIC_OBJDIR)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(DEPFLAGS) -MF $(@:.o=.d) -MT $@ -c $< -o $@

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

build: $(ELFFILES) $(JAVA_TOOL) $(LIBTRACE) $(VMLINUX_KERNEL_OBJDUMP_FILES)

tools: $(LIBTRACE)
	$(call msg,TOOLS,deepflow-ebpfctl)
	$(Q)$(CC) $(CFLAGS) --static -g -O2 user/ctrl_tracer.c user/ctrl.c $(LIBTRACE) -o deepflow-ebpfctl -lelf -lz -lpthread

$(JAVA_TOOL): $(JAVA_AGENT_SO) user/log.c user/utils.c user/mem.c user/vec.c user/profile/java/jvm_symbol_collect.c libs/jattach/build/libjattach.a
	$(call msg,TOOLS,$@)
	@$(GNU_CC) $(CFLAGS) -DJAVA_AGENT_ATTACH_TOOL user/log.c user/utils.c user/mem.c user/vec.c user/profile/java/jvm_symbol_collect.c libs/jattach/build/libjattach.a -o $@ -ldl -lpthread
	@rm -rf user/profile/deepflow_jattach_bin.c
	@./tools/bintobuffer ./$@ user/profile/deepflow_jattach_bin.c deepflow_jattach_bin

libs/jattach/build/libjattach.a:
	$(call msg,MAKE,$@)
	$(Q)patch -p1 -d libs/jattach -Ns --no-backup-if-mismatch <libs/0001-Add-compilation-for-static-lib.patch || true
	$(Q)$(MAKE) -sC libs/jattach dll --no-print-directory

-include user/extended/feature.bottom.mk
-include $(STATIC_OBJS:.o=.d)

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
	$(Q)rm -rf kernel/$(KERNEL_OUTPUT_DIR)
	$(Q)rm -rf .profiler .socket-tracer
	$(Q)rm -rf samples/rust/socket-tracer/target
	$(Q)rm -rf samples/rust/profiler/target
	$(Q)rm -rf $(JAVA_AGENT_SO) $(JAVA_TOOL) tools/bintobuffer

test: $(ELFFILES) $(LIBTRACE)
	$(Q)$(MAKE) -C test --no-print-directory

.PHONY: all build clean tools test rust-sample .socket-tracer .profiler
