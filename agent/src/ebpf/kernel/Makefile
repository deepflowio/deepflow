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

LLC ?= /usr/bin/llc
CLANG ?= /usr/bin/clang
LLVM_STRIP ?= /usr/bin/llvm-strip
LLVM_OBJDUMP ?= /usr/bin/llvm-objdump
CC ?= gcc
TAEGET_KERN_SRC = socket_trace.c perf_profiler.c
TAEGET_KERN_LL = $(TAEGET_KERN_SRC:c=ll)
TAEGET_KERN_ELF = $(TAEGET_KERN_SRC:c=elf)
ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'                                   \
                      "$(1)"                                            \
                      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"       \
                      "$(if $(3),  CO-RE)";
endif
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

ifeq ($(LINUX_VER_3_10_0),1)
	EXTRA_EBPF_CLAGS = -DLINUX_VER_3_10_0
else ifeq ($(LINUX_VER_5_2_PLUS),1)
	EXTRA_EBPF_CLAGS = -DLINUX_VER_5_2_PLUS
else ifeq ($(LINUX_VER_KYLIN),1)
	EXTRA_EBPF_CLAGS = -DLINUX_VER_KYLIN
endif

FINAL_TARGET = -emit-llvm -D__TARGET_ARCH_$(ARCH) -o ${@:.elf=.ll} -c $^ && $(LLC) -march=bpf -filetype=obj -mcpu=v2 -o $@ ${@:.elf=.ll}

all: $(TAEGET_KERN_ELF)

EBPF_CLAGS ?= -I. -Ivmlinux -Iinclude -D__BPF_TRACING__ -D GROUP_LEADER_OFFSET_OVERRIDE=0 \
        -DSTART_BOOTTIME_OFFSET_OVERRIDE=0      \
        -DSTART_BOOTTIME_VARNAME=real_start_time

%.elf: %.c
	$(call msg,BPF,$@,$(CORE))	
	$(Q)$(CLANG) $(EBPF_CLAGS) $(EXTRA_EBPF_CLAGS) -std=gnu99 -Wimplicit-function-declaration \
		-ffreestanding -fno-builtin -Wall \
		-Wno-deprecated-declarations \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-pragma-once-outside-header \
		-Wno-address-of-packed-member \
		-Wno-unknown-warning-option \
		-fno-color-diagnostics \
		-fno-unwind-tables \
		-fno-stack-protector \
		-fno-asynchronous-unwind-tables -g -O2 $(FINAL_TARGET)
	$(Q)$(LLVM_OBJDUMP) --source --debug-vars --line-numbers --symbol-description $@ > ${@:.elf=.objdump} 
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

clean:
	@rm $(TAEGET_KERN_ELF) $(TARGET) ${TAEGET_KERN_ELF:.elf=.ll} *.S *.objdump -rf

.PHONY: all clean

