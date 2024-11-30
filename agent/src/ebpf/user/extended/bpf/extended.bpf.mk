# Copyright (c) 2024 Yunshan Networks
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
BUILD_DIR        ?= $(PWD)/user/extended/bpf
TAEGET_KERN_SRC = cpu_balancer.bpf.c 
BPF_BYTECODE_C = cpu_balancer_bpf_bytecode.c
BYTECODE_NAME_C = cpu_balancer_ebpf_data
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

FINAL_TARGET = -emit-llvm -D__TARGET_ARCH_$(ARCH) -o ${TAEGET_KERN_ELF:.elf=.ll} -c $(TAEGET_KERN_SRC) && $(LLC) -march=bpf -filetype=obj -mcpu=v2 -o $(TAEGET_KERN_ELF) ${TAEGET_KERN_ELF:.elf=.ll}

all: $(BPF_BYTECODE_C)

$(BPF_BYTECODE_C): $(TAEGET_KERN_SRC)
	@echo "  Generate file $(BUILD_DIR)/$@"
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
	$(Q)$(LLVM_OBJDUMP) --source --debug-vars --line-numbers --symbol-description $(TAEGET_KERN_ELF) > ${TAEGET_KERN_ELF:.elf=.objdump} 
	$(Q)$(LLVM_STRIP) -g $(TAEGET_KERN_ELF) # strip useless DWARF info
	@../../../tools/bintobuffer $(TAEGET_KERN_ELF) $@ $(BYTECODE_NAME_C)

EBPF_CLAGS ?= -I. -Ivmlinux -Iinclude -I../../../kernel/include

clean:
	@rm $(TAEGET_KERN_ELF) ${TAEGET_KERN_ELF:.elf=.ll} *.S *.objdump $(BPF_BYTECODE_C) -rf

.PHONY: all clean
