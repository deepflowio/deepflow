ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
endif

CC ?= gcc
OBJDIR ?= .
STATIC_OBJDIR := $(OBJDIR)/staticobjs

define compile_socket_trace_elf
	@echo "  COMPILE ELF kernel version $(1)"
	@mkdir -p data/linux-$(strip $1)
	@cd kernel && make clean --no-print-directory && make socket_trace.elf $(2) --no-print-directory && cd ../
	@cp kernel/socket_trace.elf data/linux-$(strip $1)/
endef

CLANG_VER := $(shell /usr/bin/clang --version | grep "version" | awk '{print $$3}')
CLANG_VER_MAIN := $(shell /usr/bin/clang --version | grep "version" | awk '{print $$3}' | awk -F. '{print $$1}' | awk '{print int($$0)}')
LIBTRACE := libebpf.a
OBJS := libbpf/src/bpf.o \
	libbpf/src/btf.o \
	libbpf/src/libbpf.o \
	libbpf/src/libbpf_errno.o \
	libbpf/src/netlink.o \
	libbpf/src/nlattr.o \
	libbpf/src/str_error.o \
	libbpf/src/libbpf_probes.o \
	libbpf/src/bpf_prog_linfo.o \
	libbpf/src/xsk.o \
	libbpf/src/btf_dump.o \
	libbpf/src/hashmap.o \
	libbpf/src/ringbuf.o \
	user/bcc/bcc_elf.o \
	user/bcc/bcc_proc.o \
	user/common.o \
	user/probe.o \
	user/perf.o \
	user/symbol.o \
	user/go_tracer.o \
	user/table.o \
	user/ring.o \
	user/tracer.o \
	user/socket.o \
	user/log.o \
	user/ctrl.o \
	user/offset.o

STATIC_OBJS := $(addprefix $(STATIC_OBJDIR)/,$(OBJS))

CFLAGS ?= -std=gnu99 -g -O2 -ffunction-sections -fdata-sections -fPIC -fno-omit-frame-pointer -m64 -Wall -Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers
CFLAGS += $(MACHINE_CFLAGS) -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -Ilibbpf/src -Ilibbpf/include -Ilibbpf/include/uapi -I.
LDFLAGS ?= -lbddisasm -ldwarf -lelf -lz -lpthread

all: build

ELFFILES = ./.data_done
$(ELFFILES):
	$(call msg,Clang/LLVM,,$(CLANG_VER))
	@if [ $(CLANG_VER_MAIN) -lt 10 ]; then \
                echo "  check llvm-clang fail. expect Clang/LLVM 10+" && exit 1; \
        fi
	@rm -rf data
	$(call compile_socket_trace_elf, common)
	$(call compile_socket_trace_elf, 5.2, LINUX_VER_5_2=1)
	$(call compile_socket_trace_elf, core, CORE=1)
	@touch $(ELFFILES)

$(STATIC_OBJDIR) $(SHARED_OBJDIR):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@/libbpf/src
	$(Q)mkdir -p $@/user/bcc

$(STATIC_OBJDIR)/%.o: %.c | $(STATIC_OBJDIR)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

$(LIBTRACE): $(STATIC_OBJS)
	$(call msg,AR,$@)
	$(Q)$(AR) rcs $@ $^
	
build: $(ELFFILES) $(LIBTRACE)

install:
	rm -rf /usr/share/metaflow-agent
	mkdir -p /usr/share/metaflow-agent
	cp data/* /usr/share/metaflow-agent/ -raf

tools:
	$(call msg,TOOLS,metaflow-ebpfctl)
	$(Q)gcc user/ctrl_tracer.c user/ctrl.c user/log.c -o metaflow-ebpfctl

rust-sample:
	$(call msg,Current-DIR,,$(CURR))
	$(Q)rm -rf samples/rust/src/ebpf.rs
	$(Q)cp mod.rs samples/rust/src/ebpf.rs
	$(Q)rm -rf samples/rust/target
	$(Q)cd samples/rust/ && cargo build --release && cd ../../
	$(call msg,RUST-SAMPLE,,samples/rust/target/release/rust_sample)

clean:
	$(Q)make -C kernel clean --no-print-directory
	$(Q)make -C test clean --no-print-directory
	$(Q)rm -rf $(ELFFILES) data metaflow-ebpfctl $(STATIC_OBJDIR) $(LIBTRACE) *.a
	$(Q)rm -rf samples/rust/target
test:
	$(Q)make -C test --no-print-directory

.PHONY: all build clean install tools test

