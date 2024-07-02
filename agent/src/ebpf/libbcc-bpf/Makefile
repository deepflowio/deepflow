ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
endif

ARCH := $(shell uname -m)

#CXX := /work/aarch64-linux-musl-native/bin/aarch64-linux-musl-c++
#CC :=  /work/aarch64-linux-musl-native/bin/aarch64-linux-musl-gcc
#AR := /work/aarch64-linux-musl-native/bin/ar

#CXX := c++
#CC := gcc
#AR := ar

BCCDIR_SRC ?= ./include
OBJDIR ?= .
STATIC_OBJDIR := $(OBJDIR)/bcc-static.dir

OBJS :=
OBJS_C := libbpf.c.o \
          perf_reader.c.o libbpf/bpf.c.o \
          libbpf/bpf_prog_linfo.c.o \
          libbpf/btf.c.o \
          libbpf/btf_dump.c.o \
          libbpf/gen_loader.c.o \
          libbpf/hashmap.c.o \
          libbpf/libbpf.c.o \
          libbpf/libbpf_errno.c.o \
          libbpf/libbpf_probes.c.o \
          libbpf/linker.c.o \
          libbpf/netlink.c.o \
          libbpf/nlattr.c.o \
          libbpf/relo_core.c.o \
          libbpf/ringbuf.c.o \
          libbpf/str_error.c.o \
          libbpf/strset.c.o \
          libbpf/usdt.c.o bcc_elf.c.o bcc_perf_map.c.o bcc_proc.c.o

STATIC_OBJS := $(addprefix $(STATIC_OBJDIR)/,$(OBJS))
STATIC_OBJS_C := $(addprefix $(STATIC_OBJDIR)/,$(OBJS_C))

build: $(STATIC_OBJS) $(STATIC_OBJS_C)
	@if [[ $(ARCH) == *"aarch64"* ]]; then \
            $(AR) qc ../libbcc_bpf.a $(STATIC_OBJS) $(STATIC_OBJS_C); \
        fi

$(STATIC_OBJDIR) $(STATIC_OBJDIR_C):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@/libbpf

CFLAGS_CXX ?= -I$(BCCDIR_SRC) \
	-I$(BCCDIR_SRC)/cc \
	-I$(BCCDIR_SRC)/cc/frontends/b \
	-I$(BCCDIR_SRC)/cc/frontends/clang \
	-I$(BCCDIR_SRC)/cc/libbpf/include \
	-I$(BCCDIR_SRC)/cc/libbpf/include/uapi \
	-I/usr/aarch64-linux-musl/include \
	-Wall -fno-rtti -fPIC -DBCC_PROG_TAG_DIR='"/var/tmp/bcc"' -Wno-unused-result -DLLVM_MAJOR_VERSION=11 \
	-g -O2 -DNDEBUG   -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS \
	-std=gnu++1y 

CFLAGS ?= -I. -I../zlib \
	-I$(BCCDIR_SRC) \
	-I$(BCCDIR_SRC)/cc \
	-I$(BCCDIR_SRC)/cc/libbpf/src \
	-I$(BCCDIR_SRC)/cc/frontends/b \
	-I$(BCCDIR_SRC)/cc/frontends/clang \
	-I$(BCCDIR_SRC)/cc/libbpf/include \
	-I$(BCCDIR_SRC)/cc/libbpf/include/uapi \
	-I/usr/aarch64-linux-musl/include \
	-g -Wall -Werror=pointer-to-int-cast -fPIC -Wno-unused-result -DCOMPAT_NEED_REALLOCARRAY -O2 -DNDEBUG \
	-D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS
	

$(STATIC_OBJDIR)/%.c.o: %.c | $(STATIC_OBJDIR)
	$(call msg,CC,$@)
	$(CC) $(CFLAGS) -c $< -o $@

$(STATIC_OBJDIR)/%.o: % | $(STATIC_OBJDIR)
	$(call msg,CXX,$@)
	$(CXX) $(CFLAGS_CXX) -c $< -o $@

clean:
	@rm -rf $(STATIC_OBJS) $(STATIC_OBJS_C) $(STATIC_OBJDIR) ../libbcc_bpf.a

.PHONY: clean
