CLANG = clang
CFLAGS = -Iinclude

all: xdpsock_kern.o

xdpsock_kern.o: xdpsock_kern.c
	@$(CLANG) -O2 -Wall -target bpf -c $^ -o $@

clean:
	@rm -rf *.o

.PHONY: all clean
