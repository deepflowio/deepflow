# Compile in Linux

Here is the documentation about how to compile agent in Linux system

## Use docker

The easiest way is to use our docker image:
```bash
docker run --privileged --rm -it -v \
    $(pwd):/deepflow hub.deepflow.yunshan.net/public/rust-build bash -c \
    "source /opt/rh/devtoolset-8/enable && git clone --recursive https://github.com/deepflowio/deepflow.git /deepflow && cd /deepflow/agent && cargo build"

# binary file directory: ./deepflow/agent/target/debug/deepflow-agent
```

## Manually compilation

Agent compilation requires the following environments:
- Clang/LLVM: 11/12
- rust: 1.61+

Install basic tools:
- ubuntu, debian, kali, etc.
  ```bash
  apt-get install -y clang-11 gcc llvm-11 llvm-11-dev libpcap0.8-dev libelf-dev make
  ```
- fedora
  ```bash
  yum install llvm11 gcc  libpcap-devel glibc-static elfutils-libelf-devel make
  yum --releasever=33 install clang   # install clang11
  ```

Create soft link:
```bash
ln -s /usr/bin/clang-11 /usr/bin/clang
ln -s /usr/bin/llvm-objdump-11 /usr/bin/llvm-objdump
ln -s /usr/bin/llc-11 /usr/bin/llc
ln -s /usr/bin/llvm-strip-11 /usr/bin/llvm-strip
```

Compile static libraries:
```bash
# bcc
# reference：https://github.com/iovisor/bcc/blob/master/INSTALL.md
wget https://github.com/iovisor/bcc/releases/download/v0.25.0/bcc-src-with-submodule.tar.gz
tar -xzf bcc-src-with-submodule.tar.gz
cd bcc && cmake3 . && make && make install

# bddisasm
git clone https://github.com/bitdefender/bddisasm
cd bddisasm
make && make install && make clean
ln -s /usr/local/lib/libbddisasm.a /usr/lib/libbddisasm.a

# zlib
wget https://zlib.net/zlib-1.2.12.tar.gz
tar -xzf zlib-1.2.12.tar.gz
cd zlib-1.2.12
./configure
make && make install && make clean
ln -s /usr/local/lib/libz.a /usr/lib/libz.a

# libdwarf
wget https://github.com/davea42/libdwarf-code/releases/download/v0.4.1/libdwarf-0.4.1.tar.xz
tar -xf libdwarf-0.4.1.tar.xz
cd libdwarf-0.4.1
CFLAGS="-fpic" ./configure --disable-dependency-tracking
make && make install && make clean
ln -s /usr/local/lib/libdwarf.a /usr/lib/libdwarf.a

# libelf
# libelf.a in elfutils not include in some Linux distribution default repository.
# compile elfutils requires a lot of dependencies, please solve it according to your Linux distribution.
wget https://sourceware.org/elfutils/ftp/0.187/elfutils-0.187.tar.bz2
tar -xf elfutils-0.187.tar.bz2
cd elfutils-0.187
./configure
make && make install && make clean
ln -s /usr/local/lib/libelf.a /usr/lib/libelf.a

# libGoReSym
# Install or upgrade golang version to 1.18
wget https://github.com/deepflowio/libGoReSym/archive/refs/tags/v0.0.1-2.tar.gz
tar -xzf v0.0.1-2.tar.gz
cd libGoReSym-0.0.1-2
make && make install && make clean
```

Compile agent：
```bash
git clone --recursive https://github.com/deepflowio/deepflow.git
cd deepflow/agent
cargo build
```
