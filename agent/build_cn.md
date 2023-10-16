# Linux 下编译

这里是通用的 Linux 系统编译文档

## 使用 docker 编译

最简单的方法是使用我们构建好的编译环境：
```bash
git clone --recursive https://github.com/deepflowio/deepflow.git 
cd deepflow 
docker run --privileged --rm -it -v \
    $(pwd):/deepflow -v ~/.cargo:/usr/local/cargo hub.deepflow.yunshan.net/public/rust-build bash -c \
    "cd /deepflow/agent && cargo build"

# binary file directory: ./agent/target/debug/deepflow-agent
```

## 手动编译

agent 编译需要准备以下环境:
- Clang/LLVM 11 或 Clang/LLVM 12
- rust       1.61以上

安装基本工具：
- ubuntu、debian、kali 等使用 apt 安装:
  ```bash
  apt-get install -y clang-11 gcc llvm-11 llvm-11-dev libpcap0.8-dev libelf-dev make
  ```
- fedora:
  ```bash
  yum install llvm11 gcc  libpcap-devel glibc-static elfutils-libelf-devel make
  yum --releasever=33 install clang   # install clang11
  ```

添加软链接：
```bash
ln -s /usr/bin/clang-11 /usr/bin/clang
ln -s /usr/bin/llvm-objdump-11 /usr/bin/llvm-objdump
ln -s /usr/bin/llc-11 /usr/bin/llc
ln -s /usr/bin/llvm-strip-11 /usr/bin/llvm-strip
```

编译依赖的静态库：
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
ln -s /usr/local/lib/libbddisasm.a /usr/lib/libbddisasm.a # 建立软链接, agent 静态库目录是 /usr/lib/ 和 /usr/lib64

# zlib
wget https://www.zlib.net/fossils/zlib-1.2.12.tar.gz
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
# 个别系统的 elfutils 库没有 libelf.a，编译 elfutils 需要大量依赖，请根据不同平台自行处理
wget https://sourceware.org/elfutils/ftp/0.187/elfutils-0.187.tar.bz2
tar -xf elfutils-0.187.tar.bz2
cd elfutils-0.187
./configure
make && make install && make clean
ln -s /usr/local/lib/libelf.a /usr/lib/libelf.a

# libGoReSym
# 安装/升级golang版本到go1.18
wget https://github.com/deepflowio/libGoReSym/archive/refs/tags/v0.0.1-2.tar.gz
tar -xzf v0.0.1-2.tar.gz
cd libGoReSym-0.0.1-2
make && make install && make clean
```

编译 agent：
```bash
git clone --recursive https://github.com/deepflowio/deepflow.git
cd deepflow/agent
cargo build
```
