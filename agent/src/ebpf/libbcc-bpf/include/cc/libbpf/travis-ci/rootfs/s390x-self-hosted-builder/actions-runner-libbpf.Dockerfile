# Self-Hosted IBM Z Github Actions Runner.

# Temporary image: amd64 dependencies.
FROM amd64/ubuntu:20.04 as ld-prefix
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get -y install ca-certificates libicu66 libssl1.1

# Main image.
FROM s390x/ubuntu:20.04

# Packages for libbpf testing that are not installed by .github/actions/setup.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get -y install \
        bc \
        bison \
        cmake \
        cpu-checker \
        curl \
        flex \
        git \
        jq \
        linux-image-generic \
        qemu-system-s390x \
        rsync \
        software-properties-common \
        sudo \
        tree

# amd64 dependencies.
COPY --from=ld-prefix / /usr/x86_64-linux-gnu/
RUN ln -fs ../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /usr/x86_64-linux-gnu/lib64/
RUN ln -fs /etc/resolv.conf /usr/x86_64-linux-gnu/etc/
ENV QEMU_LD_PREFIX=/usr/x86_64-linux-gnu

# amd64 Github Actions Runner.
ARG version=2.285.0
RUN useradd -m actions-runner
RUN echo "actions-runner ALL=(ALL) NOPASSWD: ALL" >>/etc/sudoers
RUN echo "Defaults env_keep += \"DEBIAN_FRONTEND\"" >>/etc/sudoers
RUN usermod -a -G kvm actions-runner
USER actions-runner
ENV USER=actions-runner
WORKDIR /home/actions-runner
RUN curl -L https://github.com/actions/runner/releases/download/v${version}/actions-runner-linux-x64-${version}.tar.gz | tar -xz
VOLUME /home/actions-runner

# Scripts.
COPY fs/ /
ENTRYPOINT ["/usr/bin/entrypoint"]
CMD ["/usr/bin/actions-runner"]
