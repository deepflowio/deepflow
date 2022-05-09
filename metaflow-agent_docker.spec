Name:       metaflow-agent_docker
Version:    1.0
Release:    %(git rev-list --count HEAD)%{?dist}
Summary:    deepflow metaflow-agent docker

Group:      Applications/File
Vendor:     Yunshan Networks
License:    Copyright (c) 2012-2022 Yunshan Netwoks
URL:        http://yunshan.net
Source:     metaflow-agent_docker.spec

%define pwd %(echo $PWD)
%define full_version %{version}-%{release}

%description
deepflow metaflow-agent docker

%prep
mkdir -p $RPM_BUILD_ROOT/temp/
cp %pwd/target/release/metaflow-agent $RPM_BUILD_ROOT/temp/
cp %pwd/target/release/metaflow-agent-ctl $RPM_BUILD_ROOT/temp/
cp %pwd/src/ebpf/metaflow-ebpfctl $RPM_BUILD_ROOT/temp/
cp -r %pwd/src/ebpf/data $RPM_BUILD_ROOT/temp/
cp %pwd/config/metaflow-agent.yaml $RPM_BUILD_ROOT/temp/
cp %pwd/docker/dockerfile $RPM_BUILD_ROOT/temp/
cp %pwd/docker/metaflow-agent-cm.yaml $RPM_BUILD_ROOT/temp/
cp -r %pwd/docker/require $RPM_BUILD_ROOT/temp/
(cd $RPM_BUILD_ROOT/temp/ &&
    docker build -t metaflow-agent:%full_version . &&
    docker save -o metaflow-agent-%full_version.tar metaflow-agent:%full_version &&
    tar zcvf metaflow-agent-%full_version.tar.gz metaflow-agent-%full_version.tar &&
    cat metaflow-agent.yaml >> metaflow-agent-cm.yaml &&
    sed -i '9,$s/^/    /g' metaflow-agent-cm.yaml
)
mkdir -p $RPM_BUILD_ROOT/tmp/metaflow-agent
cp $RPM_BUILD_ROOT/temp/metaflow-agent-%full_version.tar.gz $RPM_BUILD_ROOT/tmp/metaflow-agent
cp $RPM_BUILD_ROOT/temp/metaflow-agent-cm.yaml $RPM_BUILD_ROOT/tmp/metaflow-agent
cp %pwd/docker/metaflow-agent-ds.yaml $RPM_BUILD_ROOT/tmp/metaflow-agent
(cd $RPM_BUILD_ROOT/tmp &&
    tar zcvf metaflow-agent_%full_version.tar.gz metaflow-agent/ &&
    rm -rf metaflow-agent/ && cd $RPM_BUILD_ROOT && rm -rf temp/
)

%files
/tmp/metaflow-agent_%full_version.tar.gz

%post
tar xf /tmp/metaflow-agent_%full_version.tar.gz -C /tmp/
(cd /tmp/metaflow-agent && tar xf metaflow-agent-%full_version.tar.gz && rm -rf metaflow-agent-%full_version.tar.gz)
rm -rf /tmp/metaflow-agent_%full_version.tar.gz
