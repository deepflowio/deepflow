Name:       deepflow-agent_docker
Version:    1.0
Release:    %(git rev-list --count HEAD)%{?dist}
Summary:    deepflow agent docker

Group:      Applications/File
Vendor:     Yunshan Networks
License:    Copyright (c) 2012-2022 Yunshan Netwoks
URL:        http://yunshan.net
Source:     deepflow-agent_docker.spec

%define pwd %(echo $PWD)
%define full_version %{version}-%{release}

%description
deepflow agent docker

%prep
mkdir -p $RPM_BUILD_ROOT/temp/
cp -r %pwd/output $RPM_BUILD_ROOT/temp/
cp %pwd/config/deepflow-agent.yaml $RPM_BUILD_ROOT/temp/
cp %pwd/docker/dockerfile $RPM_BUILD_ROOT/temp/
cp %pwd/docker/deepflow-agent-cm.yaml $RPM_BUILD_ROOT/temp/
mkdir -p $RPM_BUILD_ROOT/temp/docker/
cp -r %pwd/docker/require $RPM_BUILD_ROOT/temp/docker/
(cd $RPM_BUILD_ROOT/temp/ &&
    docker build -t deepflow-agent:%full_version . --load &&
    docker save -o deepflow-agent-%full_version.tar deepflow-agent:%full_version &&
    tar zcvf deepflow-agent-%full_version.tar.gz deepflow-agent-%full_version.tar &&
    cat deepflow-agent.yaml >> deepflow-agent-cm.yaml &&
    sed -i '9,$s/^/    /g' deepflow-agent-cm.yaml
)
mkdir -p $RPM_BUILD_ROOT/tmp/deepflow-agent
cp $RPM_BUILD_ROOT/temp/deepflow-agent-%full_version.tar.gz $RPM_BUILD_ROOT/tmp/deepflow-agent
cp $RPM_BUILD_ROOT/temp/deepflow-agent-cm.yaml $RPM_BUILD_ROOT/tmp/deepflow-agent
cp %pwd/docker/deepflow-agent-ds.yaml $RPM_BUILD_ROOT/tmp/deepflow-agent
(cd $RPM_BUILD_ROOT/tmp &&
    tar zcvf deepflow-agent_%full_version.tar.gz deepflow-agent/ &&
    rm -rf deepflow-agent/ && cd $RPM_BUILD_ROOT && rm -rf temp/
)

%files
/tmp/deepflow-agent_%full_version.tar.gz

%post
tar xf /tmp/deepflow-agent_%full_version.tar.gz -C /tmp/
(cd /tmp/deepflow-agent && tar xf deepflow-agent-%full_version.tar.gz && rm -rf deepflow-agent-%full_version.tar.gz)
rm -rf /tmp/deepflow-agent_%full_version.tar.gz
