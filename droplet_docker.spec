Name:       droplet_docker
Version:    1.1
Release:    %(git rev-list --count HEAD)%{?dist}
Summary:    deepflow droplet docker

Group:      Applications/File
Vendor:     Yunshan Networks
License:    Copyright (c) 2012-2016 Yunshan Netwoks
URL:        http://yunshan.net
Source:     droplet_docker.spec

%define pwd %(echo $PWD)
%define full_version %{version}-%{release}

%description
deepflow droplet docker

%prep
(cd %pwd; make)
mkdir -p $RPM_BUILD_ROOT/temp/
cp %pwd/bin/droplet $RPM_BUILD_ROOT/temp/
cp %pwd/config/droplet.yaml $RPM_BUILD_ROOT/temp/
cp %pwd/droplet_docker/dockerfile $RPM_BUILD_ROOT/temp/
cp %pwd/droplet_docker/droplet-cm.yaml $RPM_BUILD_ROOT/temp/
cp -r %pwd/droplet_docker/require $RPM_BUILD_ROOT/temp/
(cd $RPM_BUILD_ROOT/temp/ &&
    docker build -t deepflow-droplet:%full_version . &&
    docker save -o deepflow-droplet-%full_version.tar deepflow-droplet:%full_version &&
    tar zcvf droplet-%full_version.tar.gz deepflow-droplet-%full_version.tar &&
    cat droplet.yaml >> droplet-cm.yaml &&
    sed -i '10,$s/^/    /g' droplet-cm.yaml
)
mkdir -p $RPM_BUILD_ROOT/tmp/droplet
cp $RPM_BUILD_ROOT/temp/droplet-%full_version.tar.gz $RPM_BUILD_ROOT/tmp/droplet
cp $RPM_BUILD_ROOT/temp/droplet-cm.yaml $RPM_BUILD_ROOT/tmp/droplet
cp %pwd/droplet_docker/droplet-ds.yaml $RPM_BUILD_ROOT/tmp/droplet
(cd $RPM_BUILD_ROOT/tmp &&
    tar zcvf droplet_%full_version.tar.gz droplet/ &&
    rm -rf droplet/ && cd $RPM_BUILD_ROOT && rm -rf temp/
)


%files
/tmp/droplet_%full_version.tar.gz

%post
tar xf /tmp/droplet_%full_version.tar.gz -C /tmp/
(cd /tmp/droplet && tar xf droplet-%full_version.tar.gz && rm -rf droplet-%full_version.tar.gz)
rm -rf /tmp/droplet_%full_version.tar.gz
