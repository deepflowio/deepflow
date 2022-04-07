#!/bin/bash

set -e
set -x

PWD=`pwd`
VERSION=`echo ${CI_COMMIT_REF_NAME//B_LC_RELEASE_} | tr '_' '.' | sed 's/master/latest/'`
RELEASE=`/usr/bin/git rev-list --count HEAD`

WORKDIR=$PWD/work
if [ -e $WORKDIR ]; then
    rm -rf $WORKDIR
fi
mkdir -p $WORKDIR

cp -r $PWD/docker/require $WORKDIR
cp -r $PWD/src/ebpf/data $WORKDIR
cp $PWD/src/ebpf/metaflow-ebpfctl $WORKDIR
cp $PWD/docker/dockerfile $WORKDIR

