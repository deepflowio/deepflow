#!/bin/bash

cd ${BASH_SOURCE%/*} 2>/dev/null
./stop.sh $@ >/dev/null && ./start.sh $@ >/dev/null