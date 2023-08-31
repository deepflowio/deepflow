#!/bin/bash

cd ${BASH_SOURCE%/*}

red_echo ()      { [ "$HASTTY" != "1" ] && echo "$@" || echo -e "\033[031;1m$@\033[0m"; }
blue_echo ()     { [ "$HASTTY" != "1" ] && echo "$@" || echo -e "\033[034;1m$@\033[0m"; }
green_echo ()    { [ "$HASTTY" != "1" ] && echo "$@" || echo -e "\033[032;1m$@\033[0m"; }

log () {
     # 打印消息, 并记录到日志, 日志文件由 LOG_FILE 变量定义
     local retval=$?
     local timestamp=$(date +%Y%m%d-%H%M%S)
     local level=INFO
     local func_seq=$(echo ${FUNCNAME[@]} | sed 's/ /-/g')
     local logfile=${LOG_FILE:=/tmp/bkc.log}

     local opt=

     if [ "${1:0:1}" == "-" ]; then
          opt=$1
          shift 1
     else
          opt=""
     fi

     echo -e $opt "$timestamp|$BASH_LINENO\t$@"
     echo -e $opt "$timestamp $level|$BASH_LINENO|${func_seq} $@\n" >>$logfile

     return $retval
}

usage () {
    echo "usage: $0 PLUGIN_NAME"
    exit 0
}

_status_windows_proc () {
    local proc="$1"
    local pids

    pids=( $(ps -efW | grep "bin/${proc}" | awk '{print $2}') )
    echo -n ${pids[@]}

    [ ${#pids[@]} -ne 0 ]
}

_status_linux_proc () {
    local proc="$1"
    local pids
    local __pids=()

    pids=$(ps xao pid,ppid,command | awk -v PROG="./$proc" '$3 == PROG { print $1 }')
    for pid in ${pids[@]} ; do
        abs_path=$(readlink -f /proc/$pid/exe)
        if [ "${abs_path%/$proc*}" == "${PWD}" ] ; then
            __pids=(${__pids} ${pid})
        fi
    done
    pids=(${__pids[@]})

    echo -n ${pids[@]}

    [ ${#pids[@]} -ne 0 ]
}

_stop () {
    kill -9 $(_status_${os_type}_proc $1) 2>/dev/null
}

_status () {
    local proc="$1"

    _status_${os_type}_proc $proc
}

case $(uname -s) in
    *Linux) os_type=linux ;;
    *CYGWIN*) os_type=windows ;;
esac

[ -z "$1" ] && usage

log -n "stop $1 ..."
_stop $1
sleep 2
if ! _status $1; then
    green_echo "Done"
else
    red_echo "Fail"
fi