#!/bin/bash

(
    if [ $(id -u) -ge 1000 ]; then
        # real user session
        PORT=23826
        XAUTH_GUESS=$(ps uxe | grep -v grep | egrep -o 'XAUTHORITY=\S+' | head -1 | awk -F= '{print $2}')
        XAUTHORITY=${XAUTHORITY:-${XAUTH_GUESS}}
        while [ 1 ]; do
            $SNAP/usr/bin/x11vnc -loop -forever -bg -rfbport "${PORT}" -xkb -noxrecord -noxfixes -noxdamage -shared -norc -localhost -auth "${XAUTHORITY}"
        done
    else
        # login screen session
        PORT=23824
        XAUTHORITY=""
        while [ -z "${XAUTHORITY}" ]; do
            sleep 1
            XAUTHORITY=$(ps axeo euid,comm,args | awk '{ if ($1< 1000) {print $0} }' | egrep -o 'XAUTHORITY=\S+' | head -1 | awk -F= '{print $2}')
        done    
        while [ 1 ]; do
            $SNAP/usr/bin/x11vnc -env FD_XDM=1 -loop -forever -bg -rfbport "${PORT}" -xkb -noxrecord -noxfixes -noxdamage -shared -norc -display :0 -localhost -auth "${XAUTHORITY}"
        done
    fi
) 2>&1 | logger -t logmein-rc 
