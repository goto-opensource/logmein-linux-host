#!/bin/bash

UUSER=${USER:-$(whoami)}
(
    while [ 1 ]; do
        if [ $(id -u) -ge 1000 ]; then
            # real user session
            UUID=${UID:-$(id -u)}
            XAUTHORITY=${XAUTHORITY:-/run/user/${UUID}/gdm/Xauthority}
            PORT=23826
            #x11vnc -env UNIXPW_DISABLE_SSL=1 -loop -forever -bg -rfbport "${PORT}" -xkb -noxrecord -noxfixes -noxdamage -shared -norc -unixpw -unixpw_cmd "/snap/logmein-host/current/scripts/unixpw_cmd.sh" -localhost -auth "${XAUTHORITY}"
            x11vnc -env UNIXPW_DISABLE_SSL=1 -loop -forever -bg -rfbport "${PORT}" -xkb -noxrecord -noxfixes -noxdamage -shared -norc -unixpw -localhost -auth "${XAUTHORITY}"
        else
            # login screen session
            UUID=$(id -u gdm)
            XAUTHORITY=${XAUTHORITY:-/run/user/${UUID}/gdm/Xauthority}
            PORT=23824
            x11vnc -env FD_XDM=1 -env UNIXPW_DISABLE_SSL=1 -loop -forever -bg -rfbport "${PORT}" -xkb -noxrecord -noxfixes -noxdamage -shared -norc -display :0 -auth "${XAUTHORITY}"
        fi
    done
) &>>/tmp/logmein.${UUSER}.log
