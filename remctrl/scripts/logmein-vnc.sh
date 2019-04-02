#!/bin/bash

env

while [ 1 ]; do 
    x11vnc -env UNIXPW_DISABLE_SSL=1 -loop -forever -bg -rfbport 23824 -xkb -noxrecord -noxfixes -noxdamage -shared -norc -unixpw -localhost -auth $XAUTHORITY
done
