#!/bin/bash

if [ "$1" == "" ] || [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    echo "Installing or uninstalling the LogMeIn VNC module."
    echo ""
    echo "Usage: $0 --install | --uninstall"
    exit 0
fi

if [ "$1" == "--install" ]; then
    snap list logmein-host &>/dev/null
    if [ "$?" != "0" ]; then
        echo "You must install \"logmein-host\" first!"
        exit 1
    fi

    sudo cp /snap/logmein-host/current/scripts/vnc-starter.service /lib/systemd/system/vnc-starter.service
    sudo cp /snap/logmein-host/current/scripts/logmein-vnc.desktop /etc/xdg/autostart/logmein-vnc.desktop
    sudo cp /snap/logmein-host/current/scripts/logmein-vnc.desktop /usr/share/gdm/autostart/LoginWindow/logmein-vnc.desktop

    sudo systemctl enable vnc-starter.service
    sudo systemctl start vnc-starter.service

    sudo snap set logmein-host enable-vnc=yes

elif [ "$1" == "--uninstall" ]; then
    sudo systemctl stop vnc-starter.service
    sudo systemctl disable vnc-starter.service

    sudo rm -f /lib/systemd/system/vnc-starter.service
    sudo rm -f /etc/xdg/autostart/logmein-vnc.desktop
    sudo rm -f /usr/share/gdm/autostart/LoginWindow/logmein-vnc.desktop

    snap list logmein-host &>/dev/null
    if [ "$?" == "0" ]; then
        sudo snap set logmein-host enable-vnc=no
    fi
fi
