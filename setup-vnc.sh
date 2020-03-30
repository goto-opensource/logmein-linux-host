#!/bin/bash

usage() {
    if [ "$*" ]; then
        echo "$*"
        echo
    fi
    echo "Usage: ${NAME} [--install | --uninstall] [--use-default-vnc-port]"
    echo
    echo "Setting up the LogMeIn VNC module."
    echo
    echo "    --install               Installs the necessary services and"
    echo "                            configures the parameters"
    echo "    --uninstall             Removes the services and all the"
    echo "                            configuration"
    echo "    --use-default-vnc-port  Use VNC server running at"
    echo "                            localhost:5900"
    echo
    exit 2
}

NAME="$(basename $0)"
INSTALL=""
UNINSTALL=""
USE_DEFAULT_VNC_PORT=""

while [ "$*" ]; do
    param=$1; shift; OPTARG=$1
    case $param in
    --install) INSTALL="1"                              ;;
    --uninstall) UNINSTALL="1"                          ;;
    --use-default-vnc-port) USE_DEFAULT_VNC_PORT="yes"  ;;
    -h|--help) usage                                    ;;
    -*) usage "Unknown option: ${param}"                ;;
    *) usage "Unknown parameter: ${param}"                 ;;
    esac
done


uninstall() {
    sudo systemctl stop vnc-starter.service
    sudo systemctl disable vnc-starter.service

    sudo rm -f /lib/systemd/system/vnc-starter.service
    sudo rm -f /etc/xdg/autostart/logmein-vnc.desktop
    sudo rm -f /usr/share/gdm/autostart/LoginWindow/logmein-vnc.desktop
}


if [ "${INSTALL}" == "1" ]; then
    snap list logmein-host &>/dev/null
    if [ "$?" != "0" ]; then
        echo "You must install \"logmein-host\" first!"
        exit 1
    fi

    if [ "$(sudo snap get logmein-host deploy-code)" != "SAVED" ]; then
        echo "You must register with a valid deployment code!"
        exit 1
    fi

    # TODO: maybe check for `systemctl status display-manager.service` ???

    if [ "${USE_DEFAULT_VNC_PORT}" != "yes" ]; then
        if bash -c "exec 7<>/dev/tcp/localhost/5900" &> /dev/null; then
            exec 7<&-
            exec 7>&-

            while [ "${USE_DEFAULT_VNC_PORT}" != "yes" ] && [ "${USE_DEFAULT_VNC_PORT}" != "no" ]; do 
                echo -n "It seems you have a VNC server running on localhost:5900. Would you like to use that? [yes/no] "
                read USE_DEFAULT_VNC_PORT
            done
        else
            exec 7<&-
            exec 7>&-
        fi
    fi

    uninstall &>/dev/null

    if [ "${USE_DEFAULT_VNC_PORT}" == "yes" ]; then
        sudo snap set logmein-host use-default-vnc-port=yes
    else
        sudo snap set logmein-host use-default-vnc-port=no

        sudo cp /snap/logmein-host/current/scripts/vnc-starter.service /lib/systemd/system/vnc-starter.service
        sudo cp /snap/logmein-host/current/scripts/logmein-vnc.desktop /etc/xdg/autostart/logmein-vnc.desktop
        sudo cp /snap/logmein-host/current/scripts/logmein-vnc.desktop /usr/share/gdm/autostart/LoginWindow/logmein-vnc.desktop

        sudo systemctl enable vnc-starter.service
        sudo systemctl start vnc-starter.service
    fi

    sudo snap set logmein-host enable-vnc=yes
elif [ "$UNINSTALL" == "1" ]; then
    uninstall

    snap list logmein-host &>/dev/null
    if [ "$?" == "0" ]; then
        sudo snap set logmein-host enable-vnc=no
        sudo snap set logmein-host use-default-vnc-port=no
    fi
else
    usage
fi
