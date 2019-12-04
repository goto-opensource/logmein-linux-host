#!/bin/sh

sudo cp /snap/logmein-host/current/scripts/vnc-starter.service /lib/systemd/system/vnc-starter.service
sudo cp /snap/logmein-host/current/scripts/logmein-vnc.desktop /etc/xdg/autostart/logmein-vnc.desktop
sudo cp /snap/logmein-host/current/scripts/logmein-vnc.desktop /usr/share/gdm/autostart/LoginWindow/logmein-vnc.desktop
sudo systemctl enable vnc-starter.service
sudo systemctl start vnc-starter.service
