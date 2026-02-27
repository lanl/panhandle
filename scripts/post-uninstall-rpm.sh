#!/bin/bash
service_name="panhandle"
if systemctl is-active --quiet "$service_name"; then
    echo "panhandle RPM removal requested, stopping the panhandle service"
    systemctl stop panhandle
    rm -f /usr/lib/systemd/system/panhandle.service
    systemctl daemon-reload
    rm -f /usr/sbin/panhandle
    rm -f /usr/share/man/man1/panhandle.1
else
    rm -f /usr/sbin/panhandle
    rm -f /usr/lib/systemd/system/panhandle.service
    rm -f /usr/share/man/man1/panhandle.1
fi