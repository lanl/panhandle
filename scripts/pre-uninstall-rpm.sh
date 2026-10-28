#!/bin/bash
service_name="panhandle"
if systemctl is-active --quiet "$service_name"; then
    echo "panhandle RPM removal requested, stopping the panhandle service"
    systemctl stop "$service_name"
fi
systemctl disable "$service_name" 2>/dev/null || true
