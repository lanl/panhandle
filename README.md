# panhandle

## Description

A project to provide user activity monitoring for High Performance Computing systems and clusters. The goal is to provide effective user activity monitoring with minimal performance impact on the host running this service.

## Tools

This project uses [eBPF]( https://ebpf.io/) to monitor events on a Linux host, format and output those events as desired by the user. The output includes options for http, syslog and file output as well as standard console output. All outputs support text and JSON formatting.

This project is written in [Rust](https://www.rust-lang.org/) and uses the [Aya](https://aya-rs.dev/) library to reduce dependencies and maximize the ability of this program to run on a variety of systems.

## Components

The RPMs in the build artifacts provide:

1. The panhandle binary `/usr/sbin/panhandle`
2. The configuration file: `/opt/panhandle/panhandle.yaml`
3. The default systemd service to run panhandle: `/usr/lib/systemd/system/panhandle.service`
4. The man page at `/usr/share/man/man1/panhandle.1`
5. Logrotate configuration file: `/etc/logrotate.d/panhandle`

## Configuration & Implementation

1. Install the appropriate RPM for your Linux version.
2. If log monitoring by a SEIM or Splunk server is desired, please add the logfile `/var/log/panhandle/panhandle.log` to your monitored rsyslog file inputs.
3. Enable and start the panhandle systemd service with: `systemctl enable --now panhandle` or your configuration manager of choice.

## Releasability

`O5058 panhandle has been acknowledged by the NNSA for open-source release.`
