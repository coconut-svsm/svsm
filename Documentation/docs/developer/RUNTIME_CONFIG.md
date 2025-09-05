# SVSM runtime configuration

Some SVSM parameters can be configured from the host using the QEMU command
line option `-fw_cfg`

## Attestation: opt/org.svsm/VsockAttestPort

By default, vsock uses port 1995 for attestation. This option enables the use
of a different port.

`scripts/launch_guest.sh [..] -- -fw_cfg name=opt/org.svsm/VsockAttestPort,string=1234`