# Debugging

The SVSM can be built to incorporate a GDB stub that can be used to provide full
source-level debugging of the SVSM kernel code. To enable the GDB stub pass
```FEATURES=enable-gdb``` to the ```make``` command line:

```shell
FW_FILE=/path/to/firmware/OVMF.fd make FEATURES=enable-gdb
```

The GDB stub remains dormant until a CPU exception occurs, either through a
kernel panic or via a debug breakpoint, at which time the GDB stub will await a
serial port connection and display this message in the console:

```plain
[SVSM] ***********************************
[SVSM] * Waiting for connection from GDB *
[SVSM] ***********************************
```

The GDB stub uses a hardware serial port at IO port 0x2f8, which is the second
simulated serial port in the QEMU configuration. Using the example configuration
above, the serial port is configured using `-serial pty`.

QEMU will create a virtual serial port on the host at `/dev/pts/[n]` where `[n]`
is the device index. This index will be reported by QEMU in the console when the
virtual machine is started. You can then connect GDB to the waiting SVSM using
the command, replacing `[n]` with the correct device index:

```shell
sudo gdb --ex "target extended-remote /dev/pts/[n]`
```

If you have the source code available on the host system then you can add the
debug symbols and use source-level debugging:

```plain
(gdb) symbol-file target/x86_64-unknown-none/debug/svsm
```

Note that some GDB features are not available for debugging the SVSM kernel due
to limited debug capabilities inside an AMD SEV-SNP confidential container. Some
of these limitations may be addressed in future updates.

* Hardware breakpoints and watchpoints are not yet supported.
* Interrupting a running kernel with Ctrl-C is not possible. You must insert a
  forced breakpoint in the code to enter the debugger before stepping through
  target code.
* Debugging is currently limited to the SVSM kernel itself. OVMF and the guest
  OS cannot be debugged using the SVSM GDB stub.
