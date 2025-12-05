Persistence
===========

The persistence subsystem enables the SVSM to securely preserve sensitive state
across reboots, such as, but not limited to, the vTPM NV state or UEFI
variables.


Overview
--------
When persisting sensitive state to external, non-volatile storage from a TEE or
the SVSM in particular, special security considerations apply: the untrusted
virtualization host not only has full access to the external storage volume's
contents, but is even capable of spoofing and altering IO requests over time,
potentially enabling certain attacks on traditional block-level FDE schemes.

The
[CocoonFs](https://coconut-svsm.github.io/cocoon-tpm/cocoonfs/cocoonfs-format.html)
filesystem format has been designed specifically with a TEE's security
requirements in mind, and is currently the only filesystem supported by the
SVSM. Support for other formats might perhaps get added in the future if
there's a demand.

The persistence storage is protected by a symmetric key received at startup from
a KBS as the result of a successful remote attestation, therefore the
persistence functionality requires a working [attestation
setup](ATTESTATION.md).

There are two alternative ways to initially provision a CocoonFs filesystem
image with the [`cocoonfs-cli`](https://crates.io/crates/cocoonfs-cli) utility:
without or with access to the key. If created without a key, a mere "filesystem
creation header" would get written, the actual formatting would then
subsequently take place on the first attempt to open the image from the SVSM,
with the key obtained from attestation procedure. If created with a key, the
filesystem will get formatted right away at `cocoonfs-cli` invocation time.

At startup, the SVSM would iterate over all block devices attach to it and use
the first one that can be opened successfully with the key provided from
attestation for all its persistence needs. In particular:

* At most one CocoonFs volume will actively be used from a given SVSM boot instance.
* If a block device has a CocoonFs image formatted onto it, but its
  authentication with the key obtained from attestation failed, it would get
  skipped.
* If no working CocoonFs image had been found yet, and the next block device has
  a "CocoonFs creation header" on it, the filesystem would get formatted with
  whatever key had been obtained from attestion and henceforth be used for the
  persistence needs, irrespective of whether there's perhaps another CocoonFs
  block device formatted with that same key later in the iteration list or not.

Current development state and caveats
-------------------------------------
The persistence functionality is under development, the core subsystem itself
has been implemented, but none of the components which could potentially make
use of it have been adapted yet to actually do so.

Furthermore, the exact details on how the symmetric key material used for
securing the externally stored data is to get derived from the secret received
from the KBS have not been finalized yet, so do not expect at this point that
persistence volume images accessible from the SVSM at some code version will
continue to work with past or future releases.

Currently, the secret key material received from the KBS is not authenticated in
any way, making the persistence subsystem prone to MITM attacks. The details on
how to resolve this have not been settled yet, for reference and further details
c.f. [this mail thread](https://lore.kernel.org/r/877bwxyiqv.fsf@).

Setup/Testing
-------------
1. Enable the cocoonfs Cargo feature. This will pull in the virtio-drivers feature.
2. Setup attestation -- it's currently the only way to get a secret into the SVSM.
3. Prepare a CocoonFs filesystem image using [`cocoonfs-cli`](https://crates.io/crates/cocoonfs-cli)
   ```
   cocoonfs -i cocoonfs.img -f write-mkfs-info-header -H sha2 -C aes -t 128 -I 'ddeeff' -s 8M
   ```
   Note that this merely writes a CocoonFs "filesystem creation info header",
   which doesn't require access to the key. The actual filesystem formatting
   will get done when the SVSM first attempts to open the filesystem.
4. Attach the filesystem image to the SVSM via the qemu command line (taken from
   `scripts/launch_guest.sh`): append `,x-svsm-virtio-mmio=on` to the `-machine`
   spec and add
   ```
   -global virtio-mmio.force-legacy=false
   -drive file=<path>/cocoonfs.img,format=raw,if=none,id=svsm_storage,cache=none
   -device virtio-blk-device,drive=svsm_storage
   ```

If everything goes well, you should see the following message at the first boot:
```
[SVSM] persistent CocoonFs storage opened successfully
[SVSM] persistence demo: no boot counter found yet
[SVSM] persistence demo: successfully wrote updated boot counter
```
and e.g.
```
[SVSM] persistent CocoonFs storage opened successfully
[SVSM] persistence demo: boot counter read back is 1
[SVSM] persistence demo: successfully wrote updated boot counter
```
etc. in subsequent ones.
