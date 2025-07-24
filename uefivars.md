
## SVSM UEFI MM PROTOCOL

Process MM communication requests from edk2 firmware.

Usually this request serialization format is used by edk2 for
communication between normal mode and management mode (MM for short).

This SVSM protocol is a thin wrapper to allow edk2 firmware send those
requests to the SVSM instead.  This allows the SVSM to provide services
which are usually running in SMM mode on bare metal or
non-confidential VMs, specifically an UEFI variable store.

### protocol number

```
pub const SVSM_UEFI_MM_PROTOCOL: u32 = 4;
```
preliminary, not yet officially assigned

### protocol request

```
const SVSM_UEFI_MM_REQUEST: u32 = 1;
```
Parameters:
 * RCX: buffer address (guest physical).  Must be page aligned.
 * RDX: buffer size

Request SVSM to process the communication buffer as a UEFI request.
The response format is request-specific.

### request format

The request serialization format is specified by edk2, the short
overview below is purely informational.

The buffer starts with this header:

```
// EFI_MM_COMMUNICATE_HEADER
#[repr(C, packed)]
pub struct MmCoreHeader {
    pub guid: [u8; 16],
    pub size: u64,
}
```

The `guid` specifies the receiver of the message (typically an efi
protocol guid or an efi event guid), and therefore also the format of
the request data following this header.  The `size` field specified
the size of the request data (excluding the header).

### uefi spec references

 * UEFI Platform Initialization Specification, section IV-5.7 "MM
   Communication Protocol" describes the EFI_MM_COMMUNICATE_HEADER
   struct.

### edk2 code references

 * MdePkg/Include/Protocol/MmCommunication.h
 * MdeModulePkg/Include/Guid/SmmVariableCommon.h
 * MdeModulePkg/Include/Guid/VarCheckPolicyMmi.h

### linux references

The linux kernel has an efi variable driver implementation using this
request format in `drivers/firmware/efi/stmm`.  It sends those
requests to the edk2 MM code running in arm secure partition.
