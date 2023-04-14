use crate::fw_cfg::FwCfgError;
use crate::sev::ghcb::GhcbError;
use crate::sev::msr_protocol::GhcbMsrError;
use crate::sev::SevSnpError;

// As a general rule, functions private to a given module may use the
// leaf error types. Public functions should return an SvsmError
// containing a leaf error type, usually the one corresponding to
// that module. We always provide a way to convert a leaf error into
// a SvsmError via the From trait at the module level.
#[derive(Clone, Copy, Debug)]
pub enum SvsmError {
    // Errors related to GHCB
    Ghcb(GhcbError),
    // Errors related to MSR protocol
    GhcbMsr(GhcbMsrError),
    // Errors related to SEV-SNP operations, like PVALIDATE or RMPUPDATE
    SevSnp(SevSnpError),
    // Errors related to memory management
    Mem,
    // There is no VMSA
    MissingVMSA,
    // There is no CAA
    MissingCAA,
    // Invalid address, usually provided by the guest
    InvalidAddress,
    // Errors related to firmware parsing
    Firmware,
    // Errors related to firmware configuration contents
    FwCfg(FwCfgError),
    // Errors related to ACPI parsing.
    Acpi,
}
