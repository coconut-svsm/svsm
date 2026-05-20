// SPDX-License-Identifier: MIT
//
// TPM internal-state extraction and injection.
//
// Provides `extract_vtpm_state()` / `inject_vtpm_state()` via FFI into the
// `state_accessor.{c,h}` getter/setter functions, which directly access
// the TPM 2.0 Reference Implementation's internal globals (gp, gc, gr).
// A command-based fallback (`extract_vtpm_state_via_commands`) is sketched
// for environments where the direct accessors are unavailable.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::protocols::errors::SvsmReqError;

// ============================================================
// FFI Declarations — direct extern "C" (no bindgen needed)
// ============================================================

unsafe extern "C" {
    // Seed accessors
    fn get_ep_seed(out: *mut u8);
    fn set_ep_seed(in_: *const u8);
    fn get_sp_seed(out: *mut u8);
    fn set_sp_seed(in_: *const u8);
    fn get_pp_seed(out: *mut u8);
    fn set_pp_seed(in_: *const u8);

    // Auth value accessors (return actual size written)
    fn get_owner_auth(out_buf: *mut u8, buf_size: usize) -> usize;
    fn set_owner_auth(in_: *const u8, len: usize);
    fn get_endorsement_auth(out_buf: *mut u8, buf_size: usize) -> usize;
    fn set_endorsement_auth(in_: *const u8, len: usize);
    fn get_lockout_auth(out_buf: *mut u8, buf_size: usize) -> usize;
    fn set_lockout_auth(in_: *const u8, len: usize);
    fn get_platform_auth(out_buf: *mut u8, buf_size: usize) -> usize;
    fn set_platform_auth(in_: *const u8, len: usize);

    // Counter accessors
    fn get_total_reset_count() -> u64;
    fn set_total_reset_count(val: u64);
    fn get_reset_count() -> u32;
    fn set_reset_count(val: u32);
    fn get_clear_count() -> u32;
    fn set_clear_count(val: u32);
    #[allow(dead_code)]
    fn get_object_context_id() -> u64;
    #[allow(dead_code)]
    fn set_object_context_id(val: u64);

    // PCR save accessors
    fn get_pcr_save(out_buf: *mut u8, buf_size: usize) -> usize;
    fn set_pcr_save(in_: *const u8, len: usize);

    // Bulk serialization
    fn serialize_vtpm_state(out_buf: *mut u8, buf_size: usize) -> usize;
    fn deserialize_vtpm_state(in_: *const u8, len: usize) -> i32;
}

// ============================================================
// Constants
// ============================================================

/// Primary seed size in bytes (SHA-256 → 32 bytes)
pub const PRIMARY_SEED_SIZE: usize = 32;

/// Maximum auth value buffer size
const MAX_AUTH_SIZE: usize = 64;

/// Maximum PCR save area size (worst case: SHA-256 + SHA-384 + SHA-512 banks)
const MAX_PCR_SAVE_SIZE: usize = 4096;

/// Maximum serialized state buffer size.
///
/// Sized for the Tier-A field set (DA + PCR alloc, blob ~3 KB) with
/// headroom for an upcoming Tier-B section that dumps the full 16 KB
/// `s_NV[]` platform NV memory.
const MAX_SERIALIZED_SIZE: usize = 32768;

// ============================================================
// VtpmInternalState — Mirror of TPM Internal Globals
// ============================================================

/// Complete dump of seal-relevant TPM internal state.
///
/// Covers Persistent (gp), State Clear (gc), and State Reset (gr) data.
#[derive(Debug, Clone)]
pub struct VtpmInternalState {
    /// Endorsement Primary Seed (32 bytes)
    pub ep_seed: [u8; 32],
    /// Storage Primary Seed (32 bytes) — the SRK seed
    pub sp_seed: [u8; 32],
    /// Platform Primary Seed (32 bytes)
    pub pp_seed: [u8; 32],
    /// Owner hierarchy auth value
    pub owner_auth: Vec<u8>,
    /// Endorsement hierarchy auth value
    pub endorsement_auth: Vec<u8>,
    /// Lockout auth value
    pub lockout_auth: Vec<u8>,
    /// Platform auth value
    pub platform_auth: Vec<u8>,
    /// PCR save area (raw binary dump of PCR_SAVE struct)
    pub pcr_save: Vec<u8>,
    /// Total reset counter (monotonic across TPM lifetime)
    pub total_reset_count: u64,
    /// Reset counter (reset by TPM2_Clear)
    pub reset_count: u32,
    /// Clear count (incremented on TPM Resume)
    pub clear_count: u32,
}

impl VtpmInternalState {
    /// Create an empty (all-zeros) state for bootstrap.
    pub fn empty() -> Self {
        Self {
            ep_seed: [0u8; 32],
            sp_seed: [0u8; 32],
            pp_seed: [0u8; 32],
            owner_auth: Vec::new(),
            endorsement_auth: Vec::new(),
            lockout_auth: Vec::new(),
            platform_auth: Vec::new(),
            pcr_save: Vec::new(),
            total_reset_count: 0,
            reset_count: 0,
            clear_count: 0,
        }
    }
}

// ============================================================
// Direct global access via libtcgtpm accessors (FFI)
// ============================================================

/// Extract all seal-relevant TPM internal state via direct C global access.
///
/// Calls the state_accessor.c getter functions, which read gp, gc, gr
/// directly. This is the fastest path but requires libtcgtpm to be
/// compiled with state_accessor.c.
#[inline] // R1: avoid sret aggregate-return on VtpmInternalState
pub fn extract_vtpm_state() -> Result<VtpmInternalState, SvsmReqError> {
    let mut ep_seed = [0u8; 32];
    let mut sp_seed = [0u8; 32];
    let mut pp_seed = [0u8; 32];

    // SAFETY: FFI calls into state_accessor.c. Buffer pointers and sizes are correct.
    unsafe {
        get_ep_seed(ep_seed.as_mut_ptr());
        get_sp_seed(sp_seed.as_mut_ptr());
        get_pp_seed(pp_seed.as_mut_ptr());
    }

    let owner_auth = get_auth_value(get_owner_auth)?;
    let endorsement_auth = get_auth_value(get_endorsement_auth)?;
    let lockout_auth = get_auth_value(get_lockout_auth)?;
    let platform_auth = get_auth_value(get_platform_auth)?;

    let mut pcr_buf = vec![0u8; MAX_PCR_SAVE_SIZE];
    let pcr_len;
    // SAFETY: FFI call with correct buffer size.
    unsafe {
        pcr_len = get_pcr_save(pcr_buf.as_mut_ptr(), pcr_buf.len());
    }
    pcr_buf.truncate(pcr_len);

    let total_reset_count;
    let reset_count;
    let clear_count;
    // SAFETY: FFI calls returning scalar values.
    unsafe {
        total_reset_count = get_total_reset_count();
        reset_count = get_reset_count();
        clear_count = get_clear_count();
    }

    Ok(VtpmInternalState {
        ep_seed,
        sp_seed,
        pp_seed,
        owner_auth,
        endorsement_auth,
        lockout_auth,
        platform_auth,
        pcr_save: pcr_buf,
        total_reset_count,
        reset_count,
        clear_count,
    })
}

/// Inject TPM internal state via direct C global write.
///
/// Writes all seal-relevant fields back into gp, gc, gr. This must be
/// called before any TPM operation that depends on the restored state
/// (e.g., before creating the SRK or loading persistent objects).
pub fn inject_vtpm_state(state: &VtpmInternalState) -> Result<(), SvsmReqError> {
    // SAFETY: FFI calls into state_accessor.c. All pointers and lengths are valid.
    unsafe {
        set_ep_seed(state.ep_seed.as_ptr());
        set_sp_seed(state.sp_seed.as_ptr());
        set_pp_seed(state.pp_seed.as_ptr());

        set_owner_auth(state.owner_auth.as_ptr(), state.owner_auth.len());
        set_endorsement_auth(
            state.endorsement_auth.as_ptr(),
            state.endorsement_auth.len(),
        );
        set_lockout_auth(state.lockout_auth.as_ptr(), state.lockout_auth.len());
        set_platform_auth(state.platform_auth.as_ptr(), state.platform_auth.len());

        set_pcr_save(state.pcr_save.as_ptr(), state.pcr_save.len());

        set_total_reset_count(state.total_reset_count);
        set_reset_count(state.reset_count);
        set_clear_count(state.clear_count);
    }

    Ok(())
}

// ============================================================
// Bulk Serialization (C-backed)
// ============================================================

/// Serialize all seal-relevant state into a flat binary buffer using
/// the C `serialize_vtpm_state()` function.
///
/// Returns the serialized bytes. This is the recommended path for
/// state extraction before sealing, as the C function knows the exact
/// struct layouts.
#[inline] // R1: avoid sret aggregate-return on Vec<u8>
pub fn extract_serialized_state() -> Result<Vec<u8>, SvsmReqError> {
    let mut buf = vec![0u8; MAX_SERIALIZED_SIZE];
    let written;
    // SAFETY: FFI call with correctly sized buffer.
    unsafe {
        written = serialize_vtpm_state(buf.as_mut_ptr(), buf.len());
    }
    if written == 0 || written > buf.len() {
        log::error!("serialize_vtpm_state failed: buffer too small or error");
        return Err(SvsmReqError::invalid_request());
    }
    buf.truncate(written);
    Ok(buf)
}

/// Deserialize state from the C `serialize_vtpm_state()` format back
/// into TPM globals.
pub fn inject_serialized_state(data: &[u8]) -> Result<(), SvsmReqError> {
    let ret;
    // SAFETY: FFI call with valid buffer pointer and length.
    unsafe {
        ret = deserialize_vtpm_state(data.as_ptr(), data.len());
    }
    if ret != 0 {
        log::error!("deserialize_vtpm_state failed: error code {ret}");
        return Err(SvsmReqError::invalid_request());
    }
    Ok(())
}

// ============================================================
// Command-based fallback path (skeleton)
// ============================================================

/// Extract vTPM state using standard TPM 2.0 commands.
///
/// This path uses:
///   - TPM2_NV_Read for persistent NV indices (auth values, counters)
///   - TPM2_ContextSave for loaded objects (EK, SRK)
///   - TPM2_GetCapability for PCR allocation and algorithm info
///
/// This is specification-compliant and works with any TPM (real or
/// simulated), but requires the TPM to be fully initialized and the
/// target objects to be loaded.
///
/// NOT YET IMPLEMENTED — placeholder for environments where the direct
/// libtcgtpm accessors are unavailable.
#[allow(dead_code)]
#[inline] // R1: avoid sret aggregate-return on Vec<u8>
pub fn extract_vtpm_state_via_commands() -> Result<Vec<u8>, SvsmReqError> {
    // A command-based extraction path would:
    // 1. TPM2_HierarchyChangeAuth(TPM_RH_OWNER) — read ownerAuth
    //    (can't actually read it; would need prior knowledge or use Policy)
    // 2. TPM2_NV_Read for NV indices 0x01c00000–0x01c00003 (EK, SRK templates)
    // 3. TPM2_ContextSave for the SRK handle (if loaded)
    // 4. TPM2_ContextSave for the EK handle (if loaded)
    // 5. TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_RESET_COUNT, ...)
    // 6. TPM2_GetCapability(TPM_CAP_PCR, ...)
    //
    // Limitation: auth values cannot be read via TPM commands by design.
    // This path therefore requires the provisioner to have set known auth
    // values during manufacturing, or to use policy-based access.
    log::warn!("Command-based state extraction not yet implemented");
    Err(SvsmReqError::invalid_request())
}

// ============================================================
// Helpers
// ============================================================

/// Read an auth value via the C getter, which returns the actual
/// length and copies data into a caller-provided buffer.
fn get_auth_value(
    getter: unsafe extern "C" fn(*mut u8, usize) -> usize,
) -> Result<Vec<u8>, SvsmReqError> {
    let mut buf = vec![0u8; MAX_AUTH_SIZE];
    let len;
    // SAFETY: FFI call into state_accessor.c. Buffer pointer and size are valid.
    unsafe {
        len = getter(buf.as_mut_ptr(), buf.len());
    }
    if len > buf.len() {
        log::error!(
            "Auth value getter returned length {} > buffer {}",
            len,
            buf.len()
        );
        return Err(SvsmReqError::invalid_request());
    }
    buf.truncate(len);
    Ok(buf)
}
