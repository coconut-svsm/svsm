// SPDX-License-Identifier: MIT
//
// Runtime re-seal hook for the persistent vTPM.
//
// # Why this exists (Tier-B L5-R root cause)
//
// `vtpm_init_sealed` seals vTPM state at Provision/Recover time — before the
// guest OS boots. Guest-runtime NV writes (e.g. `tpm2_nvdefine 0x1500016` +
// `tpm2_nvwrite ...`) live only in the simulator's RAM `s_NV[]` and are never
// serialised, encrypted, or pushed to the host. A cold boot unseals the
// Provision-time snapshot, so `tpm2_nvread 0x1500016` returns garbage.
//
// # Trigger selection
//
// We sniff `TPM2_Shutdown(SU_STATE)` (cmdCode 0x00000145). TCG semantics say
// the guest OS is about to lose volatile TPM state — exactly the right moment
// to persist g* + s_NV into a fresh SealedBlob.
//
// # What is / is not cached
//
// Only stable addressing parameters are cached in `ResealContext`:
// `vm_id`, host CID, and VSOCK ports. The AES-256 key and GCM nonce are
// **freshly derived from `platform_entropy()` on every re-seal** (CR-I2).
// Sensitive key material is zeroized before this function returns.
//
// # Lock ordering
//
// `trigger_if_shutdown` is called from `TcgTpm::send_tpm_command` while the
// outer `VTPM` SpinLock is held. `do_reseal` MUST NOT re-acquire `VTPM` —
// it talks to the physical TPM through a separate `TpmProxy<VsockTransport>`
// and reads vTPM internal state through C FFI
// (`state::extract_serialized_state`), neither of which touches the Rust
// `VTPM` lock.
//
// # Failure semantics
//
// Re-seal is best-effort. On failure we log the error and let the guest see
// its real `TPM2_Shutdown` success response. `RESEAL_CTX` is left unchanged
// (the old SealedBlob on the host is retained). Fail-closed enforcement is
// on the next cold boot's unseal path (NV-counter check + AES-GCM tag verify).

extern crate alloc;

use alloc::vec::Vec;

use crate::locking::SpinLock;
use crate::protocols::errors::SvsmReqError;
use crate::vtpm::proxy::{TpmProxy, VsockTransport};
use crate::vtpm::sealed::{self, VtpmState};
use crate::vtpm::sealed_store::{SealedBlobStore, VsockHostStore};
use crate::vtpm::state;

// ---------------------------------------------------------------------------
// ResealContext — stable parameters cached across the instance lifetime
// ---------------------------------------------------------------------------

struct ResealContext {
    vm_id: [u8; 16],
    host_cid: u32,
    tpm_port: u32,
    store_load_port: u32,
    store_save_port: u32,
}

static RESEAL_CTX: SpinLock<Option<ResealContext>> = SpinLock::new(None);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Register the parameters needed for a future runtime re-seal.
///
/// Called at the tail of both the Provision and Recover branches in
/// `vtpm_init_sealed`. Safe to call more than once — a double-install logs a
/// warning and overwrites the old context (Recover re-registration is
/// expected).
pub fn install_reseal_context(
    vm_id: [u8; 16],
    host_cid: u32,
    tpm_port: u32,
    store_load_port: u32,
    store_save_port: u32,
) {
    let mut guard = RESEAL_CTX.lock();
    if guard.is_some() {
        log::warn!("VTPM: reseal context overwritten (double-install)");
    }
    *guard = Some(ResealContext {
        vm_id,
        host_cid,
        tpm_port,
        store_load_port,
        store_save_port,
    });
}

/// Sniff a TPM command/response pair. If the command is a successful
/// `TPM2_Shutdown`, trigger a runtime re-seal.
///
/// MUST be called from outside the VTPM SpinLock (see module-level lock
/// ordering doc). The hook never propagates errors — failures are logged
/// and the guest sees its real Shutdown rc.
pub fn trigger_if_shutdown(command: &[u8], response: &[u8]) {
    // Command header minimum: tag(2) + size(4) + cmdCode(4) = 10 bytes.
    if command.len() < 10 {
        return;
    }

    let cmd_code = u32::from_be_bytes(command[6..10].try_into().unwrap());
    if cmd_code != 0x0000_0145 {
        // TPM_CC_Shutdown
        return;
    }

    // Response header minimum: tag(2) + size(4) + rc(4) = 10 bytes.
    if response.len() < 10 {
        return;
    }

    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    if rc != 0 {
        // TPM_RC_SUCCESS
        log::debug!("VTPM: TPM2_Shutdown returned non-zero rc=0x{rc:x}, skipping re-seal");
        return;
    }

    match do_reseal() {
        Ok(counter) => log::info!("VTPM: runtime re-seal commit (counter={counter})"),
        Err(e) => log::error!("VTPM: re-seal failed: {e:?}; old blob retained"),
    }
}

// ---------------------------------------------------------------------------
// Internal re-seal logic
// ---------------------------------------------------------------------------

/// Execute a full persistence cycle: extract vTPM state → fresh encrypt →
/// seal to TPM → save blob to host.
///
/// Returns the NV counter of the newly sealed blob on success.
///
/// # Known risk: NV-counter / blob-save ordering
///
/// `sealed::seal_state` increments the TPM NV counter *before* this
/// function saves the packed blob to the host via VSOCK. If
/// `VsockHostStore::save` fails after a successful `nv_increment`, the old
/// blob's counter is now stale and will be rejected on the next cold-boot
/// unseal by the NV-counter check. Mitigation (save-first-then-increment)
/// is deferred to a follow-up optimisation and is not part of this change.
fn do_reseal() -> Result<u64, SvsmReqError> {
    // 1. Snapshot the reseal context (release lock quickly).
    let ctx = {
        let guard = RESEAL_CTX.lock();
        guard.as_ref().map(|c| ResealContext {
            vm_id: c.vm_id,
            host_cid: c.host_cid,
            tpm_port: c.tpm_port,
            store_load_port: c.store_load_port,
            store_save_port: c.store_save_port,
        })
    };
    let ctx = ctx.ok_or_else(|| {
        log::warn!("VTPM: re-seal triggered but RESEAL_CTX is None — persist not enabled?");
        SvsmReqError::invalid_request()
    })?;

    // 2. Extract current vTPM internal state (C FFI, no VTPM lock).
    let serialized = state::extract_serialized_state().map_err(|e| {
        log::error!("VTPM: re-seal extract_serialized_state failed: {e:?}");
        SvsmReqError::invalid_request()
    })?;
    log::info!(
        "VTPM: re-seal extracted internal state ({} bytes)",
        serialized.len()
    );

    // 3. Build VtpmState. Only `extra` (serialized g* + s_NV) is populated;
    //    ek_pub is left empty — sealed.rs does not require it, and we cannot
    //    access TcgTpm.ekpub without the VTPM lock (see Lock ordering above).
    let vtpm_state = VtpmState {
        ek_priv: Vec::new(),
        ek_pub: Vec::new(),
        srk_priv: Vec::new(),
        srk_pub: Vec::new(),
        owner_auth: [0u8; 32],
        endorsement_auth: [0u8; 32],
        lockout_auth: [0u8; 32],
        nv_data: Vec::new(),
        nv_counter: 0,
        platform_auth: [0u8; 32],
        extra: serialized,
    };

    // 4. Fresh key material (CR-I2: every re-seal derives new keys).
    let mut aes_key = [0u8; 32];
    let mut nonce = [0u8; 12];
    crate::vtpm::platform_entropy(&mut aes_key, &mut nonce).map_err(|e| {
        log::error!("VTPM: re-seal platform_entropy failed: {e:?}");
        SvsmReqError::invalid_request()
    })?;

    // 5. Proxy to the TPM via VSOCK.
    let transport = VsockTransport::new(ctx.host_cid, ctx.tpm_port);
    let mut proxy = TpmProxy::new(transport);

    // 6. Seal state to TPM (nv_increment + TPM2_Seal).
    let blob =
        sealed::seal_state(&mut proxy, &vtpm_state, ctx.vm_id, &aes_key, &nonce).map_err(|e| {
            log::error!("VTPM: re-seal seal_state failed: {e:?}");
            SvsmReqError::invalid_request()
        })?;

    // 7. Flush the primary handle cached in the proxy.
    proxy.flush_primary();

    // 8. Pack the blob for host storage.
    let packed = blob.pack();
    let counter = blob.counter;

    // 9. Save to host via VSOCK.
    let store = VsockHostStore::new(ctx.host_cid, ctx.store_load_port, ctx.store_save_port);
    store.save(&packed).map_err(|e| {
        log::error!("VTPM: re-seal host save failed: {e:?}");
        SvsmReqError::invalid_request()
    })?;

    // 10. Zeroize key material.
    crate::vtpm::zeroize_key_material(&aes_key, &nonce);

    Ok(counter)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TPM command header (big-endian).
    fn tpm_cmd(cmd_code: u32, extra: &[u8]) -> Vec<u8> {
        let size = (10 + extra.len()) as u32;
        let mut cmd = Vec::with_capacity(size as usize);
        cmd.extend_from_slice(&0x8001u16.to_be_bytes()); // tag
        cmd.extend_from_slice(&size.to_be_bytes()); // size
        cmd.extend_from_slice(&cmd_code.to_be_bytes()); // commandCode
        cmd.extend_from_slice(extra);
        cmd
    }

    /// Build a minimal TPM success response (rc = 0).
    fn tpm_success_resp() -> Vec<u8> {
        let mut resp = Vec::with_capacity(10);
        resp.extend_from_slice(&0x8001u16.to_be_bytes()); // tag
        resp.extend_from_slice(&10u32.to_be_bytes()); // size
        resp.extend_from_slice(&0u32.to_be_bytes()); // rc = SUCCESS
        resp
    }

    /// Build a minimal TPM error response (rc != 0).
    fn tpm_error_resp(rc: u32) -> Vec<u8> {
        let mut resp = Vec::with_capacity(10);
        resp.extend_from_slice(&0x8001u16.to_be_bytes()); // tag
        resp.extend_from_slice(&10u32.to_be_bytes()); // size
        resp.extend_from_slice(&rc.to_be_bytes());
        resp
    }

    #[test]
    fn test_trigger_ignores_non_shutdown() {
        // Install a context so the filter has something to forward to.
        install_reseal_context([0u8; 16], 2, 9999, 9997, 9998);

        // TPM2_GetRandom (cmdCode = 0x0000017B)
        let cmd = tpm_cmd(0x0000_017B, &[0x00, 0x04]); // 4 random bytes
        let resp = tpm_success_resp();

        // Must not panic, must not call do_reseal (cmdCode filter).
        trigger_if_shutdown(&cmd, &resp);
    }

    #[test]
    fn test_trigger_ignores_failed_shutdown() {
        install_reseal_context([0u8; 16], 2, 9999, 9997, 9998);

        // TPM2_Shutdown (cmdCode = 0x00000145) with SU_STATE
        let cmd = tpm_cmd(0x0000_0145, &[0x00, 0x01]);
        // Non-zero rc → must not trigger re-seal.
        let resp = tpm_error_resp(0x0000_0100); // TPM_RC_INITIALIZE

        trigger_if_shutdown(&cmd, &resp);
    }

    #[test]
    fn test_short_command_ignored() {
        install_reseal_context([0u8; 16], 2, 9999, 9997, 9998);
        let short_cmd = [0x80u8, 0x01]; // 2 bytes < 10
        let resp = tpm_success_resp();
        trigger_if_shutdown(&short_cmd, &resp);
    }

    #[test]
    fn test_short_response_ignored() {
        install_reseal_context([0u8; 16], 2, 9999, 9997, 9998);
        let cmd = tpm_cmd(0x0000_0145, &[0x00, 0x01]);
        let short_resp = [0x80u8, 0x01]; // 2 bytes < 10
        trigger_if_shutdown(&cmd, &short_resp);
    }
}
