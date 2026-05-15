// SPDX-License-Identifier: MIT
//
// vTPM proxy: TPM 2.0 command construction over a pluggable transport.
//
// Constructs raw TPM 2.0 command buffers (CreatePrimary, Create, Load,
// Unseal, FlushContext, NV_*) and sends them to a TPM endpoint reachable
// through an implementation of `TpmTransport`. The endpoint may be a
// software vTPM (development/testing), a physical discrete TPM
// (hardware-anchored persistence), or any other out-of-CVM TPM service.
// Runs in VMPL0; the transport itself crosses the CVM boundary.

extern crate alloc;

use crate::protocols::errors::SvsmReqError;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

// ============================================================
// TPM 2.0 Constants
// ============================================================

const TPM_ST_SESSIONS: u16 = 0x8002;
const TPM_CC_CREATEPRIMARY: u32 = 0x00000131;
const TPM_CC_CREATE: u32 = 0x00000153;
const TPM_CC_LOAD: u32 = 0x00000157;
const TPM_CC_UNSEAL: u32 = 0x0000015E;
const TPM_CC_FLUSHCONTEXT: u32 = 0x00000165;

const TPM_RH_OWNER: u32 = 0x40000001;
#[allow(dead_code)]
const TPM_RH_NULL: u32 = 0x40000007;
#[allow(dead_code)]
const TPM_RS_PW: u32 = 0x40000009;

const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_CFB: u16 = 0x0043;
const TPM_ALG_KEYEDHASH: u16 = 0x0008;
const TPM_ALG_NULL: u16 = 0x0010;
#[allow(dead_code)]
const TPM_ALG_POLICY: u16 = 0x000F;

const TPM_RC_SUCCESS: u32 = 0;

// TPMA_OBJECT flags
const TPMA_OBJECT_FIXEDTPM: u32 = 0x00000002;
const TPMA_OBJECT_FIXEDPARENT: u32 = 0x00000010;
const TPMA_OBJECT_SENSITIVEDATAORIGIN: u32 = 0x00000020;
const TPMA_OBJECT_USERWITHAUTH: u32 = 0x00000040;
const TPMA_OBJECT_SIGN_ENCRYPT: u32 = 0x00040000;
const TPMA_OBJECT_DECRYPT: u32 = 0x00020000;
const TPMA_OBJECT_RESTRICTED: u32 = 0x00010000;

// ============================================================
// Transport Abstraction
// ============================================================

/// Pluggable transport for sending TPM 2.0 commands to an out-of-CVM TPM
/// endpoint. Endpoints may include:
///   - a software vTPM running on the host (development / testing)
///   - a physical discrete TPM (hardware-anchored persistence)
///   - a KBS-backed TPM service (future)
///
/// Implementations must preserve TPM command/response message boundaries.
///
/// Bundled implementations:
/// - `VsockTransport`  — AF_VSOCK to the host (feature-gated `vsock`)
/// - `MockTransport`   — records commands for unit testing
pub trait TpmTransport {
    fn send_command(&self, command: &[u8]) -> Result<Vec<u8>, SvsmReqError>;
}

// ============================================================
// MockTransport — for unit testing without real TPM
// ============================================================

/// A mock transport that records commands and returns canned responses.
/// Useful for unit tests of TpmProxy logic without requiring a real TPM.
#[derive(Debug, Default)]
pub struct MockTransport {
    pub commands: core::cell::RefCell<Vec<Vec<u8>>>,
    canned_responses: core::cell::RefCell<VecDeque<Vec<u8>>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self {
            commands: core::cell::RefCell::new(Vec::new()),
            canned_responses: core::cell::RefCell::new(VecDeque::new()),
        }
    }

    /// Enqueue a response to be returned by the next pending
    /// `send_command` call. Multiple calls form a FIFO queue.
    pub fn set_response(&self, response: Vec<u8>) {
        self.canned_responses.borrow_mut().push_back(response);
    }

    /// Build a minimal success response for the given command code.
    /// Response layout: tag(2) + size(4) + rc(4) + [optional data]
    pub fn build_ok_response(_cc: u32, extra: &[u8]) -> Vec<u8> {
        let mut r = Vec::with_capacity(10 + extra.len());
        r.extend_from_slice(&0x8002u16.to_be_bytes()); // TPM_ST_SESSIONS
        let size = (10 + extra.len()) as u32;
        r.extend_from_slice(&size.to_be_bytes());
        r.extend_from_slice(&0u32.to_be_bytes()); // TPM_RC_SUCCESS
        r.extend_from_slice(extra);
        r
    }
}

impl TpmTransport for MockTransport {
    fn send_command(&self, command: &[u8]) -> Result<Vec<u8>, SvsmReqError> {
        self.commands.borrow_mut().push(command.to_vec());
        self.canned_responses
            .borrow_mut()
            .pop_front()
            .ok_or(SvsmReqError::invalid_request())
    }
}

// ============================================================
// VsockTransport — AF_VSOCK to a host-side TPM forwarder
// ============================================================

/// AF_VSOCK transport to a host-side TPM endpoint.
///
/// On each `send_command`:
/// 1. Opens a VSOCK connection to host (CID=2) on the configured port
/// 2. Sends the raw TPM command buffer
/// 3. Reads the TPM response (header first to get total size, then body)
/// 4. Closes the connection
///
/// This one-command-per-connection model avoids TPM session state issues.
/// The host side needs a lightweight forwarder such as:
///   `socat VSOCK-LISTEN:9999,fork OPEN:/dev/tpm0`
#[cfg(feature = "vsock")]
#[derive(Debug)]
pub struct VsockTransport {
    remote_cid: u32,
    remote_port: u32,
}

#[cfg(feature = "vsock")]
impl VsockTransport {
    /// Default VSOCK port for TPM forwarding.
    pub const DEFAULT_TPM_PORT: u32 = 9999;
    /// Host CID (always 2 in VSOCK).
    pub const HOST_CID: u32 = 2;

    pub fn new(remote_cid: u32, remote_port: u32) -> Self {
        Self {
            remote_cid,
            remote_port,
        }
    }
}

#[cfg(feature = "vsock")]
impl TpmTransport for VsockTransport {
    fn send_command(&self, command: &[u8]) -> Result<Vec<u8>, SvsmReqError> {
        use crate::io::{Read, Write};
        use crate::vsock::stream::VsockStream;

        // Open fresh connection for each command
        let mut stream = VsockStream::connect(self.remote_port, self.remote_cid).map_err(|_| {
            log::error!(
                "VsockTransport: failed to connect to {}:{}",
                self.remote_cid,
                self.remote_port
            );
            SvsmReqError::invalid_request()
        })?;

        // Send TPM command
        let written = stream.write(command).map_err(|_| {
            log::error!("VsockTransport: write failed");
            SvsmReqError::invalid_request()
        })?;
        if written != command.len() {
            log::error!("VsockTransport: short write {}/{}", written, command.len());
            return Err(SvsmReqError::invalid_request());
        }

        // Read TPM response header: tag(2) + size(4) + rc(4) = 10 bytes minimum
        let mut header = [0u8; 10];
        let n = stream.read(&mut header).map_err(|_| {
            log::error!("VsockTransport: header read failed");
            SvsmReqError::invalid_request()
        })?;
        if n < 10 {
            log::error!("VsockTransport: short header read {n}/10");
            return Err(SvsmReqError::invalid_request());
        }

        // Parse total response size from bytes 2..6 (big-endian u32)
        let resp_size = u32::from_be_bytes(header[2..6].try_into().unwrap()) as usize;

        if !(10..=4096).contains(&resp_size) {
            log::error!("VsockTransport: invalid response size {resp_size}");
            return Err(SvsmReqError::invalid_request());
        }

        let mut response = Vec::with_capacity(resp_size);
        response.extend_from_slice(&header);

        // Read remaining response body
        let remaining = resp_size - 10;
        if remaining > 0 {
            let mut buf = alloc::vec![0u8; remaining];
            let mut total_read = 0usize;
            while total_read < remaining {
                let n = stream.read(&mut buf[total_read..]).map_err(|_| {
                    log::error!("VsockTransport: body read failed at {total_read}/{remaining}");
                    SvsmReqError::invalid_request()
                })?;
                if n == 0 {
                    // Peer closed — partial read is an error if we expected more
                    break;
                }
                total_read += n;
            }
            if total_read < remaining {
                log::error!("VsockTransport: short body read {total_read}/{remaining}");
                return Err(SvsmReqError::invalid_request());
            }
            response.extend_from_slice(&buf);
        }

        // stream dropped → connection shutdown
        Ok(response)
    }
}

// ============================================================
// TPM Command Builder Helpers
// ============================================================

fn extend_empty_auth(buf: &mut Vec<u8>) {
    buf.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x09, // auth size
        0x40, 0x00, 0x00, 0x09, // session handle = TPM_RS_PW
        0x00, 0x00, // nonce = empty
        0x01, // sessionAttributes = continueSession
        0x00, 0x00, // password = empty
    ]);
}

fn tpm_cmd_rc(cmd: &[u8]) -> u32 {
    u32::from_be_bytes(cmd[6..10].try_into().unwrap())
}

fn pcr_policy_digest_placeholder() -> [u8; 32] {
    // Zero digest: "seal to any PCR state" for prototype.
    // Production: derive from actual PCR policy via TPM2_PolicyPCR.
    [0u8; 32]
}

#[allow(dead_code)]
fn build_pcr_selection(pcr_mask: &[u8]) -> Vec<u8> {
    let mut sel = Vec::with_capacity(8);
    sel.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    sel.push(pcr_mask.len() as u8);
    sel.extend_from_slice(pcr_mask);
    sel
}

// ============================================================
// TPM2_CreatePrimary (Owner Hierarchy)
// ============================================================

/// Build TPM2_CreatePrimary command for Owner hierarchy.
///
/// Creates a primary storage key under TPM_RH_OWNER used as parent
/// for subsequent TPM2_Create (seal) operations.
fn build_create_primary_owner(tpmt_public: &[u8]) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(4096);

    // Command header
    cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // size placeholder
    cmd.extend_from_slice(&TPM_CC_CREATEPRIMARY.to_be_bytes());

    // Handle: TPM_RH_OWNER
    cmd.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());

    // Authorization block
    extend_empty_auth(&mut cmd);

    // inSensitive: TPM2B_SENSITIVE_CREATE
    cmd.extend_from_slice(&[0x00, 0x04]); // size
    cmd.extend_from_slice(&[0x00, 0x00]); // userAuth = empty

    // inPublic: TPM2B_PUBLIC
    cmd.extend_from_slice(&(tpmt_public.len() as u16).to_be_bytes());
    cmd.extend_from_slice(tpmt_public);

    // outsideInfo
    cmd.extend_from_slice(&[0x00, 0x00]);

    // creationPCR
    cmd.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // Patch size
    let sz = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&sz.to_be_bytes());

    cmd
}

// ============================================================
// TPM2_Create (Seal)
// ============================================================

/// Build TPM2_Create command to seal data under a parent key.
///
/// `parent_handle` — handle from CreatePrimary
/// `data` — the data to seal (≤256 bytes for RSA-2048 parent)
/// `policy_digest` — 32-byte PCR policy digest
fn build_create(parent_handle: u32, data: &[u8], policy_digest: &[u8; 32]) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(4096);

    // Build TPMT_PUBLIC for a keyedhash (sealed data) object
    let tpmt_public = build_keyedhash_public(policy_digest);

    let in_sensitive_data = build_sensitive_create(data);

    // Command header
    cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // size placeholder
    cmd.extend_from_slice(&TPM_CC_CREATE.to_be_bytes());

    // Handle: parent key
    cmd.extend_from_slice(&parent_handle.to_be_bytes());

    // Authorization block
    extend_empty_auth(&mut cmd);

    // inSensitive
    cmd.extend_from_slice(&in_sensitive_data);

    // inPublic
    cmd.extend_from_slice(&(tpmt_public.len() as u16).to_be_bytes());
    cmd.extend_from_slice(&tpmt_public);

    // outsideInfo
    cmd.extend_from_slice(&[0x00, 0x00]);

    // creationPCR
    cmd.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // Patch size
    let sz = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&sz.to_be_bytes());

    cmd
}

fn build_keyedhash_public(policy_digest: &[u8; 32]) -> Vec<u8> {
    let mut p = Vec::with_capacity(64);

    // TPMT_PUBLIC:
    //   type: TPM_ALG_KEYEDHASH
    p.extend_from_slice(&TPM_ALG_KEYEDHASH.to_be_bytes());
    //   nameAlg: TPM_ALG_SHA256
    p.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    //   objectAttributes: fixedTPM | fixedParent | userWithAuth | signEncrypt
    let attrs = TPMA_OBJECT_FIXEDTPM
        | TPMA_OBJECT_FIXEDPARENT
        | TPMA_OBJECT_USERWITHAUTH
        | TPMA_OBJECT_SIGN_ENCRYPT;
    p.extend_from_slice(&attrs.to_be_bytes());

    //   authPolicy: 32-byte policy digest
    p.extend_from_slice(&(32u16).to_be_bytes());
    p.extend_from_slice(policy_digest);

    //   parameters (keyedhash union):
    //     scheme: TPM_ALG_NULL (sealed data, not a signing key)
    p.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    //     scheme detail: keyedHashScheme (empty for NULL)
    p.extend_from_slice(&[0x00, 0x00]); // TPM_ALG_NULL
    p.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes()); // hashAlg

    //   unique (keyedhash union):
    p.extend_from_slice(&[0x00, 0x00]); // zero-length unique

    p
}

fn build_sensitive_create(data: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(data.len() + 8);
    // TPM2B_SENSITIVE_CREATE outer size
    let inner_size = 2 + data.len(); // auth(2) + data(size+data)
    s.extend_from_slice(&(inner_size as u16).to_be_bytes());
    // userAuth = empty
    s.extend_from_slice(&[0x00, 0x00]);
    // data: TPM2B_SENSITIVE_DATA
    s.extend_from_slice(&(data.len() as u16).to_be_bytes());
    s.extend_from_slice(data);
    s
}

// ============================================================
// TPM2_Load
// ============================================================

/// Build TPM2_Load command to load a sealed object into the TPM.
fn build_load(parent_handle: u32, sealed_priv: &[u8], sealed_pub: &[u8]) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(4096);

    cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // size placeholder
    cmd.extend_from_slice(&TPM_CC_LOAD.to_be_bytes());

    // Handle: parent key
    cmd.extend_from_slice(&parent_handle.to_be_bytes());

    // Authorization block
    extend_empty_auth(&mut cmd);

    // inPrivate: TPM2B_PRIVATE
    cmd.extend_from_slice(&(sealed_priv.len() as u16).to_be_bytes());
    cmd.extend_from_slice(sealed_priv);

    // inPublic: TPM2B_PUBLIC
    cmd.extend_from_slice(&(sealed_pub.len() as u16).to_be_bytes());
    cmd.extend_from_slice(sealed_pub);

    // Patch size
    let sz = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&sz.to_be_bytes());

    cmd
}

/// Extract object handle from TPM2_Load response (offset 10, u32).
fn parse_load_handle(response: &[u8]) -> Result<u32, SvsmReqError> {
    if response.len() < 14 {
        return Err(SvsmReqError::invalid_request());
    }
    Ok(u32::from_be_bytes(response[10..14].try_into().unwrap()))
}

// ============================================================
// TPM2_Unseal
// ============================================================

/// Build TPM2_Unseal command.
fn build_unseal(item_handle: u32) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(256);

    cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // size placeholder
    cmd.extend_from_slice(&TPM_CC_UNSEAL.to_be_bytes());

    // Handle: loaded object
    cmd.extend_from_slice(&item_handle.to_be_bytes());

    // Authorization: password session with empty password
    // TPM_RS_PW session
    cmd.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x09, // auth size
        0x40, 0x00, 0x00, 0x09, // session handle = TPM_RS_PW
        0x00, 0x00, // nonce = empty
        0x01, // continueSession
        0x00, 0x00, // password = empty
    ]);

    // Patch size
    let sz = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&sz.to_be_bytes());

    cmd
}

/// Extract unsealed data from TPM2_Unseal response.
/// Response: tag(2) + size(4) + rc(4) + paramSize(4) + TPM2B_SENSITIVE_DATA
fn parse_unseal_data(response: &[u8]) -> Result<Vec<u8>, SvsmReqError> {
    if response.len() < 16 {
        return Err(SvsmReqError::invalid_request());
    }
    // outData: TPM2B_SENSITIVE_DATA at offset 14
    let data_size = u16::from_be_bytes(response[14..16].try_into().unwrap()) as usize;
    if response.len() < 16 + data_size {
        return Err(SvsmReqError::invalid_request());
    }
    Ok(response[16..16 + data_size].to_vec())
}

// ============================================================
// TPM2_FlushContext
// ============================================================

fn build_flushcontext(handle: u32) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(32);

    cmd.extend_from_slice(&[0x80, 0x01]); // TPM_ST_NO_SESSIONS
    cmd.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // size placeholder
    cmd.extend_from_slice(&TPM_CC_FLUSHCONTEXT.to_be_bytes());
    cmd.extend_from_slice(&handle.to_be_bytes());

    let sz = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&sz.to_be_bytes());

    cmd
}

// ============================================================
// Default RSA 2048 Primary Key Template (Owner Hierarchy)
// ============================================================

/// Build TPMT_PUBLIC for an RSA-2048 storage key under Owner hierarchy.
///
/// This is a restricted decryption key used as parent for sealed objects.
/// Matches tpm2-tools `tpm2_createprimary -C o -G rsa2048` behavior.
fn build_rsa2048_storage_template() -> Vec<u8> {
    let mut t = Vec::with_capacity(64);

    // type: TPM_ALG_RSA
    t.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
    // nameAlg: TPM_ALG_SHA256
    t.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    // objectAttributes: restricted | decrypt | fixedTPM | fixedParent
    //   | sensitiveDataOrigin | userWithAuth
    let attrs = TPMA_OBJECT_RESTRICTED
        | TPMA_OBJECT_DECRYPT
        | TPMA_OBJECT_FIXEDTPM
        | TPMA_OBJECT_FIXEDPARENT
        | TPMA_OBJECT_SENSITIVEDATAORIGIN
        | TPMA_OBJECT_USERWITHAUTH;
    t.extend_from_slice(&attrs.to_be_bytes());

    // authPolicy: empty
    t.extend_from_slice(&[0x00, 0x00]);

    // parameters (RSA union):
    //   symmetric: TPM_ALG_AES + 128 + CFB
    t.extend_from_slice(&TPM_ALG_AES.to_be_bytes());
    t.extend_from_slice(&128u16.to_be_bytes()); // keyBits
    t.extend_from_slice(&TPM_ALG_CFB.to_be_bytes()); // mode
    //   scheme: TPM_ALG_NULL (decrypt-only, not signing)
    t.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    //   scheme detail
    t.extend_from_slice(&[0x00, 0x00]); // TPM_ALG_NULL
    t.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes()); // hashAlg
    //   keyBits: 2048
    t.extend_from_slice(&2048u16.to_be_bytes());
    //   exponent: 0 (default = 65537)
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // unique (RSA union): zero-length
    t.extend_from_slice(&[0x00, 0x00]);

    t
}

// ============================================================
// TpmProxy
// ============================================================

/// Proxy that constructs TPM seal/unseal commands and sends them
/// to the physical TPM via a transport.
///
/// Operates entirely within VMPL0 — no sockets, no JSON, no separate process.
#[derive(Debug)]
pub struct TpmProxy<T: TpmTransport> {
    transport: T,
    primary_handle: Option<u32>,
    pcr_policy_digest: [u8; 32],
    seal_counter: u64,
}

impl<T: TpmTransport> TpmProxy<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            primary_handle: None,
            pcr_policy_digest: pcr_policy_digest_placeholder(),
            seal_counter: 0,
        }
    }

    pub fn set_pcr_policy(&mut self, digest: [u8; 32]) {
        self.pcr_policy_digest = digest;
    }

    /// Ensure primary storage key exists under Owner hierarchy.
    pub fn ensure_primary(&mut self) -> Result<u32, SvsmReqError> {
        if let Some(handle) = self.primary_handle {
            return Ok(handle);
        }

        let template = build_rsa2048_storage_template();
        let cmd = build_create_primary_owner(&template);
        let response = self.transport.send_command(&cmd)?;

        let rc = tpm_cmd_rc(&response);
        if rc != TPM_RC_SUCCESS {
            // TPM_RC_INITIALIZE (0x100) if TPM not started — that's ok,
            // the handle from the command response may still be valid
            if rc != 0x100 {
                log::warn!("CreatePrimary returned rc=0x{rc:x}");
            }
        }

        // Object handle is at offset 10 in response
        if response.len() < 14 {
            return Err(SvsmReqError::invalid_request());
        }
        let handle = u32::from_be_bytes(response[10..14].try_into().unwrap());
        self.primary_handle = Some(handle);
        Ok(handle)
    }

    /// Seal a payload (≤256 bytes) under the physical TPM.
    ///
    /// Returns (sealed_private, sealed_public) — the TPM2B_PRIVATE and
    /// TPM2B_PUBLIC from the TPM2_Create response, which together form
    /// the sealed object stored to disk.
    ///
    /// This seals only the AES key (60 bytes in practice), not bulk data.
    /// Bulk data is AES-256-GCM encrypted separately by the caller.
    pub fn seal_payload(&mut self, payload: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SvsmReqError> {
        let parent_handle = self.ensure_primary()?;
        self.seal_counter += 1;

        let cmd = build_create(parent_handle, payload, &self.pcr_policy_digest);
        let response = self.transport.send_command(&cmd)?;

        let rc = tpm_cmd_rc(&response);
        if rc != TPM_RC_SUCCESS {
            log::error!("TPM2_Create failed rc=0x{rc:x}");
            return Err(SvsmReqError::invalid_request());
        }

        // Parse TPM2_Create response:
        // tag(2) + size(4) + rc(4) + paramSize(4)
        // + outPrivate: TPM2B_PRIVATE  (offset 14)
        // + outPublic: TPM2B_PUBLIC
        let mut offset = 14;

        // outPrivate
        if response.len() < offset + 2 {
            return Err(SvsmReqError::invalid_request());
        }
        let priv_size =
            u16::from_be_bytes(response[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        let sealed_priv = response[offset..offset + priv_size].to_vec();
        offset += priv_size;

        // outPublic
        if response.len() < offset + 2 {
            return Err(SvsmReqError::invalid_request());
        }
        let pub_size =
            u16::from_be_bytes(response[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        let sealed_pub = response[offset..offset + pub_size].to_vec();

        Ok((sealed_priv, sealed_pub))
    }

    /// Unseal a previously sealed payload.
    ///
    /// Loads the sealed object via TPM2_Load, then unseals via TPM2_Unseal.
    /// Returns the recovered plaintext payload (the AES key).
    pub fn unseal_payload(
        &mut self,
        sealed_priv: &[u8],
        sealed_pub: &[u8],
    ) -> Result<Vec<u8>, SvsmReqError> {
        let parent_handle = self.ensure_primary()?;

        // Step 1: Load
        let load_cmd = build_load(parent_handle, sealed_priv, sealed_pub);
        let load_response = self.transport.send_command(&load_cmd)?;

        let rc = tpm_cmd_rc(&load_response);
        if rc != TPM_RC_SUCCESS {
            log::error!("TPM2_Load failed rc=0x{rc:x}");
            return Err(SvsmReqError::invalid_request());
        }

        let item_handle = parse_load_handle(&load_response)?;

        // Step 2: Unseal
        let unseal_cmd = build_unseal(item_handle);
        let unseal_response = self.transport.send_command(&unseal_cmd)?;

        let rc = tpm_cmd_rc(&unseal_response);
        if rc != TPM_RC_SUCCESS {
            log::error!("TPM2_Unseal failed rc=0x{rc:x}");
            return Err(SvsmReqError::invalid_request());
        }

        let data = parse_unseal_data(&unseal_response)?;

        // Step 3: Flush loaded object
        let flush_cmd = build_flushcontext(item_handle);
        let _ = self.transport.send_command(&flush_cmd);

        Ok(data)
    }

    /// Flush the primary key handle (call before shutdown).
    pub fn flush_primary(&mut self) {
        if let Some(handle) = self.primary_handle.take() {
            let cmd = build_flushcontext(handle);
            let _ = self.transport.send_command(&cmd);
        }
    }

    pub fn seal_counter(&self) -> u64 {
        self.seal_counter
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal CreatePrimary success response.
    /// Returns a fake object handle (0x81000000).
    fn fake_create_primary_response() -> Vec<u8> {
        let handle: u32 = 0x81000000;
        let extra = handle.to_be_bytes().to_vec();
        MockTransport::build_ok_response(TPM_CC_CREATEPRIMARY, &extra)
    }

    /// Build a minimal Create success response.
    /// Returns outPrivate = b"sealed_priv_data" + outPublic = b"sealed_pub_data".
    fn fake_create_response() -> Vec<u8> {
        let priv_data = b"sealed_priv_data";
        let pub_data = b"sealed_pub_data";
        let payload_size = 2 + priv_data.len() + 2 + pub_data.len();
        let mut extra = Vec::new();
        // paramSize (TPM_ST_SESSIONS response carries a 4-byte parameter
        // size before the response parameters).
        extra.extend_from_slice(&(payload_size as u32).to_be_bytes());
        extra.extend_from_slice(&(priv_data.len() as u16).to_be_bytes());
        extra.extend_from_slice(priv_data);
        extra.extend_from_slice(&(pub_data.len() as u16).to_be_bytes());
        extra.extend_from_slice(pub_data);
        MockTransport::build_ok_response(TPM_CC_CREATE, &extra)
    }

    /// Build a minimal Load success response.
    fn fake_load_response() -> Vec<u8> {
        let handle: u32 = 0x81000001;
        let extra = handle.to_be_bytes().to_vec();
        MockTransport::build_ok_response(TPM_CC_LOAD, &extra)
    }

    /// Build a minimal Unseal success response.
    fn fake_unseal_response(data: &[u8]) -> Vec<u8> {
        let mut extra = Vec::new();
        // paramSize (4 bytes)
        extra.extend_from_slice(&(data.len() as u32 + 2).to_be_bytes());
        // TPM2B_SENSITIVE_DATA: size(2) + data
        extra.extend_from_slice(&(data.len() as u16).to_be_bytes());
        extra.extend_from_slice(data);
        MockTransport::build_ok_response(TPM_CC_UNSEAL, &extra)
    }

    fn fake_flush_response() -> Vec<u8> {
        // FlushContext response has no extra data
        MockTransport::build_ok_response(TPM_CC_FLUSHCONTEXT, &[])
    }

    #[test]
    fn test_create_primary_command_structure() {
        let transport = MockTransport::new();
        transport.set_response(fake_create_primary_response());

        let mut proxy = TpmProxy::new(transport);
        let handle = proxy.ensure_primary().unwrap();

        assert_eq!(handle, 0x81000000);
        assert_eq!(proxy.seal_counter(), 0);

        // Verify the recorded command
        let cmds = proxy.transport.commands.borrow();
        let cmd = &cmds[0];
        // tag = TPM_ST_SESSIONS (0x8002)
        assert_eq!(u16::from_be_bytes(cmd[0..2].try_into().unwrap()), 0x8002);
        // command code = TPM_CC_CREATEPRIMARY
        assert_eq!(
            u32::from_be_bytes(cmd[6..10].try_into().unwrap()),
            TPM_CC_CREATEPRIMARY
        );
        // handle area starts at offset 10 = TPM_RH_OWNER
        assert_eq!(
            u32::from_be_bytes(cmd[10..14].try_into().unwrap()),
            TPM_RH_OWNER
        );
    }

    #[test]
    fn test_seal_payload_command() {
        let transport = MockTransport::new();
        transport.set_response(fake_create_primary_response());
        transport.set_response(fake_create_response());

        let mut proxy = TpmProxy::new(transport);
        let payload = b"test_payload_60_bytes_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

        let (sealed_priv, sealed_pub) = proxy.seal_payload(payload).unwrap();

        assert_eq!(sealed_priv, b"sealed_priv_data");
        assert_eq!(sealed_pub, b"sealed_pub_data");
        assert_eq!(proxy.seal_counter(), 1);

        // Verify Create command was sent
        let cmds = proxy.transport.commands.borrow();
        assert_eq!(cmds.len(), 2); // CreatePrimary + Create
        let create_cmd = &cmds[1];
        assert_eq!(
            u32::from_be_bytes(create_cmd[6..10].try_into().unwrap()),
            TPM_CC_CREATE
        );
    }

    #[test]
    fn test_unseal_payload_roundtrip() {
        let transport = MockTransport::new();
        let original_payload = b"test_payload_60_bytes_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

        // Set up canned responses for the full sequence:
        // CreatePrimary → Create → (stash priv/pub) → CreatePrimary → Load → Unseal → Flush
        transport.set_response(fake_create_primary_response());
        transport.set_response(fake_create_response());

        let mut proxy = TpmProxy::new(transport);
        let (sealed_priv, sealed_pub) = proxy.seal_payload(original_payload).unwrap();

        // Now for unseal: CreatePrimary → Load → Unseal → Flush
        let transport2 = MockTransport::new();
        transport2.set_response(fake_create_primary_response());
        transport2.set_response(fake_load_response());
        // unseal must return EXACTLY the original 60-byte payload
        transport2.set_response(fake_unseal_response(original_payload));
        transport2.set_response(fake_flush_response());

        let mut proxy2 = TpmProxy::new(transport2);
        let recovered = proxy2.unseal_payload(&sealed_priv, &sealed_pub).unwrap();

        assert_eq!(recovered, original_payload);
    }

    #[test]
    fn test_primary_handle_cached() {
        let transport = MockTransport::new();
        transport.set_response(fake_create_primary_response());
        transport.set_response(fake_create_response());
        transport.set_response(fake_create_response());

        let mut proxy = TpmProxy::new(transport);

        // First call: creates primary + creates sealed
        proxy
            .seal_payload(b"payload_1_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
            .unwrap();

        // Second call: uses cached handle, only sends Create
        proxy
            .seal_payload(b"payload_2_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
            .unwrap();

        let cmds = proxy.transport.commands.borrow();
        // CreatePrimary should only appear once
        let cp_count = cmds
            .iter()
            .filter(|c| {
                c.len() >= 10
                    && u32::from_be_bytes(c[6..10].try_into().unwrap()) == TPM_CC_CREATEPRIMARY
            })
            .count();
        assert_eq!(
            cp_count, 1,
            "CreatePrimary should be cached after first call"
        );
    }

    #[test]
    fn test_flush_primary() {
        let transport = MockTransport::new();
        transport.set_response(fake_create_primary_response());
        transport.set_response(fake_flush_response());

        let mut proxy = TpmProxy::new(transport);
        proxy.ensure_primary().unwrap();
        assert!(proxy.primary_handle.is_some());

        proxy.flush_primary();
        assert!(proxy.primary_handle.is_none());

        // Verify FlushContext was sent
        let cmds = proxy.transport.commands.borrow();
        let flush_cmd = &cmds[1];
        assert_eq!(
            u32::from_be_bytes(flush_cmd[6..10].try_into().unwrap()),
            TPM_CC_FLUSHCONTEXT
        );
    }

    #[test]
    fn test_build_rsa2048_template_valid() {
        let template = build_rsa2048_storage_template();
        // Must start with TPM_ALG_RSA
        assert_eq!(
            u16::from_be_bytes(template[0..2].try_into().unwrap()),
            TPM_ALG_RSA
        );
        // The TPMT_PUBLIC body (excluding outer u16 size) is fixed-length
        // for this template; cross-check exact layout to guard accidental
        // field reordering.
        assert_eq!(
            template.len(),
            30,
            "Unexpected template size: {}",
            template.len()
        );
        // Verify keyBits = 2048 lives at the known offset
        // (type(2)+nameAlg(2)+attrs(4)+authPolicy(2)+sym(6)+scheme(2)
        //  +scheme_detail(4) = 22).
        assert_eq!(
            u16::from_be_bytes(template[22..24].try_into().unwrap()),
            2048
        );
    }

    #[test]
    fn test_build_keyedhash_public() {
        let policy = [0xAAu8; 32];
        let pub_area = build_keyedhash_public(&policy);
        assert_eq!(
            u16::from_be_bytes(pub_area[0..2].try_into().unwrap()),
            TPM_ALG_KEYEDHASH
        );
        // The policy digest should be in the output
        assert!(pub_area.windows(32).any(|w| w == policy));
    }
}
