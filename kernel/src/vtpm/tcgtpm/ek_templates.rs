// SPDX-License-Identifier: MIT
//
// Copyright (C) Coconut-SVSM authors
//
// Author: Dionna Glaze <dionnaglaze@google.com>
//

extern crate alloc;

use crate::crypto::rand::Rand;
#[cfg(feature = "google-vtpm-ek")]
use crate::crypto::rand::Reader as RandReader;
use alloc::vec::Vec;

use crate::protocols::errors::SvsmReqError;
use crate::vtpm::{
    tcgtpm::{tss, SvsmVTpmError},
    TcgTpmSimulatorInterface,
};

// All constants are defined in TCG Trusted Platform Module Library Part 2 - Structures
// with the names stated in comments.
//
// Table 9. definition of TPM_ALG_ID constants:
// TPM_ALG_CFB     (0x0043)
// TPM_ALG_ECC     (0x0023)
// TPM_ALG_ECDSA   (0x0018)
// TPM_ALG_RSA     (0x0001)
// TPM_ALG_RSASSA  (0x0014)
// TPM_ALG_SHA256  (0x000B)
// TPM_ALG_NULL    (0x0010)
//
// Table 33. TPMA_OBJECT bits
// fixedTPM(1)
// fixedParent(4)
// sensitiveDataOrigin(5)
// userWithAuth(6)
// adminWithPolicy(7)
// restricted(16)
// decrypt(17)
// sign/encrypt(18)
//
// Table 225. TPMA_NV bits
// TPMA_NV_PPWRITE(0)
// TPMA_NV_WRITEDEFINE(13)
// TPMA_NV_PPREAD(16)
// TPMA_NV_OWNERREAD(17)
// TPMA_NV_AUTHREAD(18)
// TPMA_NV_NO_DA(25)
// TPMA_NV_PLATFORMCREATE(30)
//
// Table 223. TPM_NT
// TPM_NT_ORDINARY

// TPMT_PUBLIC with TCG default EK template,
// see Table 2: Default EK Template (TPMT_PUBLIC) L-1: RSA 2048 (Storage)
// of TCG EK Credential Profile For TPM Family 2.0; Level 0 Version 2.5 Revision 2
pub const DEFAULT_PUBLIC_AREA: [u8; 314] = [
    0x00, 0x01, // type TPM_ALG_RSA
    0x00, 0x0B, // nameAlg TPM_ALG_SHA256
    0x00, 0x03, 0x00, 0xb2, // objectAttributes { decrypt restricted adminWithPolicy
    // sensitiveDataOrigin fixedParent fixedTpm }
    0x00, 0x20, // authPolicy PolicyA_SHA256 (EK Credential profile)
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
    0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
    // TPMS_RSA_PARMS {
    0x00, 0x06, // symmetric { algorithm TPM_ALG_AES
    0x00, 0x80, // keyBits 128
    0x00, 0x43, // mode TPM_ALG_CFB }
    0x00, 0x10, // scheme TPM_ALG_NULL
    0x08, 0x00, // keyBits 2048
    0x00, 0x00, 0x00, 0x00, // exponent (0) } TPMS_RSA_PARMS
    0x01, 0x00, // unique
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// TPM2B_PUBLIC for low range ECC endorsement key.
// see Table 3: Default EK Template (TPMT_PUBLIC) L-2: ECC NIST P256 (Storage)
// of TCG EK Credential Profile For TPM Family 2.0; Level 0 Version 2.5 Revision 2
pub const LOW_RANGE_ECC_TEMPLATE: [u8; 126] = [
    0x00, 0x23, // type TPM_ALG_ECC
    0x00, 0x0B, // nameAlg TPM_ALG_SHA256
    // objectAttributes { restricted, decrypt, fixedTpm, fixedParent,
    0x00, 0x03, 0x00, 0xb2, // sensitiveDataOrigin, adminWithPolicy }
    0x00, 0x20, // authPolicy (PolicyA_SHA256)
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
    0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
    // ECC parameters {
    0x00, 0x06, 0x00, 0x80, 0x00,
    0x43, // symmetric {algorithm TPM_ALG_AES, keyBits 128, mode TPM_ALG_CFB}
    0x00, 0x18, 0x00, 0x0B, // scheme { scheme TPM_ALG_ECDSA, details: TPM_ALG_SHA256 }
    0x00, 0x03, // curveID TPM_ECC_NIST_P256
    0x00, 0x10, 0x00, 0x00, // kdf {scheme TPM_ALG_NULL, details mbz}
    // } ECC parameters
    0x00, 0x20, // x coord
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x20, // y coord
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[cfg(feature = "google-vtpm-ek")]
const GOOGLE_RSA_SIGNING_TEMPLATE: [u8; 22] = [
    0x00, 0x01, // type TPM_ALG_RSA
    0x00, 0x0B, // nameAlg TPM_ALG_SHA256
    0x00, 0x05, // objectAttributes { restricted, signEncrypt,
    0x00, 0x72, //  fixedTpm, fixedParent, sensitiveDataOrigin, userWithAuth }
    0x00, 0x00, // authPolicy empty
    // RSA parameters {
    0x00, 0x10, // symmetric {algorithm TPM_ALG_NULL,
    //  keybits skipped,
    //  mode skipped }
    0x00, 0x14, 0x00, 0x0B, // scheme { scheme TPM_ALG_RSASSA, details TPM_ALG_SHA256 }
    0x08, 0x00, // keybits { 2048 }
    0x00, 0x00, 0x00, 0x00, // exponent { 0 }
          // } RSA parameters
];

#[cfg(feature = "google-vtpm-ek")]
const GOOGLE_ECC_SIGNING_TEMPLATE: [u8; 20] = [
    0x00, 0x23, // type TPM_ALG_ECC
    0x00, 0x0B, // nameAlg TPM_ALG_SHA256
    0x00, 0x05, // objectAttributes { restricted, signEncrypt,
    0x00, 0x72, //   fixedTpm, fixedParent, sensitiveDataOrigin, userWithAuth }
    0x00, 0x00, // authPolicy empty
    // ECC parameters {
    0x00, 0x10, //  symmetric { algorithm TPM_ALG_NULL
    // keybits skipped,
    // mode skipped }
    0x00, 0x18, 0x00, 0x0B, // scheme { ecc scheme TPM_ALG_ECDSA, asym scheme TPM_ALG_SHA256}
    0x00, 0x03, // curveID { TPM_ECC_NIST_P256 }
    0x00, 0x10, // kdf { scheme TPM_ALG_NULL, details skipped }
          // } ECC parameters
];

#[cfg(feature = "google-vtpm-ek")]
pub fn extend_rand_point<R: Rand>(
    rand: &mut R,
    size: u16,
    v: &mut Vec<u8>,
) -> Result<(), SvsmReqError> {
    v.extend_from_slice(&size.to_be_bytes());
    let cur_len: usize = v.len();
    let usize_size: usize = size.try_into().unwrap();
    v.resize(cur_len + usize_size, 0);
    rand.fill_bytes(&mut v[cur_len..])
}

/// The Google Component OEM region of NV indices is 01c1_0000..01c1_003f.
/// The AK template NVIndex for an RSA signing key is 01c1_0001
#[cfg(feature = "google-vtpm-ek")]
pub fn google_rsa_signing_template<R: Rand>(rand: &mut R) -> Result<Vec<u8>, SvsmReqError> {
    let mut result = Vec::with_capacity(GOOGLE_RSA_SIGNING_TEMPLATE.len() + 0x100);
    result.extend_from_slice(&GOOGLE_RSA_SIGNING_TEMPLATE[..]);
    extend_rand_point(rand, 0x100, &mut result)?;
    Ok(result)
}

/// The Google Component OEM region of NV indices is 01c1_0000..01c1_003f.
/// The AK template NVIndex for an RSA signing key is 01c1_0001
#[cfg(feature = "google-vtpm-ek")]
pub fn google_ecc_signing_template<R: Rand>(rand: &mut R) -> Result<Vec<u8>, SvsmReqError> {
    let mut result = Vec::with_capacity(GOOGLE_ECC_SIGNING_TEMPLATE.len() + 0x44);
    result.extend_from_slice(&GOOGLE_ECC_SIGNING_TEMPLATE[..]);
    extend_rand_point(rand, 0x20, &mut result)?;
    extend_rand_point(rand, 0x20, &mut result)?;
    Ok(result)
}

// Returns a TPM2B_NV_PUBLIC.
fn init_nv_public(nvindex: u32, len: usize) -> Result<Vec<u8>, SvsmReqError> {
    let size: u16 = len
        .try_into()
        .map_err(|_| SvsmReqError::invalid_request())?;
    let mut result = Vec::with_capacity(16);
    // size = handle + alg_id + sizeof(TPMA_NV) + length(u16) + length(u16)
    result.extend_from_slice(&[0x00, 0x0E]); // Size of TPMS_NV_PUBLIC that follows.
    result.extend_from_slice(&nvindex.to_be_bytes()); // nvIndex (4 byte handle)
    result.extend_from_slice(&[
        0x00, 0x0B, // nameAlg TPM_ALG_SHA256
        0x42, // attributes { TPMA_NV_PLATFORMCREATE, TPMA_NV_NO_DA |
        0x07, //              {TPMA_NV_AUTHREAD | TPMA_NV_OWNERREAD | TPMA_NV_PPREAD} |
        0x20, //              TPMA_NV_WRITEDEFINE |
        0x01, //              (TPM_NT_ORDINARY) TPMA_NV_PPWRITE }
        0x00, 0x00, // authPolicy (empty)
    ]);
    result.extend_from_slice(&size.to_be_bytes()); // dataSize (2 bytes)
    Ok(result)
}

fn set_nv<T: TcgTpmSimulatorInterface>(
    vtpm: &T,
    nvindex: u32,
    public_area: &[u8],
) -> Result<(), SvsmReqError> {
    match tss::undefine_nv_space(vtpm, nvindex) {
        Ok(_) => (),
        Err(SvsmVTpmError::CommandError(rc)) => {
            if rc != tss::TPM_RC2_RC_VALUE {
                return Err(SvsmReqError::invalid_request());
            }
        }
        Err(SvsmVTpmError::ReqError(e)) => return Err(e),
    }
    tss::define_nv_space(vtpm, init_nv_public(nvindex, public_area.len())?.as_slice())?;
    tss::write_nv(vtpm, nvindex, public_area)?;
    Ok(())
}

/// Initializes contents for NV indices that are "manufacturer populated" for EK templates.
///
/// Arguments:
///
/// * `vtpm`: An implementation of [`TcgTpmSimulatorInterface`] to send commands to.
#[allow(unused)]
pub fn populate<T: TcgTpmSimulatorInterface, R: Rand>(
    vtpm: &T,
    rand: &mut R,
) -> Result<(), SvsmReqError> {
    // Low range constants defined in TCG EK Credential Profile 2.0 section 2.2.2.4 Low Range.
    set_nv(vtpm, 0x01c0_0004, &DEFAULT_PUBLIC_AREA[..])?;
    set_nv(vtpm, 0x01c0_000c, &LOW_RANGE_ECC_TEMPLATE[..])?;
    #[cfg(feature = "google-vtpm-ek")]
    {
        // Handle constants defined in Google's Vanadium and used in
        // https://github.com/google/go-tpm-tools/blob/main/client/handles.go
        set_nv(
            vtpm,
            0x01c1_0001,
            google_rsa_signing_template(rand)?.as_slice(),
        )?;
        set_nv(
            vtpm,
            0x01c1_0003,
            google_ecc_signing_template(rand)?.as_slice(),
        )?;
    }
    #[cfg(not(feature = "google-vtpm-ek"))]
    let _ = rand;
    Ok(())
}

#[allow(dead_code)]
struct Nonrandom;

impl Rand for Nonrandom {
    fn fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), SvsmReqError> {
        buf.fill(4);
        Ok(())
    }
}

pub fn populate_default<T: TcgTpmSimulatorInterface>(vtpm: &T) -> Result<(), SvsmReqError> {
    #[cfg(feature = "google-vtpm-ek")]
    {
        let mut rand = RandReader {};
        return populate(vtpm, &mut rand);
    }
    // Randomness is not used outside of google-vtpm-ek.
    #[cfg(not(feature = "google-vtpm-ek"))]
    {
        let mut nop = Nonrandom {};
        return populate(vtpm, &mut nop);
    }
}

mod test {
    #[test]
    fn test_nonrandom() {
        let mut nop = Nonrandom {};
        let mut buf = [0u8; 5];
        nop.fill_bytes(&mut buf).expect("Failed to fill bytes");
        assert_eq!(buf, [4u8; 5]);
    }
}
