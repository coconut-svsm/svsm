// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::error::Error;
use std::fs;

use igvm::{IgvmDirectiveHeader, IgvmFile};
use igvm_defs::{
    IgvmPlatformType, IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY, IGVM_VHS_SNP_ID_BLOCK_SIGNATURE,
};
use p384::ecdsa::signature::Signer;
use p384::ecdsa::{Signature, SigningKey};
use p384::elliptic_curve::bigint::ArrayEncoding;
use p384::{EncodedPoint, SecretKey};
use zerocopy::{Immutable, IntoBytes};
use zerocopy07::FromZeroes;

use crate::igvm_measure::IgvmMeasure;
use crate::utils::{get_compatibility_mask, get_policy};

#[repr(C, packed)]
#[derive(IntoBytes, Immutable, Clone, Copy, Debug)]
pub struct SevIdBlock {
    pub ld: [u8; 48],
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct SevIdBlockBuilder {
    pub id_block: SevIdBlock,
    compatibility_mask: u32,
}

impl SevIdBlockBuilder {
    pub fn build(igvm: &IgvmFile, measure: &IgvmMeasure) -> Result<Self, Box<dyn Error>> {
        let compatibility_mask = get_compatibility_mask(igvm, IgvmPlatformType::SEV_SNP).ok_or(
            String::from("IGVM file is not compatible with the specified platform."),
        )?;
        let policy = get_policy(igvm, compatibility_mask)
            .ok_or(String::from("IGVM file does not contain a guest policy."))?;

        let mut ld = [0u8; 48];
        ld.copy_from_slice(measure.digest());

        Ok(Self {
            compatibility_mask,
            id_block: SevIdBlock {
                ld,
                family_id: Default::default(),
                image_id: Default::default(),
                version: 1,
                guest_svn: Default::default(),
                policy,
            },
        })
    }

    fn secret_key(key_file: &String) -> Result<SecretKey, Box<dyn Error>> {
        let pem = fs::read_to_string(key_file)?;
        Ok(SecretKey::from_sec1_pem(&pem)?)
    }

    pub fn gen_signature(
        key_file: &String,
        data: &[u8],
    ) -> Result<Box<IGVM_VHS_SNP_ID_BLOCK_SIGNATURE>, Box<dyn Error>> {
        let signing_key = SigningKey::from(&Self::secret_key(key_file)?);
        let signature: Signature = signing_key.sign(data);

        let r = signature.r().to_canonical().to_le_byte_array();
        let s = signature.s().to_canonical().to_le_byte_array();

        let mut result = IGVM_VHS_SNP_ID_BLOCK_SIGNATURE {
            r_comp: [0u8; 72],
            s_comp: [0u8; 72],
        };
        result.r_comp[..r.len()].copy_from_slice(&r);
        result.s_comp[..s.len()].copy_from_slice(&s);

        Ok(Box::new(result))
    }

    pub fn pub_key(
        key_file: &String,
    ) -> Result<Box<IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY>, Box<dyn Error>> {
        let secret_key = Self::secret_key(key_file)?;
        let ep = EncodedPoint::from(secret_key.public_key());
        let mut x = *ep.x().unwrap();
        let mut y = *ep.y().unwrap();
        x.reverse();
        y.reverse();

        let mut result = IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY {
            curve: 2,
            reserved: 0,
            qx: [0u8; 72],
            qy: [0u8; 72],
        };
        result.qx[..x.len()].copy_from_slice(&x);
        result.qy[..y.len()].copy_from_slice(&y);

        Ok(Box::new(result))
    }

    pub fn sign(
        &self,
        key_file: &String,
        author_key_file: &Option<String>,
    ) -> Result<IgvmDirectiveHeader, Box<dyn Error>> {
        let id_block_signature = Self::gen_signature(key_file, self.id_block.as_bytes())?;
        let id_key = SevIdBlockBuilder::pub_key(key_file)?;

        let (author_key_sig, author_pub_key) = if let Some(author_key) = author_key_file {
            // The IGVM public key format includes an extra u32 reserved field that should
            // not be measured according to the AMD SEV-SNP specification.
            let mut id_key_field = vec![2u8, 0u8, 0u8, 0u8];
            id_key_field.extend_from_slice(&id_key.qx);
            id_key_field.extend_from_slice(&id_key.qy);
            id_key_field.resize(0x404, 0);
            (
                Self::gen_signature(author_key, id_key_field.as_bytes())?,
                Self::pub_key(author_key)?,
            )
        } else {
            (
                Box::new(IGVM_VHS_SNP_ID_BLOCK_SIGNATURE::new_zeroed()),
                Box::new(IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY::new_zeroed()),
            )
        };

        Ok(IgvmDirectiveHeader::SnpIdBlock {
            compatibility_mask: self.compatibility_mask,
            author_key_enabled: if author_key_file.is_some() { 1 } else { 0 },
            reserved: [0u8; 3],
            ld: self.id_block.ld,
            family_id: self.id_block.family_id,
            image_id: self.id_block.image_id,
            version: self.id_block.version,
            guest_svn: self.id_block.guest_svn,
            id_key_algorithm: 1,
            author_key_algorithm: 1,
            id_key_signature: id_block_signature,
            id_public_key: id_key,
            author_key_signature: author_key_sig,
            author_public_key: author_pub_key,
        })
    }
}
