// use super::prelude::*; // unused

use crate::protocol::common::qxfer::{ParseAnnex, QXferReadBase};

pub type qXferMemoryMapRead<'a> = QXferReadBase<'a, MemoryMapAnnex>;

#[derive(Debug)]
pub struct MemoryMapAnnex;

impl<'a> ParseAnnex<'a> for MemoryMapAnnex {
    #[inline(always)]
    fn from_buf(buf: &[u8]) -> Option<Self> {
        if buf != b"" {
            return None;
        }

        Some(MemoryMapAnnex)
    }
}
