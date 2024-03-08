// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Carlos López <carlos.lopez@suse.com

#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt;

// PackItArchive has a Vec of files, so it requires alloc
#[cfg(feature = "alloc")]
mod archive;
mod decode;
// The encoder requires the std::io::Write trait
#[cfg(feature = "std")]
mod encode;
mod file;
mod header;

#[cfg(feature = "alloc")]
pub use archive::PackItArchive;
pub use decode::PackItArchiveDecoder;
#[cfg(feature = "std")]
pub use encode::PackItArchiveEncoder;
pub use file::PackItFile;
pub use header::PackItHeader;

/// A convenience alias for `Result<T, PackItError>`.
pub type PackItResult<T> = Result<T, PackItError>;

/// Errors encountered during archive packing and unpacking
#[derive(Debug)]
#[cfg_attr(not(feature = "std"), derive(Clone, Copy, PartialEq, Eq))]
pub enum PackItError {
    UnexpectedEOF,
    InvalidHeader,
    InvalidFileHeader,
    InvalidFileName,
    #[cfg(feature = "std")]
    IoError(std::io::Error),
}

#[cfg(feature = "std")]
impl From<std::io::Error> for PackItError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl fmt::Display for PackItError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEOF => write!(f, "Unexpected end of file"),
            Self::InvalidHeader => write!(f, "Invalid header"),
            Self::InvalidFileHeader => write!(f, "Invalid file header"),
            Self::InvalidFileName => write!(f, "File name too long or not valid UTF-8"),
            #[cfg(feature = "std")]
            Self::IoError(e) => write!(f, "I/O error: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode() {
        let data = [
            80, 75, 73, 84, 8, 0, 0, 0, 1, 0, 2, 0, 9, 0, 0, 0, 0, 0, 0, 0, 102, 49, 115, 111, 109,
            101, 32, 100, 97, 116, 97, 1, 0, 2, 0, 14, 0, 0, 0, 0, 0, 0, 0, 102, 50, 115, 111, 109,
            101, 32, 109, 111, 114, 101, 32, 100, 97, 116, 97, 1, 0, 5, 0, 15, 0, 0, 0, 0, 0, 0, 0,
            102, 51, 47, 102, 52, 101, 118, 101, 110, 32, 109, 111, 114, 101, 32, 100, 97, 116, 97,
            33,
        ];
        let decoder = PackItArchiveDecoder::load(&data).unwrap();
        let expected = [
            PackItFile::new("f1", b"some data").unwrap(),
            PackItFile::new("f2", b"some more data").unwrap(),
            PackItFile::new("f3/f4", b"even more data!").unwrap(),
            PackItFile::new("f3/f4/f5", b"another nested file").unwrap(),
        ];

        assert_eq!(decoder.header().header_size(), 8);

        for (file, orig) in decoder.zip(&expected) {
            let file = file.unwrap();
            assert_eq!(file.name(), orig.name());
            assert_eq!(file.data(), orig.data());
            assert_eq!(file.total_size(), orig.total_size());
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn encode_decode_witharchive() {
        let files = [
            PackItFile::new("f1", b"some data").unwrap(),
            PackItFile::new("f2", b"some more data").unwrap(),
            PackItFile::new("f3/f4", b"even more data!").unwrap(),
            PackItFile::new("f3/f4/f5", b"another nested file").unwrap(),
        ];

        // Generate archive
        let mut ar = PackItArchive::new();
        for file in files.iter() {
            ar.insert(file.clone());
        }

        // Encode to buffer
        let mut dst = Vec::new();
        ar.write(&mut dst).unwrap();

        // Decode from buffer
        let t = PackItArchiveDecoder::load(&dst).unwrap();
        for (file, orig) in t.zip(&files) {
            let file = file.unwrap();
            assert_eq!(file.name(), orig.name());
            assert_eq!(file.data(), orig.data());
            assert_eq!(file.total_size(), orig.total_size());
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn encode_decode_withencoder() {
        let files = [
            PackItFile::new("f1", b"some data").unwrap(),
            PackItFile::new("f2", b"some more data").unwrap(),
            PackItFile::new("f3/f4", b"even more data!").unwrap(),
            PackItFile::new("f3/f4/f5", b"another nested file").unwrap(),
        ];

        let mut dst = Vec::new();
        let mut ar = PackItArchiveEncoder::new(&mut dst).unwrap();
        for file in files.iter() {
            ar.write_file(&file).unwrap();
        }

        // Decode from buffer
        let t = PackItArchiveDecoder::load(&dst).unwrap();
        for (file, orig) in t.zip(&files) {
            let file = file.unwrap();
            assert_eq!(file.name(), orig.name());
            assert_eq!(file.data(), orig.data());
            assert_eq!(file.total_size(), orig.total_size());
        }
    }
}
