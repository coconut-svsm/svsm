#[repr(C)]
#[derive(Debug, Default)]
#[derive(Copy, Clone)]
pub struct key_pair 
{
	pub public_key: [u8; 32],
	pub private_key: [u8; 32],
}

impl key_pair {
    pub const fn new() -> key_pair {
        key_pair {
            public_key: [0;32],
            private_key: [0;32]
        }
    }
}

extern "C" {
    pub fn gen_keys() -> *mut key_pair;
    pub fn get_key_size() -> u32;
    pub fn get_keys() -> *mut key_pair;
    pub fn encrypt
        (
            dst: *mut u8,
            src: *mut u8,
            len: u32,
            nonce: *mut u8,
            pub_key_recipient: *mut u8,
            priv_key_sender: *mut u8
        ) -> u32;

    pub fn decrypt(
        dst: *mut u8,
        src: *mut u8,
        len: u32,
        nonce: *mut u8,
        pub_key_sender: *mut u8,
        priv_key_recipient: *mut u8
        ) -> u32;

    pub fn my_SHA512(buff: *mut u8, buff_len: u32, hash: *mut u8) -> i32;
    pub fn get_cycles() -> u64;

}
