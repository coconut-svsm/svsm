#[repr(C)]
#[derive(Debug)]
pub struct RSA_key {
    pub key: *mut u8,
    pub size: u32,
}

extern "C" {
    /************************************************
     * Return number of bytes for RSA key
     * or 0 if the RSA keys have not been initialized 
     * *********************************************/
    pub fn get_RSA_size() -> u32;
    pub fn gen_RSA_keys(n: u32) -> u32;    
    pub fn RSA_encrypt(flen: u32, from: *mut u8, to: *mut u8) -> i32;
    pub fn RSA_decrypt(flen: u32, from: *mut u8, to: *mut u8) -> i32;
    pub fn get_RSA_public_key() -> *mut RSA_key;
    pub fn my_SHA256(buff: *const u8, buff_len: u32, hash: *mut u8) -> i32;
    pub fn my_SHA512(buff: *const u8, buff_len: u32, hash: *mut u8) -> i32;
    pub fn get_cycles() -> u64;
}
