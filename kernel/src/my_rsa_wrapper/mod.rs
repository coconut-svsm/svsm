extern "C" {
    /************************************************
     * Return number of bytes for RSA key
     * or 0 if the RSA keys have not been initialized 
     * *********************************************/
    pub fn get_RSA_size() -> u32;
    pub fn gen_RSA_keys(n: u32) -> u32;    
}
