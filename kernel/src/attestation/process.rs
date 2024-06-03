use crate::process_manager::process::TrustedProcess;

pub fn attest_process() -> bool {
    log::info!("attest(): Attesting Monitor");
    true
}

pub fn hash_process(process: &mut TrustedProcess) {
    log::info!("Hash of Process is: 0");
    process.hash = [0u8;32];

}