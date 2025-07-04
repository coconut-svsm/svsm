use crate::platform::SVSM_PLATFORM;
use bootlib::platform::SvsmPlatformType;
use core::sync::atomic::{AtomicBool, Ordering};

static HAS_QEMU_TESTDEV: AtomicBool = AtomicBool::new(false);
static HAS_TEST_IOREQUESTS: AtomicBool = AtomicBool::new(false);

pub fn has_qemu_testdev() -> bool {
    HAS_QEMU_TESTDEV.load(Ordering::Acquire)
}
pub fn has_test_iorequests() -> bool {
    HAS_TEST_IOREQUESTS.load(Ordering::Acquire)
}

pub fn is_test_platform_type(platform_type: SvsmPlatformType) -> bool {
    SVSM_PLATFORM.platform_type() == platform_type
}

pub fn set_has_qemu_testdev() {
    HAS_QEMU_TESTDEV.store(true, Ordering::Release)
}

pub fn set_has_test_iorequests() {
    HAS_TEST_IOREQUESTS.store(true, Ordering::Release)
}
