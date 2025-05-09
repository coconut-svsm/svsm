use core::arch::asm;
use log::info;
use test::ShouldPanic;

use crate::{
    cpu::percpu::current_ghcb,
    locking::{LockGuard, SpinLock},
    platform::SVSM_PLATFORM,
    serial::SerialPort,
    sev::ghcb::GHCBIOSize,
    testutils::is_qemu_test_env,
};

#[macro_export]
macro_rules! assert_eq_warn {
    ($left:expr, $right:expr) => {
        {
            let left = $left;
            let right = $right;
            if left != right {
                log::warn!(
                    "Assertion warning failed at {}:{}:{}:\nassertion `left == right` failed\n left: {left:?}\n right: {right:?}",
                    file!(),
                    line!(),
                    column!(),
                );
            }
        }
    };
}
pub use assert_eq_warn;

static SERIAL_PORT: SpinLock<Option<SerialPort<'_>>> = SpinLock::new(None);

/// Byte used to tell the host the request we need for the test.
/// These values must be aligned with `test_io()` in scripts/test-in-svsm.sh
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum IORequest {
    NOP = 0x00,
    /// get SEV-SNP pre-calculated launch measurement (48 bytes) from the host
    GetLaunchMeasurement = 0x01,
    /// Virtio-blk tests: Get Sha256 hash of the svsm state disk image
    GetStateImageSha256 = 0x02,
}

/// Return the serial port to communicate with the host for a given request
/// used in a test. The request (first byte) is sent by this function, so the
/// caller can start using the serial port according to the request implemented
/// in `test_io()` in scripts/test-in-svsm.sh
pub fn svsm_test_io() -> LockGuard<'static, Option<SerialPort<'static>>> {
    let mut sp = SERIAL_PORT.lock();
    if sp.is_none() {
        let io_port = SVSM_PLATFORM.get_io_port();
        let serial_port = SerialPort::new(io_port, 0x2e8 /*COM4*/);
        *sp = Some(serial_port);
        serial_port.init();
    }

    sp
}

pub fn svsm_test_runner(test_cases: &[&test::TestDescAndFn]) {
    info!("running {} tests", test_cases.len());
    for mut test_case in test_cases.iter().copied().copied() {
        if test_case.desc.should_panic == ShouldPanic::Yes {
            test_case.desc.ignore = true;
            test_case
                .desc
                .ignore_message
                .get_or_insert("#[should_panic] not supported");
        }

        if test_case.desc.ignore {
            if let Some(message) = test_case.desc.ignore_message {
                info!("test {} ... ignored, {message}", test_case.desc.name.0);
            } else {
                info!("test {} ... ignored", test_case.desc.name.0);
            }
            continue;
        }

        info!("test {} ...", test_case.desc.name.0);
        (test_case.testfn.0)();
    }

    info!("All tests passed!");

    exit();
}

fn exit() -> ! {
    if is_qemu_test_env() {
        const QEMU_EXIT_PORT: u16 = 0xf4;
        current_ghcb()
            .ioio_out(QEMU_EXIT_PORT, GHCBIOSize::Size32, 0)
            .unwrap();
    }
    // SAFETY: HLT instruction does not affect memory.
    unsafe {
        asm!("hlt");
    }
    unreachable!();
}
