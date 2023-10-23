use log::info;
use test::ShouldPanic;

use crate::{cpu::percpu::this_cpu_mut, sev::ghcb::GHCBIOSize};

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
    const QEMU_EXIT_PORT: u16 = 0xf4;
    this_cpu_mut()
        .ghcb()
        .ioio_out(QEMU_EXIT_PORT, GHCBIOSize::Size32, 0)
        .unwrap();
    unreachable!();
}
