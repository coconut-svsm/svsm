// SPDX-License-Identifier: MIT OR Apache-2.0
//

use test::ShouldPanic;

pub fn svsm_usermodule_test_runner(test_cases: &[&test::TestDescAndFn]) {
    log::info!("running {} user tests", test_cases.len());
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
                log::info!("test {} ... ignored, {message}", test_case.desc.name.0);
            } else {
                log::info!("test {} ... ignored", test_case.desc.name.0);
            }
            continue;
        }

        log::info!("test {} ...", test_case.desc.name.0);
        (test_case.testfn.0)();
    }

    log::info!("Usermodule tests in svsm passed!");
}
