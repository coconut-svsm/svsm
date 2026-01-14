#![no_main]

use libfuzzer_sys::{Corpus, fuzz_target};
use svsm::insn_decode::{Instruction, MAX_INSN_SIZE, TestCtx};

fuzz_target!(|input: &[u8]| -> Corpus {
    let Some(input) = input.get(..MAX_INSN_SIZE) else {
        return Corpus::Reject;
    };

    let mut data = [0u8; MAX_INSN_SIZE];
    data.copy_from_slice(input);

    let insn = Instruction::new(data);
    let _ = core::hint::black_box({
        let mut ctx = TestCtx::default();
        match insn.decode(&ctx) {
            Ok(insn_ctx) => insn_ctx.emulate(&mut ctx),
            Err(e) => Err(e),
        }
    });

    Corpus::Keep
});
