use super::sev::{GHCBIOSize, request_termination_msr, sev_es_enabled};
use core::arch::asm;
use super::GHCB;

pub fn outb(port: u16, value : u8) {
	if sev_es_enabled() {
		unsafe {
			if let Some(g) = &mut GHCB {
				let ret = g.ioio_out(port, GHCBIOSize::Size8, value as u64);
				if let Err(()) = ret {
					request_termination_msr();
				}
			}
		}
	} else {
		unsafe {
			asm!("outb %al, %dx", in("al") value, in("dx") port, options(att_syntax))
		}
	}
}

pub fn inb(port : u16) -> u8 {
	if sev_es_enabled() {
		unsafe {
			if let Some(g) = &mut GHCB {
				let ret = g.ioio_in(port, GHCBIOSize::Size8);
				match ret {
					Ok(v) => (v & 0xff) as u8,
					Err(_e) => { request_termination_msr(); 0},
				}
			} else {
				0xffu8
			}
		}
	} else {
		unsafe {
			let ret: u8;
			asm!("inb %dx, %al", in("dx") port, out("al") ret, options(att_syntax));
			ret
		}
	}
}

pub fn outw(port: u16, value : u16) {
	if sev_es_enabled() {
		unsafe {
			if let Some(g) = &mut GHCB {
				let ret = g.ioio_out(port, GHCBIOSize::Size16, value as u64);
				if let Err(()) = ret {
					request_termination_msr();
				}
			}
		}
	} else {
		unsafe {
			asm!("outw %ax, %dx", in("ax") value, in("dx") port, options(att_syntax))
		}
	}
}

pub fn inw(port : u16) -> u16 {
	if sev_es_enabled() {
		unsafe {
			if let Some(g) = &mut GHCB {
				let ret = g.ioio_in(port, GHCBIOSize::Size16);
				match ret {
					Ok(v) => (v & 0xffff) as u16,
					Err(_e) => { request_termination_msr(); 0},
				}
			} else {
				0xffffu16
			}
		}
	} else {
		unsafe {
			let ret: u16;
			asm!("inw %dx, %ax", in("dx") port, out("ax") ret, options(att_syntax));
			ret
		}
	}
}

