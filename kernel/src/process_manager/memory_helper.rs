#![allow(unused_macros)]

use crate::{address::{Address, PhysAddr}, utils::immut_after_init::ImmutAfterInitCell};
use core::cmp;
use crate::cpu::cpuid::cpuid_table;

pub const ZERO_PAGE: [u64;512] = [0;512];
pub const ZERO_PAGE_REF_U8: &[u8; 4096] = unsafe { &*(&ZERO_PAGE as *const [u64;512] as *const [u8;4096]) };


#[macro_export]
macro_rules! vaddr_as_u64_slice {
    ($vaddr:expr) => {
        unsafe { &mut *$vaddr.as_mut_ptr::<[u64;512]>() }
    };
}
#[macro_export]
macro_rules! map_paddr {
    ($paddr:expr) => {{
        let mapping = PerCPUPageMappingGuard::create_4k($paddr).unwrap();
        let vaddr = mapping.virt_addr();
         (mapping,vaddr)
    }};
}
#[macro_export]
macro_rules! vaddr_as_slice {
    ($vaddr:expr, $type:ty) => {{
        unsafe { &mut *$vaddr.as_mut_ptr::<[$type;512]>() }
    }};
    ($vaddr:expr) => {{
        unsafe { &mut *$vaddr.as_mut_ptr::<[u64;512]>() }
    }};
}

#[macro_export]
macro_rules! paddr_as_u64_slice {
    ($paddr:expr) => {{
        let (mapping, vaddr) = map_paddr!($paddr);
        (mapping, vaddr_as_u64_slice!(vaddr))
    }};
}
#[macro_export]
macro_rules! paddr_as_slice {
    ($paddr:expr, $type:ty) => {{
        let (mapping, vaddr) = map_paddr!($paddr);
        (mapping, vaddr_as_slice!(vaddr,$type))
    }};
    ($paddr:expr) => {{
        let (mapping, vaddr) = map_paddr!($paddr);
        (mapping, vaddr_as_slice!(vaddr,u64))
    }}
}
#[macro_export]
macro_rules! paddr_as_table {
    ($paddr:expr) => {{
        let (mapping, vaddr) = map_paddr!($paddr);
        (mapping, unsafe {&mut *vaddr.as_mut_ptr::<ProcessPageTablePage>()})
    }};
}

#[macro_export]
macro_rules! strip_paddr {
    ($paddr:expr) => {
        PhysAddr::from(usize::from(strip_c_bit($paddr))  & !0x8000000000000FFF)
    };
}

#[macro_export]
macro_rules! paddr_as_PhysAddr_slice {
    ($paddr:expr) => ({
        let (mapping, vaddr) = map_paddr!($paddr);
        (mapping, vaddr_as_)


    });
}

macro_rules! usize_to_u64 {
    ($usize:expr) => {
        $usize.try_into().unwrap() //In realease this does not cause overhead
    };
}

macro_rules! set_addr {
    ($addr:expr) => {{
        let entry_flags = PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::USER_ACCESSIBLE | PageFlags::ACCESSED;
        set_c_bit_in_address($addr).bits() as u64 | entry_flags.bits()
    }};
    ($addr:expr, $flags:expr) => {{
        set_c_bit_in_address($addr).bits() as u64 | $flags.bits()
    }};
}

const CBIT_LOCATION: u32 = 0x8000001f;
const PSIZE_LOCATION: u32 = 0x80000008;
static MAX_PHYS_ADDR: ImmutAfterInitCell<u64> = ImmutAfterInitCell::uninit();
static ENCRYPT_MASK: ImmutAfterInitCell<usize> = ImmutAfterInitCell::new(0);

pub fn set_ecryption_mask_address_size() {
    let res = cpuid_table(CBIT_LOCATION).expect("CPUID table query error");
    let c_bit = res.ebx & 0x3f;
    let mask = 1u64 << c_bit;
    let _ = ENCRYPT_MASK.reinit(&(mask as usize));

    let res = cpuid_table(PSIZE_LOCATION).expect("CPUID table query error");
    let guest_phys_addr_size = (res.eax >> 16) & 0xff;
    let host_phys_addr_size = res.eax & 0xff;
    let phys_addr_size = if guest_phys_addr_size == 0 {
        host_phys_addr_size
    } else {
        guest_phys_addr_size
    };
    let effective_phys_addr_size = cmp::min(c_bit, phys_addr_size);
    let max_addr = 1 << effective_phys_addr_size;
    let _ = MAX_PHYS_ADDR.reinit(&max_addr);
}

pub fn get_encryption_mask() -> usize {
    *ENCRYPT_MASK
}

pub fn strip_c_bit(paddr: PhysAddr) -> PhysAddr {
    PhysAddr::from(paddr.bits() & !get_encryption_mask())
}

pub fn set_c_bit_in_address(addr: PhysAddr) -> PhysAddr {
    return PhysAddr::from(addr.bits() | get_encryption_mask());
}
