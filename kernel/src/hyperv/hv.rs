// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use crate::address::{VirtAddr, VirtPhysPair};
use crate::cpu::msr::write_msr;
use crate::cpu::percpu::{this_cpu, PerCpu};
use crate::cpu::{IrqGuard, X86GeneralRegs};
use crate::error::SvsmError;
use crate::error::SvsmError::HyperV;
use crate::hyperv;
use crate::hyperv::{HvInitialVpContext, HyperVMsr};
use crate::mm::alloc::allocate_pages;
use crate::mm::pagetable::PTEntryFlags;
use crate::mm::{virt_to_phys, SVSM_HYPERCALL_CODE_PAGE};
use crate::platform::SVSM_PLATFORM;
use crate::types::PAGE_SIZE;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use crate::utils::unsafe_copy_bytes;

use core::arch::asm;
use core::cell::RefMut;
use core::marker::PhantomData;
use core::mem;
use core::mem::MaybeUninit;
use core::ptr;

use bitfield_struct::bitfield;

#[derive(Debug)]
struct HypercallInput<H, T: ?Sized> {
    header: *mut H,
    rep_count: usize,
    _phantom: PhantomData<T>,
}

impl<H, T: ?Sized> HypercallInput<H, T> {
    // SAFETY: the caller must guarantee the safety of the header pointer so
    // that this function can assume the safety guarantees expected for
    // subsequent access.
    unsafe fn new(header: *mut H) -> Self {
        Self {
            header,
            rep_count: 0,
            _phantom: PhantomData,
        }
    }

    /// This function requires the use of `mut self` because it generates
    /// mutable references to the addresses described by the hypercall pages,
    /// but the compiler cannot understand that relationship.  Therefore,
    /// suppress the warning for needless mut because it is actually required
    /// in this case.
    #[allow(clippy::needless_pass_by_ref_mut)]
    fn write_header(&mut self, header: &H) {
        // SAFETY: the source pointer is a safe reference, and the safety of
        // the destination pointer was determined when the input object was
        // created.
        unsafe {
            unsafe_copy_bytes(
                ptr::from_ref(header) as usize,
                self.header as usize,
                mem::size_of::<H>(),
            );
        }
    }
}

impl<H, T> HypercallInput<H, T> {
    // SAFETY: the caller must guarantee the safety of the header pointer so
    // that this function can assume the safety guarantees expected for
    // subsequent access.
    unsafe fn new_rep(header: *mut H, page_size: usize) -> Self {
        let rep_count = (page_size - mem::size_of::<H>()) / mem::size_of::<T>();
        Self {
            header,
            rep_count,
            _phantom: PhantomData,
        }
    }

    /// This function requires the use of `mut self` because it generates
    /// mutable references to the addresses described by the hypercall pages,
    /// but the compiler cannot understand that relationship.  Therefore,
    /// suppress the warning for needless mut because it is actually required
    /// in this case.
    #[allow(clippy::needless_pass_by_ref_mut)]
    fn write_rep(&mut self, index: usize, item: T) {
        assert!(index < self.rep_count);
        let addr = self.header as usize + mem::size_of::<H>() + (index * core::mem::size_of::<T>());
        // SAFETY: the source pointer is a safe reference, and the safety of
        // the destination pointer is guaranteed by the address calculation
        // at the time the input object was created, plus the bounds check
        // above.
        unsafe {
            unsafe_copy_bytes(ptr::from_ref(&item) as usize, addr, mem::size_of::<T>());
        }
    }
}

#[derive(Debug)]
struct HypercallOutput<T> {
    array: *const T,
    rep_count: usize,
}

impl<T> HypercallOutput<T> {
    // SAFETY: the caller must guarantee the safety of the array pointer so
    // that this function can assume the safety guarantees expected for
    // subsequent access.
    unsafe fn new(array: *const T, rep_count: usize) -> Self {
        Self { array, rep_count }
    }

    fn read(&self, index: usize) -> T {
        assert!(index < self.rep_count);
        let addr = self.array as usize + (index * core::mem::size_of::<T>());

        let mut item = MaybeUninit::<T>::uninit();

        // SAFETY: the source pointer is a safe reference, and the safety of
        // the destination pointer is guaranteed by the address calculation
        // at the time the input object was created, plus the bounds check
        // above.  The copy guarantees the initialization of the output object.
        unsafe {
            unsafe_copy_bytes(addr, item.as_mut_ptr() as usize, mem::size_of::<T>());

            item.assume_init()
        }
    }
}

#[derive(Debug)]
pub struct HypercallPagesGuard<'a> {
    // The page reference is never actually read; it exists here to bind the
    // lifetime of the `Ref` to the lifetime of the `HypercallPagesGuard`.
    // The input/output pages are unwrapped during construction.
    _page_ref: RefMut<'a, (VirtPhysPair, VirtPhysPair)>,
    pub input: VirtPhysPair,
    pub output: VirtPhysPair,
    _irq_guard: IrqGuard,
}

/// A structure that binds a reference to hypercall input/output pages.
/// The pages remain usable until the structure is dropped.
impl<'a> HypercallPagesGuard<'a> {
    /// Creates a new `HypercallPagesGuard` structure to describe a pair of
    /// input/output pages.
    ///
    /// # Safety
    ///
    /// No validation is performed to verify correct ownership of the specified
    /// virtual addresses, and no validation is performed to verify the
    /// correct association of virtual to physical address.  The caller is
    /// responsible for ensuring that both virtual and physical addresses are
    /// correct and usable.
    pub unsafe fn new(page_ref: RefMut<'a, (VirtPhysPair, VirtPhysPair)>) -> Self {
        let (input, output) = *page_ref;
        Self {
            _page_ref: page_ref,
            input,
            output,
            _irq_guard: IrqGuard::new(),
        }
    }

    /// Casts a hypercall input page into a header of type `H` and returns a
    /// reference to that header object.
    ///
    /// This function requires the use of `mut self` because it generates
    /// mutable references to the addresses described by the hypercall pages,
    /// but the compiler cannot understand that relationship.  Therefore,
    /// suppress the warning for needless mut because it is actually required
    /// in this case.
    #[allow(clippy::needless_pass_by_ref_mut)]
    fn hypercall_input<H>(&mut self) -> HypercallInput<H, ()> {
        let header = self.input.vaddr.as_mut_ptr::<H>();
        assert!(size_of::<H>() <= PAGE_SIZE);
        // SAFETY: the virtual address represents an entire page which is
        // exclusively owned by the `HypercallPagesGuard` and can safely be
        // cast to a header of type `H`.
        unsafe { HypercallInput::new(header) }
    }

    /// Divides a hypercall input page into a header of type `H` and a slice
    /// of repeated elements of type `T` and returns a reference to each
    /// portion.
    ///
    /// This function requires the use of `mut self` because it generates
    /// mutable references to the addresses described by the hypercall pages,
    /// but the compiler cannot understand that relationship.  Therefore,
    /// suppress the warning for needless mut because it is actually required
    /// in this case.
    #[allow(clippy::needless_pass_by_ref_mut)]
    fn hypercall_rep_input<H, T>(&mut self) -> HypercallInput<H, T> {
        let header = self.input.vaddr.as_mut_ptr::<H>();
        assert!(size_of::<H>() <= PAGE_SIZE);

        // SAFETY: the virtual address represents an entire page which is
        // exclusively owned by the `HypercallPagesGuard` and can safely be
        // cast to a header of type `H` followed by an array of `T` up to the
        // size of one page.
        unsafe { HypercallInput::new_rep(header, PAGE_SIZE) }
    }

    /// Casts a hypercall output page into a slice of repeated elements of
    /// type `T` and returns a reference to that slice.
    fn hypercall_output<T>(&self, output: HvHypercallOutput) -> HypercallOutput<T> {
        // A non-REP hypercall is assumed to have a single output element.
        let output_count = output.count();
        let count: usize = if output_count != 0 {
            output_count as usize
        } else {
            1
        };
        assert!(count * size_of::<T>() <= PAGE_SIZE);
        // SAFETY: the virtual address represents an entire page which is
        // exclusively owned by the `HypercallPagesGuard` and can safely be
        // cast to an array of `T` up to the size of one page.
        unsafe { HypercallOutput::new(self.output.vaddr.as_ptr::<T>(), count) }
    }
}

#[bitfield(u64)]
pub struct HvHypercallInput {
    call_code: u16,
    is_fast: bool,
    #[bits(9)]
    var_hdr_size: u32,
    #[bits(5)]
    _rsvd_26_30: u32,
    is_nested: bool,
    #[bits(12)]
    element_count: u32,
    #[bits(4)]
    _rsvd_44_47: u32,
    #[bits(12)]
    start_index: u32,
    #[bits(4)]
    _rsvd_60_63: u32,
}

#[bitfield(u64)]
pub struct HvHypercallOutput {
    status: u16,
    _rsvd_16_31: u16,
    #[bits(12)]
    count: u32,
    #[bits(20)]
    _rsvd_44_63: u64,
}

#[repr(u16)]
enum HvCallCode {
    EnableVpVtl = 0xf,
    GetVpRegister = 0x50,
    StartVirtualProcessor = 0x99,
}

pub const HV_PARTITION_ID_SELF: u64 = 0xFFFF_FFFF_FFFF_FFFF;
pub const HV_VP_INDEX_SELF: u32 = 0xFFFF_FFFE;

pub const HV_STATUS_SUCCESS: u16 = 0;
pub const HV_STATUS_OPERATION_FAILED: u16 = 0x71;
pub const HV_STATUS_TIMEOUT: u16 = 0x78;

static HYPERV_HYPERCALL_CODE_PAGE: ImmutAfterInitCell<VirtAddr> = ImmutAfterInitCell::uninit();
static CURRENT_VTL: ImmutAfterInitCell<u8> = ImmutAfterInitCell::uninit();
pub static IS_HYPERV: ImmutAfterInitCell<bool> = ImmutAfterInitCell::uninit();

fn is_hyperv_hypervisor() -> bool {
    // Get the hypervisor interface signature.
    let result = SVSM_PLATFORM.cpuid(0x40000001, 0);
    if let Some(cpuid_result) = result {
        cpuid_result.eax == 0x31237648
    } else {
        false
    }
}

pub fn setup_hypercall_page() -> Result<(), SvsmError> {
    // Allocate a page to use as the hypercall code page.
    let page = allocate_pages(1)?;

    // Map the page as executable at a known address.
    let hypercall_va = SVSM_HYPERCALL_CODE_PAGE;
    this_cpu()
        .get_pgtable()
        .map_4k(hypercall_va, virt_to_phys(page), PTEntryFlags::exec())?;

    HYPERV_HYPERCALL_CODE_PAGE
        .init(hypercall_va)
        .expect("Hypercall code page already allocated");

    // Set the hypercall code page address to the physical address of the
    // allocated page, and mark it enabled.
    let pa = virt_to_phys(page);
    // SAFETY: we trust the page allocator to allocate a valid page to which pa
    // points.
    unsafe { write_msr(HyperVMsr::Hypercall.into(), u64::from(pa) | 1) };

    Ok(())
}

fn hyperv_setup_hypercalls() -> Result<(), SvsmError> {
    // Set the guest OS ID.  The value is arbitrary.
    // SAFETY: the guest OS MSR does not affect safety.
    unsafe {
        SVSM_PLATFORM.write_host_msr(HyperVMsr::GuestOSID.into(), 0xC0C0C0C0);
    }

    // Take platform-specific action to enable hypercalls.
    SVSM_PLATFORM.setup_hyperv_hypercalls()?;

    // Obtain the current VTL for use in future hypercalls.
    let vsm_status_value = get_vp_register(hyperv::HvRegisterName::VsmVpStatus)?;
    let vsm_status = hyperv::HvRegisterVsmVpStatus::from(vsm_status_value);
    let current_vtl = vsm_status.active_vtl();
    CURRENT_VTL
        .init(current_vtl)
        .expect("Current VTL already initialized");

    Ok(())
}

pub fn hyperv_setup() -> Result<(), SvsmError> {
    // First, determine if this is a Hyper-V system.
    let is_hyperv = is_hyperv_hypervisor();
    IS_HYPERV
        .init(is_hyperv)
        .expect("Hyper-V support already initialized");

    if is_hyperv {
        // If this is the BSP, then configure hypercall pages.
        this_cpu().allocate_hypercall_pages()?;

        // Complete the work required to configure hypercalls.
        hyperv_setup_hypercalls()?;
    }

    Ok(())
}

/// # Safety
///
/// Hypercalls can have side-effects that include modifying memory, so
/// callers must be certain that any preconditions required for the safety
/// of a hypercall are met.
pub unsafe fn execute_hypercall(
    input_control: HvHypercallInput,
    hypercall_pages: &HypercallPagesGuard<'_>,
) -> HvHypercallOutput {
    let hypercall_va = u64::from(*HYPERV_HYPERCALL_CODE_PAGE);
    let mut output: u64;
    // SAFETY: inline assembly is required to invoke the hypercall.
    unsafe {
        asm!("callq *%rax",
             in("rax") hypercall_va,
             in("rcx") input_control.into_bits(),
             in("rdx") u64::from(hypercall_pages.input.paddr),
             in("r8") u64::from(hypercall_pages.output.paddr),
             lateout("rax") output,
             options(att_syntax));
    }
    HvHypercallOutput::from(output)
}

pub fn execute_host_hypercall(
    mut input_control: HvHypercallInput,
    hypercall_pages: &HypercallPagesGuard<'_>,
    func: fn(&mut X86GeneralRegs),
) -> HvHypercallOutput {
    let mut output: HvHypercallOutput;
    let mut regs: X86GeneralRegs = X86GeneralRegs::default();

    loop {
        // Configure the call registers based on the current state of the
        // call.
        regs.rcx = input_control.into_bits() as usize;
        regs.rdx = u64::from(hypercall_pages.input.paddr) as usize;
        regs.r8 = u64::from(hypercall_pages.output.paddr) as usize;

        // Issue the hypercall to the host.
        func(&mut regs);

        // If any status other than HV_STATUS_TIMEOUT is returned, then stop
        // the loop.
        output = HvHypercallOutput::from(regs.rax as u64);
        if output.status() != HV_STATUS_TIMEOUT {
            break;
        }

        // Continue processing from wherever the hypervisor left off.  The rep
        // start index isn't checked for validity, since it is only being used
        // as an input to the untrusted hypervisor. This applies to both simple
        // and rep hypercalls.
        input_control = input_control.with_start_index(output.count());
    }

    // If this is not a rep hypercall, then return the status directly, with
    // the element count zeroed out.
    if input_control.element_count() == 0 {
        return HvHypercallOutput::new().with_status(output.status());
    }
    // The output can be returned directly if the element count is reasonable,
    // i.e. if a successful call completed all elements or an unsuccessful call
    // completed fewer elements than were requested.
    if output.status() == HV_STATUS_SUCCESS {
        if output.count() == input_control.element_count() {
            return output;
        }
    } else if output.count() < input_control.element_count() {
        return output;
    }

    // If the output indicates success but the last rep was not completed,
    // then return failure instead.
    HvHypercallOutput::new().with_status(HV_STATUS_OPERATION_FAILED)
}

/// Dead code is allowed because the hypercall input logic doesn't recognize
/// that all fields are read when they are copied into the hypercall input
/// page.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default)]
struct HvInputGetVpRegister {
    partition_id: u64,
    vp_index: u32,
    input_vtl: hyperv::HvInputVtl,
    _rsvd: [u8; 3],
}

pub fn get_vp_register(name: hyperv::HvRegisterName) -> Result<u64, SvsmError> {
    let input_control = HvHypercallInput::new()
        .with_call_code(HvCallCode::GetVpRegister as u16)
        .with_element_count(1);

    let input_header = HvInputGetVpRegister {
        partition_id: HV_PARTITION_ID_SELF,
        vp_index: HV_VP_INDEX_SELF,
        input_vtl: hyperv::HvInputVtl::use_self(),
        ..Default::default()
    };

    let mut hypercall_pages = this_cpu().get_hypercall_pages();
    let mut input_page = hypercall_pages.hypercall_rep_input::<HvInputGetVpRegister, u32>();
    input_page.write_header(&input_header);
    input_page.write_rep(0, name as u32);

    // SAFETY: the GetVpRegisters hypercall does not write to any memory other
    // than the hypercall page, and does not consume memory that is not
    // included in the hypercall input.
    let call_output = unsafe { SVSM_PLATFORM.hypercall(input_control, &hypercall_pages) };
    let status = call_output.status();
    if status != 0 {
        return Err(HyperV(status));
    }

    let output_page = hypercall_pages.hypercall_output::<u64>(call_output);
    let reg = output_page.read(0);

    drop(hypercall_pages);

    Ok(reg)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct HvInputEnableVpVtl {
    partition_id: u64,
    vp_index: u32,
    vtl: u8,
    _rsvd: [u8; 3],
    context: hyperv::HvInitialVpContext,
}

fn enable_vp_vtl_hypercall(
    cpu: &PerCpu,
    vtl: u8,
    context: &HvInitialVpContext,
) -> Result<(), SvsmError> {
    let input_header = HvInputEnableVpVtl {
        partition_id: HV_PARTITION_ID_SELF,
        vtl,
        vp_index: cpu.get_cpu_index().try_into().unwrap(),
        context: *context,
        ..Default::default()
    };

    let input_control = HvHypercallInput::new().with_call_code(HvCallCode::EnableVpVtl as u16);

    let mut hypercall_pages = this_cpu().get_hypercall_pages();
    let mut input_page = hypercall_pages.hypercall_input::<HvInputEnableVpVtl>();
    input_page.write_header(&input_header);

    // SAFETY: the EnableVpVtl hypercall does not write to any memory and
    // does not consume memory that is not included in the hypercall input.
    let call_output = unsafe { SVSM_PLATFORM.hypercall(input_control, &hypercall_pages) };
    let status = call_output.status();

    if status != 0 {
        Err(HyperV(status))
    } else {
        Ok(())
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct HvInputStartVirtualProcessor {
    partition_id: u64,
    vp_index: u32,
    vtl: u8,
    _rsvd: [u8; 3],
    context: hyperv::HvInitialVpContext,
}

fn start_vp_hypercall(
    cpu: &PerCpu,
    vtl: u8,
    context: &HvInitialVpContext,
) -> Result<(), SvsmError> {
    let input_header = HvInputStartVirtualProcessor {
        partition_id: HV_PARTITION_ID_SELF,
        vtl,
        vp_index: cpu.get_cpu_index().try_into().unwrap(),
        context: *context,
        ..Default::default()
    };

    let input_control =
        HvHypercallInput::new().with_call_code(HvCallCode::StartVirtualProcessor as u16);

    let mut hypercall_pages = this_cpu().get_hypercall_pages();
    let mut input_page = hypercall_pages.hypercall_input::<HvInputStartVirtualProcessor>();
    input_page.write_header(&input_header);

    // SAFETY: the StartVp hypercall does not write to any memory and does not
    // consume memory that is not included in the hypercall input.
    let call_output = unsafe { SVSM_PLATFORM.hypercall(input_control, &hypercall_pages) };
    let status = call_output.status();

    if status != 0 {
        Err(HyperV(status))
    } else {
        Ok(())
    }
}

pub fn hyperv_start_cpu(cpu: &PerCpu, context: &HvInitialVpContext) -> Result<(), SvsmError> {
    // Enable the current VTL on the target CPU if the current VTL is not
    // VTL 0.
    let vtl = *CURRENT_VTL;
    if vtl != 0 {
        enable_vp_vtl_hypercall(cpu, vtl, context)?;
    }
    start_vp_hypercall(cpu, vtl, context)
}
