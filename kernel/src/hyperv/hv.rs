// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use crate::address::{PhysAddr, VirtAddr};
use crate::cpu::mem::unsafe_copy_bytes;
use crate::cpu::msr::write_msr;
use crate::cpu::percpu::{this_cpu, PerCpu};
use crate::cpu::{IrqGuard, X86GeneralRegs};
use crate::error::SvsmError;
use crate::error::SvsmError::HyperV;
use crate::hyperv;
use crate::hyperv::{HvInitialVpContext, HyperVMsr};
use crate::mm::alloc::allocate_pages;
use crate::mm::page_visibility::SharedBox;
use crate::mm::pagetable::PTEntryFlags;
use crate::mm::{virt_to_phys, SVSM_HYPERCALL_CODE_PAGE};
use crate::platform::SVSM_PLATFORM;
use crate::types::PAGE_SIZE;
use crate::utils::immut_after_init::ImmutAfterInitCell;

use core::arch::asm;
use core::cell::RefMut;
use core::marker::PhantomData;
use core::mem;
use core::mem::MaybeUninit;

use bitfield_struct::bitfield;
use zerocopy::{FromBytes, IntoBytes};

/// An raw, owned page in shared memory used for Hyper-V hypercalls.
#[derive(Debug)]
pub struct HypercallPage {
    // Shared page.
    page: SharedBox<[u8; PAGE_SIZE]>,
    // Physical address of the shared page.
    paddr: PhysAddr,
}

impl HypercallPage {
    /// Attempts to allocate a new shared hypercall page.
    pub fn try_new() -> Result<Self, SvsmError> {
        let page = SharedBox::<[u8; PAGE_SIZE]>::try_new_zeroed()?;
        let paddr = virt_to_phys(page.addr());
        Ok(Self { page, paddr })
    }

    /// Gets the virtual address of the shared page.
    fn vaddr(&self) -> VirtAddr {
        self.page.addr()
    }
}

/// A wrapper type to reinterpret an input hypercall page as a header
/// `H`, optionally followed by a number of instances of `T`.
///
/// `'a` is the lifetime of the borrow of the hypercall page from the
/// containing [`HypercallPagesGuard`], and `'b` is the lifetime of
/// the borrow of the pages into the [`PerCpu`].
#[derive(Debug)]
struct HypercallInput<'a, 'b, H, T> {
    page: &'a mut RefMut<'b, HypercallPage>,
    rep_count: usize,
    _phantom1: PhantomData<H>,
    _phantom2: PhantomData<T>,
}

impl<'a, 'b, H, T> HypercallInput<'a, 'b, H, T> {
    fn new(page: &'a mut RefMut<'b, HypercallPage>) -> Self {
        const { assert!(size_of::<H>() <= PAGE_SIZE) };
        Self {
            page,
            rep_count: 0,
            _phantom1: PhantomData,
            _phantom2: PhantomData,
        }
    }

    fn header(&self) -> *mut H {
        self.page.vaddr().as_mut_ptr()
    }

    fn write_header(&mut self, header: &H)
    where
        H: IntoBytes,
    {
        // SAFETY: the source pointer is a safe reference, and the safety of
        // the destination pointer was determined when the input object was
        // created.
        unsafe {
            unsafe_copy_bytes(header, self.header(), 1);
        }
    }

    fn new_rep(page: &'a mut RefMut<'b, HypercallPage>) -> Self {
        const { assert!(size_of::<H>() <= PAGE_SIZE) };
        const { assert!(size_of::<T>() != 0) };
        let rep_count = (PAGE_SIZE - mem::size_of::<H>()) / mem::size_of::<T>();
        Self {
            page,
            rep_count,
            _phantom1: PhantomData,
            _phantom2: PhantomData,
        }
    }

    fn write_rep(&mut self, index: usize, item: T)
    where
        T: IntoBytes,
    {
        assert!(index < self.rep_count);
        // SAFETY: the header pointer is valid and we bounds-check the
        // index.
        let dst = unsafe { self.header().add(1).cast::<T>().add(index) };
        // SAFETY: the source pointer is a safe reference, and the safety of
        // the destination pointer is guaranteed by the address calculation
        // at the time the input object was created, plus the bounds check
        // above.
        unsafe { unsafe_copy_bytes(&item, dst, 1) }
    }
}

/// A wrapper type to reinterpret an output hypercall page as a sequence
/// of a number of instances of a type `T`.
///
/// Refer to the documentation for [`HypercallInput`] for the meaning
/// of the `'a` and `'b` lifetimes.
#[derive(Debug)]
struct HypercallOutput<'a, 'b, T> {
    page: &'a RefMut<'b, HypercallPage>,
    rep_count: usize,
    _phantom: PhantomData<T>,
}

impl<'a, 'b, T> HypercallOutput<'a, 'b, T> {
    /// # Safety
    ///
    /// The caller must guarantee that `rep_count` instances of `T` fit
    /// within a single page.
    unsafe fn new(page: &'a RefMut<'b, HypercallPage>, rep_count: usize) -> Self {
        Self {
            page,
            rep_count,
            _phantom: PhantomData,
        }
    }

    fn array(&self) -> *const T {
        self.page.vaddr().as_ptr()
    }

    fn read(&self, index: usize) -> T
    where
        T: FromBytes,
    {
        assert!(index < self.rep_count);
        // SAFETY: the array pointer is valid and we bounds-check the
        // index
        let src = unsafe { self.array().add(index) };
        let mut item = MaybeUninit::<T>::uninit();

        // SAFETY: the source pointer is a safe reference, and the safety of
        // the destination pointer is guaranteed by the address calculation
        // at the time the input object was created, plus the bounds check
        // above.  The copy guarantees the initialization of the output object.
        unsafe {
            unsafe_copy_bytes(src, item.as_mut_ptr(), 1);
            item.assume_init()
        }
    }
}

/// A guard that holds an exclusive borrow of the Hyper-V hypercall pages.
/// This type is typically constructed from [`PerCpu::get_hypercall_pages`].
///
/// The type guarantees that no other piece of code attempts to modify
/// the hypercall pages. The pages remain usable until the structure is
/// dropped. Note that the hypercall pages are per-cpu, so the type does
/// not guard against concurrent users.
///
/// The type also includes helper methods to reinterpret the backing
/// pages as structured data, in order to read and write their contents.
#[derive(Debug)]
pub struct HypercallPagesGuard<'a> {
    pub input: RefMut<'a, HypercallPage>,
    pub output: RefMut<'a, HypercallPage>,
    _irq_guard: IrqGuard,
}

impl<'a> HypercallPagesGuard<'a> {
    /// Creates a new `HypercallPagesGuard` structure to describe a pair of
    /// input/output pages.
    ///
    /// This method is safe because [`HypercallPage`] guarantees by construction
    /// that the backing memory is valid and shared with the hypervisor. The type
    /// is wrapped in a [`RefMut`], meaning that there is a runtime guarantee that
    /// nobody else holds a reference to the same pages.
    pub fn new(page_ref: RefMut<'a, (HypercallPage, HypercallPage)>) -> Self {
        let (input, output) = RefMut::map_split(page_ref, |r| (&mut r.0, &mut r.1));
        Self {
            input,
            output,
            _irq_guard: IrqGuard::new(),
        }
    }

    /// Casts a hypercall input page into a header of type `H` and returns a
    /// reference to that header object.
    fn hypercall_input<'b, H>(&'b mut self) -> HypercallInput<'b, 'a, H, ()> {
        HypercallInput::new(&mut self.input)
    }

    /// Divides a hypercall input page into a header of type `H` and a slice
    /// of repeated elements of type `T` and returns a reference to each
    /// portion.
    fn hypercall_rep_input<'b, H, T>(&'b mut self) -> HypercallInput<'b, 'a, H, T> {
        HypercallInput::new_rep(&mut self.input)
    }

    /// Casts a hypercall output page into a slice of repeated elements of
    /// type `T` and returns a reference to that slice.
    fn hypercall_output<'b, T>(&'b self, output: HvHypercallOutput) -> HypercallOutput<'b, 'a, T> {
        // A non-REP hypercall is assumed to have a single output element.
        let output_count = output.count();
        let count: usize = if output_count != 0 {
            output_count as usize
        } else {
            1
        };
        assert!(count * size_of::<T>() <= PAGE_SIZE);
        // SAFETY: we've asserted that `count` instances of `T` fit in the
        // output page.
        unsafe { HypercallOutput::new(&self.output, count) }
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
#[derive(Clone, Copy, Debug, Default, IntoBytes)]
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
#[derive(Clone, Copy, Debug, Default, IntoBytes)]
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
#[derive(Clone, Copy, Debug, Default, IntoBytes)]
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
