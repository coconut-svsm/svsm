// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use super::apic::{ApicIcr, IcrDestFmt};
use super::cpuset::{AtomicCpuSet, CpuSet};
use super::idt::common::IPI_VECTOR;
use super::percpu::this_cpu;
use super::percpu::PERCPU_AREAS;
use super::TprGuard;
use crate::error::SvsmError;
use crate::platform::SVSM_PLATFORM;
use crate::types::{TPR_IPI, TPR_SYNCH};
use crate::utils::{ScopedMut, ScopedRef};

use core::cell::{Cell, UnsafeCell};
use core::mem;
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

/// This module implements inter-processor interrupt support, including the
/// ability to send and receive messages across CPUs.  Two types of IPI
/// messages are supported: multicast and unicast.  Sending a multicast IPI
/// will cause a message to be delivered to one or more CPUs as a shared
/// reference.  Sending a unicast IPI will cause a message to be delivered to a
/// single target as a mutable reference, permitting the receiving processor to
/// modify the contents of the message such that the sender of the message can
/// observe the response.  In all cases, the request to send a message will not
/// complete until all receiving CPUs have completed handling the request.
///
/// Multicast IPIs can be used to target a single CPU, an arbitrary set of
/// CPUs, or all CPUs (optionally including or excluding the sending CPU).
///
/// Sending an IPI requires the ability to raise TPR to TPR_SYNCH.  If the
/// current TPR is already above TPR_SYNCH, then the IPI request will panic.
///
/// Two traits support the delivery of IPI messages: `IpiMessage` and
/// `IpiMessageMut`.  Each of these traits requires an implementation of an
/// `invoke` method which will be called on every receiving CPU to handle
/// the message.  The `invoke` method will be called on every receving CPU,
/// including on the sending CPU if it is a selected target.  The `invoke`
/// method is always called with TPR equal to TPR_IPI.  TPR-sensitive locks
/// may not be used unless they are designed to be held at TPR_IPI.  TPR_IPI
/// is higher than TPR_SYNCH, so it is not possible to send an IPI from an
/// IPI handler.

/// The `IpiTarget` enum describes the set of CPUs that should receive a
/// multicast IPI.  There are four variants.
/// * `Single` indicates a single CPU, described by CPU index (*not* APIC ID).
/// * `Multiple` contains a `CpuSet`, which is a bitmap of multiple CPUs
///   selected by CPU index.
/// * `AllButSelf` indicates all CPUs other than the sending processor.
/// * `All` indicates all CPUs.
#[derive(Clone, Copy, Debug)]
pub enum IpiTarget {
    Single(usize),
    Multiple(CpuSet),
    AllButSelf,
    All,
}

/// # Safety
/// This trait implements a method to copy IPI message contents into a shared
/// buffer.  If that serialization is performed incorrectly, then IPI message
/// receipt will be unsound because the message may contain incorrect pointers
/// and references that refer to invalid memory - or memory that belongs to
/// another owner.  All implementations of this trait must verify that the
/// copy routine correctly copies all data and resolves all references within
/// the copied data.
pub unsafe trait IpiMessage {
    /// All IPI messages must be copied into a shared IPI buffer since stack
    /// locals are not visible across CPU/task contexts.  This function must
    /// perform a deep copy of the contents of the source buffer into the
    /// shared destination buffer.
    ///
    /// Arguments:
    ///
    /// *`src`: A pointer to the input message.
    /// *`buffer`: A byte slice in shared memory which will be the target of the copy.
    fn copy_to_shared(&self, buffer: &mut [u8])
    where
        Self: Sized,
    {
        let size = mem::size_of::<Self>();
        assert!(size <= buffer.len());
        // SAFETY: the target buffer is known not to overlap the `self` object,
        // and the assertion above proves that the target buffer is large
        // enough to receive a copy of the object.
        unsafe {
            ptr::copy_nonoverlapping(ptr::from_ref(self) as *const u8, buffer.as_mut_ptr(), size);
        }
    }

    /// Invokes the IPI handler for the message.
    fn invoke(&self);
}

/// # Safety
/// This trait implements a method to copy IPI message contents into a shared
/// buffer.  If that serialization is performed incorrectly, then IPI message
/// receipt will be unsound because the message may contain incorrect pointers
/// and references that refer to invalid memory - or memory that belongs to
/// another owner.  The same applies to the method of this trait that copies
/// modified IPI message contents back to the caller's IPI message structure.
/// All implementations of this trait must verify that the copy routines
/// correctly copy all data and resolve all references within the copied data.
pub unsafe trait IpiMessageMut {
    /// All IPI messages must be copied into a shared IPI buffer since stack
    /// locals are not visible across CPU/task contexts.  This function must
    /// perform a deep copy of the contents of the source buffer into the
    /// shared destination buffer.
    ///
    /// Arguments:
    ///
    /// *`src`: A pointer to the input message.
    /// *`buffer`: A byte slice in shared memory which will be the target of the copy.
    fn copy_to_shared(&self, buffer: &mut [u8])
    where
        Self: Sized,
    {
        let size = mem::size_of::<Self>();
        assert!(size <= buffer.len());
        // SAFETY: the target buffer is known not to overlap the `self` object,
        // and the assertion above proves that the target buffer is large
        // enough to receive a copy of the object.
        unsafe {
            ptr::copy_nonoverlapping(ptr::from_ref(self) as *const u8, buffer.as_mut_ptr(), size);
        }
    }

    /// Copies the result of the unicast IPI back into the original message
    /// buffer.
    ///
    /// Arguments:
    ///
    /// *`src`: A pointer to the input message.
    /// *`buffer`: A byte slice in shared memory which will be the target of the copy.
    fn copy_from_shared(&mut self, shared_buffer: &Self)
    where
        Self: Sized,
    {
        // SAFETY: the contents of object are to be moved from the shared
        // buffer back to the caller's object, so no drop can be permitted.
        // A pointer copy is used to perofrm this move.
        unsafe {
            ptr::copy_nonoverlapping(ptr::from_ref(shared_buffer), ptr::from_mut(self), 1);
        }
    }

    fn invoke(&mut self);
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum IpiRequest {
    IpiMut,
    IpiShared,
}

#[derive(Debug)]
pub struct IpiBoard {
    // The number of CPUs that have yet to complete the request.
    pending: AtomicUsize,

    // The request description.
    request: Cell<MaybeUninit<IpiRequest>>,

    // Space to store the IPI message being sent.
    message: UnsafeCell<MaybeUninit<[u8; 1024]>>,

    // A function pointer that will handle the IPI on the receiving CPU.
    handler: Cell<MaybeUninit<unsafe fn(*const ())>>,
}

// The IpiHelper trait exists to abstract the difference between use of
// IpiMessage and IpiMessageMut in the IPI send and receive logic.
pub trait IpiHelper {
    fn request_type(&self) -> IpiRequest;
    fn copy_to_shared(&self, shared_buffer: &mut [u8]);
    fn copy_from_shared(&mut self, shared_buffer: *const ());
    fn get_invoke_routine(&self) -> unsafe fn(*const ());
}

#[derive(Debug)]
pub struct IpiHelperShared<'a, T: IpiMessage> {
    message: &'a T,
}

impl<'a, T: IpiMessage> IpiHelperShared<'a, T> {
    pub fn new(message: &'a T) -> Self {
        Self { message }
    }

    // SAFETY: The IPI logic is guaranteed to call this function only when
    // passing a pointer to type `T`.
    unsafe fn invoke(message: *const ()) {
        // SAFETY: The calling IPI logic has guaranteed the correctness of
        // the input pointer.
        let msg = unsafe { ScopedRef::new(message as *const T).unwrap() };
        msg.invoke();
    }
}

impl<T: IpiMessage> IpiHelper for IpiHelperShared<'_, T> {
    fn request_type(&self) -> IpiRequest {
        IpiRequest::IpiShared
    }

    fn copy_to_shared(&self, shared_buffer: &mut [u8]) {
        self.message.copy_to_shared(shared_buffer);
    }

    fn copy_from_shared(&mut self, _shared_buffer: *const ()) {
        // A shared IPI does not copy back any results.
    }

    // SAFETY: The IPI logic is guaranteed to call this function only when
    // passing a pointer to type `T`.
    fn get_invoke_routine(&self) -> unsafe fn(*const ()) {
        Self::invoke
    }
}

#[derive(Debug)]
pub struct IpiHelperMut<'a, T: IpiMessageMut> {
    message: &'a mut T,
}

impl<'a, T: IpiMessageMut> IpiHelperMut<'a, T> {
    pub fn new(message: &'a mut T) -> Self {
        Self { message }
    }

    // SAFETY: The IPI logic is guaranteed to call this function only when
    // passing a pointer to type `T`.
    unsafe fn invoke(message: *const ()) {
        // SAFETY: The calling IPI logic has guaranteed the correctness of
        // the input pointer.
        let mut msg = unsafe { ScopedMut::new(message as *mut T).unwrap() };
        msg.invoke();
    }
}

impl<T: IpiMessageMut> IpiHelper for IpiHelperMut<'_, T> {
    fn request_type(&self) -> IpiRequest {
        IpiRequest::IpiMut
    }

    fn copy_to_shared(&self, shared_buffer: &mut [u8]) {
        self.message.copy_to_shared(shared_buffer);
    }

    fn copy_from_shared(&mut self, shared_buffer: *const ()) {
        // SAFETY: the IPI logic guarantees that the shared buffer will contain
        // an object of type `T`.
        unsafe {
            let shared = shared_buffer as *const T;
            self.message.copy_from_shared(shared.as_ref().unwrap());
        }
    }

    fn get_invoke_routine(&self) -> unsafe fn(*const ()) {
        Self::invoke
    }
}

impl Default for IpiBoard {
    fn default() -> Self {
        Self {
            request: Cell::new(MaybeUninit::zeroed()),
            pending: AtomicUsize::new(0),
            message: UnsafeCell::new(MaybeUninit::uninit()),
            handler: Cell::new(MaybeUninit::uninit()),
        }
    }
}

// This function is the IPI workhorse.  As input, it takes an IpiHelper which
// is the interface to the correct IPI message trait implementation.  This
// is consumed as a dynamic dispatch trait to avoid explosion due to multiple
// generic message implementations.
pub fn send_ipi(
    mut target_set: IpiTarget,
    sender_cpu_index: usize,
    ipi_helper: &mut dyn IpiHelper,
    ipi_board: &IpiBoard,
) {
    // Raise TPR to synch level to prevent reentrant attempts to send an IPI.
    let tpr_guard = TprGuard::raise(TPR_SYNCH);

    // Initialize the IPI board to describe this request.  Since no request
    // can be outstanding right now, the pending count must be zero, and
    // there can be no other CPUs that are have taken references to the IPI
    // board.
    assert_eq!(ipi_board.pending.load(Ordering::Relaxed), 0);
    ipi_board
        .request
        .set(MaybeUninit::new(ipi_helper.request_type()));
    ipi_board
        .handler
        .set(MaybeUninit::new(ipi_helper.get_invoke_routine()));
    // SAFETY: the IPI board is known to be in an uninitialized state and
    // because the request mask on the target CPUs have not yet been updated
    // to indicate a pending message from this CPU, there are no other threads
    // that could be examining the IPI board at this time.  It can safely
    // be populated with a copy of the message.
    unsafe {
        let cell = &mut *ipi_board.message.get();
        let message_buf = &mut *cell.as_mut_ptr();
        ipi_helper.copy_to_shared(message_buf);
    }

    // Enumerate all CPUs in the target set to advise that an IPI message has
    // been posted.
    let mut include_self = false;
    let mut send_interrupt = false;
    match target_set {
        IpiTarget::Single(cpu_index) => {
            if cpu_index == sender_cpu_index {
                include_self = true;
            } else {
                ipi_board.pending.store(1, Ordering::Relaxed);
                PERCPU_AREAS
                    .get_by_cpu_index(cpu_index)
                    .ipi_from(sender_cpu_index);
                send_interrupt = true;
            }
        }
        IpiTarget::Multiple(ref mut cpu_set) => {
            for cpu_index in cpu_set.iter() {
                if cpu_index == sender_cpu_index {
                    include_self = true;
                } else {
                    ipi_board.pending.fetch_add(1, Ordering::Relaxed);
                    PERCPU_AREAS
                        .get_by_cpu_index(cpu_index)
                        .ipi_from(sender_cpu_index);
                    send_interrupt = true;
                }
            }
            if include_self {
                cpu_set.remove(sender_cpu_index);
            }
        }
        _ => {
            for cpu in PERCPU_AREAS.iter() {
                ipi_board.pending.fetch_add(1, Ordering::Relaxed);
                cpu.as_cpu_ref().ipi_from(sender_cpu_index);
            }
            send_interrupt = true;

            // Remove the current CPU from the target set and completion
            // calculation, since no interrupt is required to ensure that
            // IPI handlng can be performed locally.
            ipi_board.pending.fetch_sub(1, Ordering::Relaxed);
            target_set = IpiTarget::AllButSelf;

            // Only include the current CPU if requested.
            if let IpiTarget::All = target_set {
                include_self = true;
            }
        }
    }

    // Send the IPI message.
    if send_interrupt {
        send_ipi_irq(target_set).expect("Failed to post IPI interrupt");
    }

    // If sending to the current processor, then handle the message locally.
    if include_self {
        // Raise TPR to IPI level for consistency with IPI interrupt handling.
        let ipi_tpr_guard = TprGuard::raise(TPR_IPI);

        // SAFETY: the local IPI board is known to be in the correct state
        // for processing.
        unsafe {
            receive_single_ipi(ipi_board);
        }
        drop(ipi_tpr_guard);
    }

    // Wait until all other CPUs have completed their processing of the
    // message.  This is required to ensure that no other threads can be
    // examining the IPI board.
    //
    // Note that because the current TPR is TPR_SYNCH, which is lower than
    // TPR_IPI, any other IPIs that arrive while waiting here will interrupt
    // this spin loop and will be processed correctly.
    while ipi_board.pending.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
    }

    // Perform any result copy required by the IPI.
    ipi_helper.copy_from_shared(ipi_board.message.get() as *const ());

    drop(tpr_guard);
}

fn send_single_ipi_irq(cpu_index: usize, icr: ApicIcr) -> Result<(), SvsmError> {
    let cpu = PERCPU_AREAS.get_by_cpu_index(cpu_index);
    SVSM_PLATFORM.post_irq(icr.with_destination(cpu.apic_id()).into())
}

fn send_ipi_irq(target_set: IpiTarget) -> Result<(), SvsmError> {
    let icr = ApicIcr::new().with_vector(IPI_VECTOR as u8);
    match target_set {
        IpiTarget::Single(cpu_index) => send_single_ipi_irq(cpu_index, icr)?,
        IpiTarget::Multiple(cpu_set) => {
            for cpu_index in cpu_set.iter() {
                send_single_ipi_irq(cpu_index, icr)?;
            }
        }
        IpiTarget::AllButSelf => SVSM_PLATFORM.post_irq(
            icr.with_destination_shorthand(IcrDestFmt::AllButSelf)
                .into(),
        )?,
        IpiTarget::All => SVSM_PLATFORM.post_irq(
            icr.with_destination_shorthand(IcrDestFmt::AllWithSelf)
                .into(),
        )?,
    }
    Ok(())
}

/// # Safety
/// The caller must take responsibility to ensure that the message pointer in
/// the request is valid.  This is normally ensured by assuming the lifetime
/// of the request pointer is protected by the lifetime of the bulletin board
/// that posts it.
unsafe fn receive_single_ipi(board: &IpiBoard) {
    // SAFETY: since the caller has indicated that this IPI board is valid,
    // all fields of the IPI board can be assumed to have the correct semantics
    // and can be accessed via raw pointers.
    unsafe {
        let request = board.request.get().assume_init();
        let message = board.message.get() as *const ();
        match request {
            IpiRequest::IpiShared => {
                let handler = board.handler.get().assume_init();
                handler(message);
            }
            IpiRequest::IpiMut => {
                // SAFETY: the sending CPU has guaranteed that no other CPU
                // can be looking at this IPI board, and the sending CPU is
                // also spinning while waiting for this request to be
                // processed.  Since no other thread can be examining this
                // data, it can safely be viewed through a mutable reference.
                let handler = mem::transmute::<unsafe fn(*const ()), unsafe fn(*mut ())>(
                    board.handler.get().assume_init(),
                );
                handler(message as *mut ());
            }
        }
    }
}

pub fn handle_ipi_interrupt(request_set: &AtomicCpuSet) {
    // Enumerate all CPUs in the request set and process the request identified
    // by each.
    for cpu_index in request_set.iter(Ordering::Acquire) {
        // Handle the request posted on the bulletin board of the requesting
        // CPU.
        let cpu = PERCPU_AREAS.get_by_cpu_index(cpu_index);

        // SAFETY: The IPI board is known to be valid since the sending CPU
        // marked it as valid in this CPU's request bitmap.  The IPI board
        // is guaranteed to remain valid until the pending count is
        // decremented.
        unsafe {
            let ipi_board = cpu.ipi_board();
            receive_single_ipi(cpu.ipi_board());

            // Now that the request has been handled, decrement the count of
            // pending requests on the sender's bulletin board.  The IPI
            // board may cease to be valid as soon as this decrement
            // completes.
            ipi_board.pending.fetch_sub(1, Ordering::Release);
        }
    }
}

/// Sends an IPI message to multiple CPUs.
///
/// # Safety
/// The IPI message must NOT contain any references to data unless that
/// data is known to be in memory that is visible across CPUs/tasks.
/// Otherwise, the recipient could attempt to access a pointer that is
/// invalid in the target context, or - worse - points to completely
/// incorrect data in the target context.
///
/// # Arguments
///
/// * `target_set` - The set of CPUs to which to send the IPI.
/// * `ipi_message` - The message to send.
pub fn send_multicast_ipi<M: IpiMessage>(target_set: IpiTarget, ipi_message: &M) {
    this_cpu().send_multicast_ipi(target_set, ipi_message);
}

/// Sends an IPI message to a single CPU.  Because only a single CPU can
/// receive the message, the message object can be mutable.
///
/// # Arguments
///
/// * `cpu_index` - The index of the CPU to receive the message.
/// * `ipi_message` - The message to send.
///
/// # Returns
///
/// The response message generated by the IPI recipient.
pub fn send_unicast_ipi<M: IpiMessageMut>(cpu_index: usize, ipi_message: &mut M) {
    this_cpu().send_unicast_ipi(cpu_index, ipi_message);
}

#[cfg(test)]
mod tests {
    use crate::cpu::ipi::*;

    #[derive(Copy, Clone, Debug)]
    struct TestIpi {
        value: usize,
    }

    /// # Safety
    /// The test IPI method has no references and can safely use the default
    /// copy implementations from the IPI message traits.
    unsafe impl IpiMessage for TestIpi {
        fn invoke(&self) {
            assert_eq!(self.value, 4);
        }
    }

    /// # Safety
    /// The test IPI method has no references and can safely use the default
    /// copy implementations from the IPI message traits.
    unsafe impl IpiMessageMut for TestIpi {
        fn invoke(&mut self) {
            self.value += 1;
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_ipi() {
        // IPI testing is only possible on platforms that support SVSM
        // interrupts.
        if SVSM_PLATFORM.use_interrupts() {
            let message = TestIpi { value: 4 };
            send_multicast_ipi(IpiTarget::All, &message);
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_mut_ipi() {
        // IPI testing is only possible on platforms that support SVSM
        // interrupts.
        if SVSM_PLATFORM.use_interrupts() {
            let mut message = TestIpi { value: 4 };
            send_unicast_ipi(0, &mut message);
            assert_eq!(message.value, 5);
        }
    }
}
