use cpuarch::vmsa::VMSA;
use igvm_defs::PAGE_SIZE_4K;
use core::ffi::CStr;
use core::str;
<<<<<<< HEAD
use crate::{address::VirtAddr, cpu::{cpuid::{cpuid_table_raw, CpuidResult}, percpu::{this_cpu, this_cpu_unsafe}}, map_paddr, mm::{PerCPUPageMappingGuard, PAGE_SIZE}, paddr_as_slice, process_manager::{process::{ProcessID, TrustedProcess, PROCESS_STORE}, process_memory::allocate_page, process_paging::{GraminePalProtFlags, ProcessPageFlags, ProcessPageTableRef}}, protocols::{errors::SvsmReqError, RequestParams}};
use crate::process_manager::process_paging::TP_LIBOS_START_VADDR;
=======
use crate::{address::VirtAddr, cpu::{cpuid::{cpuid_table_raw, CpuidResult}, percpu::{this_cpu, this_cpu_unsafe}}, map_paddr, mm::{PerCPUPageMappingGuard, PAGE_SIZE}, paddr_as_slice, process_manager::{process::{ProcessID, TrustedProcess, PROCESS_STORE}, process_memory::allocate_page, process_paging::{ProcessPageFlags, ProcessPageTableRef}}, protocols::{errors::SvsmReqError, RequestParams}, vaddr_as_u64_slice};
>>>>>>> 145f83e (Add result call for Trustlet)

use crate::vaddr_as_slice; 
use crate::types::PageSize;
use crate::sev::RMPFlags;
use crate::sev::rmp_adjust;
use core::arch::asm;

const TRUSTLET_VMPL: u64 = 1;

pub trait ProcessRuntime {
    fn handle_process_request(&mut self) -> bool;
    fn pal_svsm_virt_alloc(&mut self) -> bool;
    fn pal_svsm_debug_print(&mut self) -> bool;
    fn pal_svsm_fail(&mut self) -> bool;
    fn pal_svsm_exit(&mut self) -> bool;
    fn pal_svsm_map(&mut self) -> bool;
    fn pal_svsm_mprotect(&mut self) -> bool;
    fn pal_svsm_print_info(&mut self) -> bool;
    fn pal_svsm_set_tcb(&mut self) -> bool;
    fn pal_svsm_cpuid(&mut self) -> bool;
    fn pal_svsm_get_result(&mut self) -> bool;
}

#[derive(Debug)]
pub struct PALContext {
    process: &'static mut TrustedProcess,
    vmsa: &'static mut VMSA,
    string_buf: [u8;256],
    string_pos: usize,
    result_addr: u64,
    result_size: u64,
    guest_page_table: u64,
    return_value: u64,
}

pub fn invoke_trustlet(params: &mut RequestParams) -> Result<(), SvsmReqError> {

    log::info!("Invoking Trustlet");

    let id = params.rcx;
    let guest_data = params.r8;
    let guest_data_size = params.r9;
    let guest_page_table = params.rdx;
    let (invoke_data, range) = ProcessPageTableRef::copy_data_from_guest(guest_data, guest_data_size, guest_page_table);
    let invoke_data_struct = vaddr_as_u64_slice!(invoke_data);

    let function_arg = invoke_data_struct[0];
    let function_arg_size = invoke_data_struct[2];

    let result_addr = invoke_data_struct[1];
    let result_size = invoke_data_struct[3];


    let trustlet = PROCESS_STORE.get(ProcessID(id.try_into().unwrap()));

    // Getting the current processes VMSA
    let vmsa_paddr = trustlet.context.vmsa;
    let vmsa_mapping = PerCPUPageMappingGuard::create_4k(trustlet.context.vmsa).unwrap();
    let vmsa: &mut VMSA = unsafe { vmsa_mapping.virt_addr().as_mut_ptr::<VMSA>().as_mut().unwrap() };

    let apic_id = this_cpu().get_apic_id();

    let mut string_buf: [u8;256] = [0;256];
    let mut string_pos: usize = 0;
    let sev_features = trustlet.context.sev_features;

    trustlet.context.channel.copy_into(function_arg, guest_page_table, function_arg_size as usize);

    let mut rc = PALContext{
        process: trustlet,
        vmsa,
        string_buf,
        string_pos,
        result_addr,
        result_size,
        guest_page_table,
        return_value: 1,
    };

    // Execution loop of the trustlet
    // Currently the trustlet runs to completion
    loop {
        unsafe {(*(*this_cpu_unsafe()).ghcb).ap_create(vmsa_paddr,
                                                       u64::from(apic_id),
                                                       TRUSTLET_VMPL,
                                                       sev_features).unwrap()}
        if !rc.handle_process_request() {
            break;
        }
    }
<<<<<<< HEAD
=======

    params.rcx = rc.return_value;

>>>>>>> 145f83e (Add result call for Trustlet)
    Ok(())
}

impl ProcessRuntime for PALContext  {

    /// Handle request from the trustlet
    /// 
    /// CPUID instructions in a trustlet (VMPL1) results in control being passed to the SVSM
    /// We use this mechanism to implement monitor-call from the trustlet
    /// We use some part of (unused) cpuid leaf range for monitor calls
    /// Otherwise treat it as normal cpuid request and return the result
    /// 
    /// Monitor call arguments are passed in the trustlet's registers
    /// * rax: Monitor call code / cpuid leaf
    /// * others: arguments to the monitor call (depends on the call)
    fn handle_process_request(&mut self) -> bool {
        let vmsa = &mut self.vmsa;
        let rax = vmsa.rax;
        let rip = vmsa.rip;

        // Advance the trustlet's rip for the next execution (cpuid instruction is 2 bytes)
        vmsa.rip += 2;

        match rax {
            0..=23 | 0x80000000..=0x80000021 => {
                return self.pal_svsm_cpuid();
            }
            0x4FFFFFFF => {
                return self.pal_svsm_fail();
            }
            0x4FFFFFFE => {
                return self.pal_svsm_exit();
            }
            0x4FFFFFFD => {
                return self.pal_svsm_debug_print();
            }
            0x4FFFFFFC => {
                return self.pal_svsm_virt_alloc();
            }
            0x4FFFFFFB => {
                return self.pal_svsm_map();
            }
            0x4FFFFFFA => {
                return self.pal_svsm_set_tcb();
            }
            0x4FFFFFF9 => {
                return self.pal_svsm_mprotect();
            }
            0x4FFFFFF8 => {
                return self.pal_svsm_get_result();
            }
            99 => {
                let c = vmsa.rbx;
                log::info!("{}", c);

                let     c_str = core::char::from_digit(c as u32, 10).unwrap();
                log::info!("{}",c_str);
                return true
            }
            100 => {
                return self.pal_svsm_print_info();
            }
            _ => {
                log::info!("Unknown request code: {} (rip={:x})", rax, rip);
                return false;
            }

        }
       
    }

    /// Handle CPUID instruction from the trustlet
    /// 
    /// Register arguments:
    /// * rax: cpuid leaf
    /// * rcx: subleaf (if applicable)
    /// 
    /// Return:
    /// * rax: eax value of the cpuid result
    /// * rbx: ebx value of the cpuid result
    /// * rcx: ecx value of the cpuid result
    /// * rdx: edx value of the cpuid result
    fn pal_svsm_cpuid(&mut self) -> bool {
        let eax =  self.vmsa.rax as u32;
        let eax_tmp = self.vmsa.rax;
        let ecx_tmp = self.vmsa.rcx;
        // Some cpuid leafs have subleaf (ecx) and some don't
        // for the ones that don't we set ecx to 0 (otherwise CPUID table lookup fails)
        let ecx = match eax {
            4 | 7 | 0xb | 0xd | 0xf|
            0x10 | 0x12 | 0x14 | 0x17 |
            0x18 | 0x1d | 0x1e | 0x1f |
            0x24 | 0x8000001d => {
                self.vmsa.rcx as u32
            }
            _ => 0
        };

        // NOTE: we must consult the cpuid table or make explict VMGEXIT, otherwise we'll get another #VC
        let res = match cpuid_table_raw(eax, ecx, 0, 0){
            Some(r) => r,
            None => CpuidResult{eax: 0,ebx: 0, ecx: 0, edx: 0}
        };
        self.vmsa.rax = res.eax as u64;
        self.vmsa.rbx = res.ebx as u64;
        self.vmsa.rcx = res.ecx as u64;
        self.vmsa.rdx = res.edx as u64;
        return true;
    }

    /// Inidicated that results are ready
    ///
    /// Return:
    /// Sets the trustlet return value to 0
    /// Copies the reuslts into the provided buffer
    fn pal_svsm_get_result(&mut self) -> bool {
        self.process.context.channel.copy_out(
            self.result_addr,
            self.guest_page_table,
            self.result_size as usize);
        self.return_value = 0;
        false
    }




    /// Allocate virtual memory in the trustlet's page table
    /// 
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFFC)
    /// * rbx: trustlet's virtual address to allocate
    /// * rcx: size of memory to allocate
    /// * rdx: flags (GraminePalProtFlags)
    /// 
    /// Retrun:
    /// * rcx: 0 on success, -1 on failure
    fn pal_svsm_virt_alloc(&mut self) -> bool {

        // Getting the Page Table of the current Trustlet being executed
        let page_table = self.vmsa.cr3;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);

        let addr = self.vmsa.rbx;
        let mut size = self.vmsa.rcx;
        let flags = self.vmsa.rdx;

        // Check if size is a multiple of pages
        if size % 4096 != 0 {
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return true;
        }

        // Check if address starts at page boundary
        if addr % 4096 != 0 {
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return true;
        }
        let mut page_flags = ProcessPageFlags::data();
        if flags & 0x2 == 0x2 {
            page_flags = page_flags | ProcessPageFlags::WRITABLE;
        }
        //log::info!("Trying to allocate: {:#?}, {} {:?}", addr, size,page_flags);
        page_table_ref.add_pages(VirtAddr::from(addr), size / 4096, page_flags);

        //log::info!("Allocated Memory");
        self.vmsa.rcx = u64::from_ne_bytes((0i64).to_ne_bytes());

        true
    }

    /// Handle a PAL error
    /// 
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFFF)
    /// * rbx: error string address
    /// * rcx: error number
    /// 
    /// Return:
    /// * no return to the trustlet (exit the trustlet)
    fn pal_svsm_fail(&mut self) -> bool{
        // PAL reports error, exit the trustlet

        let page_table = self.vmsa.cr3;
        let string = self.vmsa.rbx;
        let errno = self.vmsa.rcx;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);

        let string_address = string & !0xFFF;
        let string_phys_address = page_table_ref.get_page(VirtAddr::from(string_address));
        let (_mapping, string_mapping) = map_paddr!(string_phys_address);
        let c_string: *const i8 = unsafe {{ string_mapping.as_ptr::<i8>() }.offset((string & 0xFFF).try_into().unwrap())};
        let s = unsafe { CStr::from_ptr(c_string) };

        log::info!(" [Trustlet] PAL Error: {} {}",s.to_str().unwrap(), errno);
        false
    }

    /// Exit the trustlet
    /// 
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFFE)
    /// * rbx: exit code
    /// 
    /// Return:
    /// * no return to the trustlet (exit the trustlet)
    fn pal_svsm_exit(&mut self) -> bool{
        // PAL exits, exit the trustlet
        let exit_code = self.vmsa.rbx;
        log::info!(" [Trustlet] Exit with Status Code: {}", exit_code);
        false
    }

    /// Print debug message from the trustlet
    /// 
    /// This function expects that the trustlet calls this function with each character,
    /// and the final character is 0
    /// 
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFFD)
    /// * rbx: character to print
    /// 
    /// Return:
    /// * no return value
    fn pal_svsm_debug_print(&mut self) -> bool {
        let c = self.vmsa.rbx;
        if self.string_pos < 255{
            self.string_buf[self.string_pos] = c as u8;
            self.string_pos += 1;
        } else {
            log::info!("Trustlet Debug Message to long");
            self.string_pos = 0;
            self.string_buf = [0;256];
        }
        if c == 0 {
            let debug_string = str::from_utf8(&self.string_buf).unwrap();
            log::info!(" [Trustlet] {}", debug_string);
            self.string_pos = 0;
            self.string_buf = [0;256];
        }
        true
    }

    /// Map a file into the trustlet's memory space
    /// 
    /// FIXME: For now, this functions only supports mapping the libos file into the specified address.
    /// (this works because that is the only callee of this function at the moment)
    /// As the monitor loads the libos file into the predefined address (TP_LIBOS_START_VADDR) at the start,
    /// this functions copy data from that region and create a new page table entry.
    /// 
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFFB)
    /// * rbx: virtual address to map
    /// * rcx: size of memory to map
    /// * rdx: flags (GraminePalProtFlags)
    /// * r8: file descriptor (unused)
    /// * r9: offset
    /// 
    /// Return:
    /// * rcx: 0 on success, -1 on failure
    fn pal_svsm_map(&mut self) -> bool {
        let addr = self.vmsa.rbx;
        let size = self.vmsa.rcx;
        let flags = self.vmsa.rdx;
        let fd = self.vmsa.r8;
        let offset = self.vmsa.r9;

        log::info!("{:#}, {}", addr, size);

        let page_table = self.vmsa.cr3;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);

        if size % 4096 != 0 {
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return false;
        }
        let num_pages = size / 4096;

        let vaddr = VirtAddr::from(addr);
        let s_vaddr = VirtAddr::from(TP_LIBOS_START_VADDR);

        let writable = (flags & GraminePalProtFlags::WRITE.bits()) != 0;
        let executable = (flags & GraminePalProtFlags::EXEC.bits()) != 0;
        let writecopy = (flags & GraminePalProtFlags::WRITECOPY.bits()) != 0;
        let mut flags = ProcessPageFlags::PRESENT | ProcessPageFlags::USER_ACCESSIBLE | ProcessPageFlags::ACCESSED;
        if writable || writecopy {
            flags |= ProcessPageFlags::WRITABLE;
        }
        if !executable {
            flags |= ProcessPageFlags::NO_EXECUTE;
        }

        for i in 0..num_pages {
            let t = page_table_ref.virt_to_phys(s_vaddr + ((i * PAGE_SIZE_4K) as usize) + (offset as usize));
            //log::info!("{:#x}, {:#x}, {:#} {:#?}",s_vaddr,offset, s_vaddr + ((i * PAGE_SIZE_4K) as usize) + (offset as usize), t);
            if writecopy {
                // FIXME: for now we do not support CoW, so copy the page at this point
                let (_old_mapping, old_page_mapped) = paddr_as_slice!(t);
                let new_page = allocate_page();
                let (mapping, new_page_mapped) = paddr_as_slice!(new_page);
                rmp_adjust(mapping.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX , PageSize::Regular).unwrap();
                for i in 0..512 {
                   new_page_mapped[i] = old_page_mapped[i];
                }
                page_table_ref.map_4k_page(vaddr + (i* PAGE_SIZE_4K).try_into().unwrap(), new_page, flags);

                //log::info!("Copy Mapping Virt:{:#x} Phys:{:#x} to Virt:{:#x} Phys:{:#x}",
                //           s_vaddr + ((i * PAGE_SIZE_4K) as usize) + (offset as usize),
                //           t,
                //           vaddr + ((i*PAGE_SIZE_4K) as usize),
                //           new_page,
                //);

            } else {
                page_table_ref.map_4k_page(vaddr + (i * PAGE_SIZE_4K).try_into().unwrap(), t, flags);

                let t2 = page_table_ref.virt_to_phys(vaddr + ((i * PAGE_SIZE_4K) as usize) );

                //log::info!("Mapping Virt:{:#x} Phys:{:#x} to Virt:{:#x} Phys:{:#x}",
                //s_vaddr + ((i * PAGE_SIZE_4K) as usize) + (offset as usize),
                //           t,
                //           vaddr + ((i*PAGE_SIZE_4K) as usize),
                //           t2
                //);
                if t != t2 {
                    panic!("Address mapping failed");
                }
            }

        }

        self.vmsa.rcx = u64::from_ne_bytes((0i64).to_ne_bytes());
        return true;
    }

    /// Update the trusted process' page entry permissions
    /// 
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFF9)
    /// * rbx: virtual address
    /// * rcx: size of memory to update
    /// * rdx: flags (GraminePalProtFlags)
    /// 
    /// Return:
    /// * rcx: 0 on success, -1 on failure
    fn pal_svsm_mprotect(&mut self) -> bool {
        let addr = self.vmsa.rbx;
        let size = self.vmsa.rcx;
        let flags = self.vmsa.rdx;

        // log::info!("svsm_mprotect: addr={:#}, size={}, flags={}", addr, size, flags);

        let process_page_table = self.vmsa.cr3;
        let mut process_page_table_ref = ProcessPageTableRef::default();
        process_page_table_ref.set_external_table(process_page_table);

        let offset = addr & 0xFFF;
        let page_num = (offset + size + 4095) / PAGE_SIZE_4K;
        let aligned_addr = addr & !0xFFF;
        let vaddr = VirtAddr::from(aligned_addr);

        let readbable = flags & GraminePalProtFlags::READ.bits() != 0;
        let writable = flags & GraminePalProtFlags::WRITE.bits() != 0;
        let executable = flags & GraminePalProtFlags::EXEC.bits() != 0;
        let writecopy = flags & GraminePalProtFlags::WRITECOPY.bits() != 0;

        // FIXME: this walks the page table every time. we can optimize this by updating entries while walking
        for i in 0..page_num {
            let target = vaddr + (i* PAGE_SIZE_4K).try_into().unwrap();
            process_page_table_ref.change_attr(target, readbable, writable, executable, writecopy);
        }

        return true;
    }

    /// Set the TCB (Thread Control Block) for the trustlet
    /// 
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFFA)
    /// * rbx: TCB address
    /// 
    /// Return:
    /// * no return value
    fn pal_svsm_set_tcb(&mut self) -> bool {
      let tcb = self.vmsa.rbx;
      self.vmsa.gs.base = tcb; // Set the base of the GS segment
      return true;
    }

    fn pal_svsm_print_info(&mut self) -> bool {
        let addr = self.vmsa.rbx;
        let len = self.vmsa.rcx;
        let print_vmsa = if self.vmsa.rdx == 0 { false } else { true };

        let page_table = self.vmsa.cr3;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);

        let addr_start = addr & !0xFFF;
        let paddr = page_table_ref.get_page(VirtAddr::from(addr_start));
        let (_mapping, addr_mapping) = map_paddr!(paddr);
        let content: *const u8 = unsafe {{ addr_mapping.as_ptr::<u8>() }.offset((addr & 0xFFF).try_into().unwrap())};
        let slice = unsafe {core::slice::from_raw_parts(content, len as usize)};

        if addr + len > addr_start + PAGE_SIZE_4K {
            log::info!("Unable to print -- Not within page");
        }
        if len % 8 != 0 {
            log::info!("Unable to print -- len not multiple of 8")
        }
        let mut i:usize = 0;
        while i != (len as usize){

            log::info!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                       slice[i],
                       slice[i+1],
                       slice[i+2],
                       slice[i+3],
                       slice[i+4],
                       slice[i+5],
                       slice[i+6],
                       slice[i+7]
            );
            i = i + 8;

        }
        //log::info!(" [Trustlet] PAL Error: {} {}",s.to_str().unwrap(), errno);
        let rdx = self.vmsa.rdx;
        log::info!("RDX: {:#x}", rdx);

        return true;
    }
}
