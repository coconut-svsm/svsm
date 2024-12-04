use cpuarch::vmsa::VMSA;
use igvm_defs::PAGE_SIZE_4K;
use core::ffi::CStr;
use core::str;
use crate::{address::VirtAddr, cpu::{cpuid::{cpuid_table_raw, CpuidResult}, percpu::{this_cpu, this_cpu_unsafe}}, map_paddr, mm::{PerCPUPageMappingGuard, PAGE_SIZE}, paddr_as_slice, process_manager::{process::{ProcessID, TrustedProcess, PROCESS_STORE}, process_memory::allocate_page, process_paging::{ProcessPageFlags, ProcessPageTableRef}}, protocols::{errors::SvsmReqError, RequestParams}};

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
    fn pal_svsm_print_info(&mut self) -> bool;
    fn pal_svsm_set_tcb(&mut self) -> bool;
    fn pal_svsm_cpuid(&mut self) -> bool;
}

#[derive(Debug)]
pub struct PALContext {
    process: &'static mut TrustedProcess,
    vmsa: &'static mut VMSA,
    string_buf: [u8;256],
    string_pos: usize,
}

pub fn invoke_trustlet(params: &mut RequestParams) -> Result<(), SvsmReqError> {

    log::info!("Invoking Trustlet");

    let id = params.rcx;

    let trustlet = PROCESS_STORE.get(ProcessID(id.try_into().unwrap()));

    //log::info!("{:?}", trustlet);

    // Getting the current processes VMSA
    let vmsa_paddr = trustlet.context.vmsa;
    let vmsa_mapping = PerCPUPageMappingGuard::create_4k(trustlet.context.vmsa).unwrap();
    let vmsa: &mut VMSA = unsafe { vmsa_mapping.virt_addr().as_mut_ptr::<VMSA>().as_mut().unwrap() };

    let apic_id = this_cpu().get_apic_id();

    let mut string_buf: [u8;256] = [0;256];
    let mut string_pos: usize = 0;
    let sev_features = trustlet.context.sev_features;


    let mut rc = PALContext{
        process: trustlet,
        vmsa: vmsa,
        string_buf: string_buf,
        string_pos: string_pos,
    };


    loop {
        unsafe {(*(*this_cpu_unsafe()).ghcb).ap_create(vmsa_paddr,
                                                       u64::from(apic_id),
                                                       TRUSTLET_VMPL,
                                                       sev_features).unwrap()}
        /*if !handle_process_request(vmsa, &mut string_buf, &mut string_pos){
            break;
        }*/
        if !rc.handle_process_request() {
            break;
        }
    }


    Ok(())


}

impl ProcessRuntime for PALContext  {

    fn handle_process_request(&mut self) -> bool {
        let vmsa = &mut self.vmsa;
        let rax = vmsa.rax;
        //vmsa.rax = 0;

        let rip = vmsa.rip;
        // The Trustlet exits with cpuid (2 Bytes)
        vmsa.rip += 2;

        let mut return_value = 0u64;

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

    fn pal_svsm_cpuid(&mut self) -> bool {
        let eax =  self.vmsa.rax as u32;
        log::info!("eax value: {:#x}",eax);
        let eax_tmp = self.vmsa.rax;
        let ecx_tmp = self.vmsa.rcx;
        let ecx = match eax {
            4 | 7 | 0xb | 0xd | 0xf|
            0x10 | 0x12 | 0x14 | 0x17 |
            0x18 | 0x1d | 0x1e | 0x1f |
            0x24 | 0x8000001d => {
                self.vmsa.rcx as u32
            }
            _ => 0
        };

        //let ecx = if eax == 0x0 || eax == 0x1 || eax == 0xd {
            // set zero for cpuid leaf that does not have subleaf (ecx)
            // TODO: check if this is correct & update checks if so
          //  0
        //} else {
        //    self.vmsa.rcx as u32
        //};

        let res = match cpuid_table_raw(eax, ecx, 0, 0){
            Some(r) => r,
            None => CpuidResult{eax: 0,ebx: 0, ecx: 0, edx: 0}
        };
        self.vmsa.rax = res.eax as u64;
        self.vmsa.rbx = res.ebx as u64;
        self.vmsa.rcx = res.ecx as u64;
        self.vmsa.rdx = res.edx as u64;
        log::info!("Returned CPUID({:#x}/{:#x}) as the following: {:#x} {:#x} {:#x} {:#x}",
        eax_tmp,
        ecx_tmp,
        res.eax,
        res.ebx,
        res.ecx,
        res.edx);
        return true;
    }

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

    fn pal_svsm_fail(&mut self) -> bool{
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

    fn pal_svsm_exit(&mut self) -> bool{
        let exit_code = self.vmsa.rbx;
        log::info!(" [Trustlet] Exit with Status Code: {}", exit_code);
        false
    }

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

    fn pal_svsm_map(&mut self) -> bool {
        let addr = self.vmsa.rbx;
        let size = self.vmsa.rcx;
        //let prot = self.vmsa.rdx >> 32;
        //let flags = self.vmsa.rdx & 0xFFFFFFFF;
        let flags = self.vmsa.rdx;
        let fd = self.vmsa.r8;
        let offset = self.vmsa.r9;

        log::info!("{:#}, {}", addr, size);

        let page_table = self.vmsa.cr3;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);

        if size % 4096 != 0 {
            return false;
        }
        let size = size / 4096;

        let copy = if flags & 0x8 != 0 { true } else { false };

        let vaddr = VirtAddr::from(addr);
        let s_vaddr = VirtAddr::from(0x18000000000u64);

        let flags = ProcessPageFlags::PRESENT | ProcessPageFlags::WRITABLE |
        ProcessPageFlags::USER_ACCESSIBLE | ProcessPageFlags::ACCESSED;

        for i in 0..size {
            let t = page_table_ref.virt_to_phys(s_vaddr + ((i * PAGE_SIZE_4K) as usize) + (offset as usize));
            //log::info!("{:#x}, {:#x}, {:#} {:#?}",s_vaddr,offset, s_vaddr + ((i * PAGE_SIZE_4K) as usize) + (offset as usize), t);
            if copy {
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

        return true;
    }

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
