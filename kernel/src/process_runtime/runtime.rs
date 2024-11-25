use cpuarch::vmsa::VMSA;
use igvm_defs::PAGE_SIZE_4K;
use core::ffi::CStr;
use core::str;
use crate::{address::VirtAddr, cpu::percpu::{this_cpu, this_cpu_unsafe}, map_paddr, mm::{PerCPUPageMappingGuard, PAGE_SIZE}, process_manager::{process::{ProcessID, TrustedProcess, PROCESS_STORE}, process_paging::{ProcessPageFlags, ProcessPageTableRef}}, protocols::{errors::SvsmReqError, RequestParams}};

const TRUSTLET_VMPL: u64 = 1;

pub trait ProcessRuntime {
    fn handle_process_request(&mut self) -> bool;
    fn pal_svsm_virt_alloc(&mut self) -> bool;
    fn pal_svsm_debug_print(&mut self) -> bool;
    fn pal_svsm_fail(&mut self) -> bool;
    fn pal_svsm_exit(&mut self) -> bool;
    fn pal_svsm_map(&mut self) -> bool;
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
        vmsa.rax = 0;

        // The Trustlet exits with cpuid (2 Bytes)
        vmsa.rip += 2;

        let mut return_value = 0u64;

        match rax {
            0 => {
                return self.pal_svsm_fail();
            }
            1 => {
                return self.pal_svsm_exit();
            }
            2 => {
                return self.pal_svsm_debug_print();
            }
            4 => {
                return self.pal_svsm_virt_alloc();
            }
            5 => {
                return self.pal_svsm_map();
            }
            99 => {
                let c = vmsa.rbx;
                log::info!("{}", c);

                let c_str = core::char::from_digit(c as u32, 10).unwrap();
                log::info!("{}",c_str);
                return true
            }
            _ => {
                log::info!("Unknown request code: {}", rax);
                return false;
            }

        }

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
        log::info!("Trying to allocate: {:#?}, {} {:?}", addr, size,page_flags);
        page_table_ref.add_pages(VirtAddr::from(addr), size / 4096, page_flags);

        log::info!("Allocated Memory");
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

        let vaddr = VirtAddr::from(addr);
        let s_vaddr = VirtAddr::from(0x18000000000u64);


        for i in 0..size {
            let t = page_table_ref.virt_to_phys(s_vaddr + ((i * PAGE_SIZE_4K) as usize) + (offset as usize));
            log::info!("{:#} {:#?}",s_vaddr + ((i * PAGE_SIZE_4K) as usize) + (offset as usize), t);
            //page_table_ref.map_4k_page(vaddr + i * PAGE_SIZE, )
        }



        return true;
    }


}
