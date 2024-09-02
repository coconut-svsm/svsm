use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::control_regs::read_cr3;
use crate::cpu::flush_tlb_global_sync;
use crate::cpu::percpu::this_cpu_mut;
use crate::locking::SpinLock;
use crate::mm::memory::{get_memory_map_len, get_memory_region_from_map};
use crate::mm::pagetable::{get_init_pgtable_locked, set_init_pgtable, PTEntry, PTEntryFlags, PTPage, PageTable};
use crate::protocols::errors::SvsmReqError;
use crate::sev::SevSnpError;
use crate::sp_pagetable::{set_c_bit_in_address, PageFlags};
use crate::types::PageSize;
use crate::sev::PvalidateOp;
use crate::sev::pvalidate;
use crate::protocols::core::PVALIDATE_LOCK;
use crate::mm::{virt_to_phys, PAGE_SIZE_2M};
use crate::mm::alloc::allocate_zeroed_page;
use crate::error::SvsmError;
use crate::mm::virtualrange::VIRT_ALIGN_4K;
use crate::mm::PAGE_SIZE;
use crate::cpu::ghcb::current_ghcb;
use crate::sev::ghcb::PageStateChangeOp;
use crate::mm::PerCPUPageMappingGuard;
use crate::utils::{memory_region, MemoryRegion};
use crate::mm::phys_to_virt;
use core::ptr;

pub fn show_page_table() {

    /*let pgtableref = get_init_pgtable_locked();
    let pgtable = unsafe {&mut *pgtableref.get_ptr()};
    let root = pgtable.get_root();
    log::info!(" {:?}",pgtable);
    drop(pgtableref);*/
    add_monitor_memory();
}

#[derive(Debug, Clone, Copy)]
struct MemoryLimit {
    pub memory_region_index: usize,
    pub end_address: PhysAddr,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessMemConfig {
    total_size: usize,
    free: usize,
    free_pages: u64,
    free_pages_len: usize,
    //Current Addresses
    start: PhysAddr,
    end: PhysAddr,
    //Test page
}

/*repr(C)]
pub struct FreePageList {

}*/

static PROCESS_MEM_CONFIG: SpinLock<ProcessMemConfig> = SpinLock::new(ProcessMemConfig::new());


#[allow(non_upper_case_globals)]
const KiB: usize = 1024;
#[allow(non_upper_case_globals)]
const MiB: usize = KiB * 1024;
#[allow(non_upper_case_globals)]
const GiB: usize = MiB * 1024;
#[allow(non_upper_case_globals)]
const TiB: usize = GiB * 1024;

const FREE_PAGE_LIST_START: usize = 0x8000000000;
const MINIMAL_MEMORY_SIZE: usize = 1 * GiB;
const VALIDATION_PAGE: u64 = PAGE_SIZE as u64;

const SELF_MAPPED_PAGE: usize = 0x10000000000;

impl ProcessMemConfig{

    const fn new() -> ProcessMemConfig{
        ProcessMemConfig{
            total_size: 0,
            free: 0,
            free_pages: 0x8000000000u64,
            free_pages_len: 0,
            start: PhysAddr::null(),
            end: PhysAddr::null(),
        }
    }

    fn init(&mut self) {
        // Configure the initial additional memory
        // For now it just assumes one more memory region

        let memory_region_count = 2;
        let mut total_size = 0;

        let initial_memory_region = get_memory_region_from_map(0);
        if initial_memory_region.end() - initial_memory_region.start() < 2 * GiB {
            log::error!("Initial Memory Region to small (not implemented)");
            panic!();
        }
        // Add up all memory regions (just one for now)
        // We assume that the first region we check (2nd region)
        // has at least 1 GiB of memory available
        for i in 1..memory_region_count {
            let region = get_memory_region_from_map(i);
            total_size += region.end() - region.start();
        }

        if MINIMAL_MEMORY_SIZE > total_size {
            log::error!("Not enough memory given to VMPL0 (second memory region is to small)");
            panic!();
        }

        // We need to be able to store every page that might get freed
        // With using the total size we overestimate the size we might need
        // since we require some of the memory for other purposes (pagetable etc)

        let max_list_size = (total_size / PAGE_SIZE) * 8;

        self.total_size = total_size;
        self.free = total_size;
        self.free_pages_len = 0;

        let region = get_memory_region_from_map(1);
        self.start = region.start();
        self.end = region.end();

        if (usize::from(self.start + max_list_size)) % PAGE_SIZE != 0 {
            log::error!("Something went wrong. Memory start is not page aligned.");
            panic!();
        }
        self.start = self.start + max_list_size;
        self.total_size -= max_list_size;

        log::info!("Total available memory: {} B",self.total_size);
        log::info!("Usable available memory: {} B", self.total_size - max_list_size);
        log::info!("Total Memory Region: {:#x} - {:#x}", region.start(), region.end());
        log::info!("Usable Memory Region: {:#x} - {:#x}", self.start, self.end);

        //let end_addr = total_size / PAGE_SIZE;
        let list_range = MemoryRegion::<VirtAddr>::new(VirtAddr::from(FREE_PAGE_LIST_START), max_list_size);

        log::info!("Reserved Memory({:#x}-{:#x}): {} B", list_range.start(), list_range.end(), list_range.end()-list_range.start());
        let mut pgtable = get_init_pgtable_locked();
        pgtable.map_region_4k(list_range,region.start(),PTEntryFlags::data());

        let page_table_entry = PTEntry::from(read_cr3()); let address = phys_to_virt(page_table_entry.address());
        let page_table_page = unsafe { &mut *address.as_mut_ptr::<PageTable>() };
        page_table_page.get_root()[1] = pgtable.get_root()[1];

        // Allocate and pvalidate all addresses in the list region
        for p in 0..(max_list_size / PAGE_SIZE) {
            let offset = p * PAGE_SIZE;
            let vaddr = VirtAddr::from(FREE_PAGE_LIST_START);
            let paddr = region.start();
            match monitor_pvalidate_vaddr_4k(vaddr + offset, paddr + offset){
                Ok(_) => (),
                Err(e) => {log::error!("{:?}",e); panic!("Failed to pvalidate initial list");}
            };
        }

        //
        let entry_flags = PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::USER_ACCESSIBLE | PageFlags::ACCESSED;
        let lvl1 = u64::from(self.start);
        let lvl1_addr = PhysAddr::from(set_c_bit_in_address(PhysAddr::from(lvl1)).bits() as u64 | entry_flags.bits());
        let lvl2 = lvl1 + PAGE_SIZE as u64;
        let lvl2_addr = PhysAddr::from(set_c_bit_in_address(PhysAddr::from(lvl2)).bits() as u64 | entry_flags.bits());
        let lvl3 = lvl2 + PAGE_SIZE as u64;
        let lvl3_addr = PhysAddr::from(set_c_bit_in_address(PhysAddr::from(lvl3)).bits() as u64 | entry_flags.bits());


        match move || -> Result<(),SvsmError> {
            let setup_process = |current_lvl_addr: u64, current_lvl: u64, next_lvl_addr: u64| ->Result<(), SvsmError> {
                let guard = PerCPUPageMappingGuard::create_4k(PhysAddr::from(current_lvl))?;
                let vaddr: VirtAddr = guard.virt_addr();
                let entry: &mut [u64; 512] = unsafe { &mut *vaddr.as_mut_ptr::<[u64;512]>() };
                monitor_pvalidate_vaddr_4k(vaddr, PhysAddr::from(current_lvl)).unwrap();
                entry[0..512].fill(0); // For some reason the memory is not zeroed by the host
                let entry = &mut entry[0];
                *entry = next_lvl_addr;
                let entries = unsafe { &mut *vaddr.as_mut_ptr::<[PTEntry;512]>() };
                log::info!("TABLE{:#x}:  {:?}\n\n\n\n",current_lvl, entries);
                Ok(())
            };
            //setup_process(lvl1_addr.into(), lvl1, lvl2_addr.into()); // 1 -> 2
            //setup_process(lvl2_addr.into(), lvl2, lvl3_addr.into()); // 2 -> 3
            //setup_process(lvl3_addr.into(), lvl3, lvl3_addr.into()); // 3 -> 3; Allows to directly write to the pagetable here
            //page_table_page.get_root()[2] = PTEntry::from(lvl1_addr); // 0 -> 1
            let vaddr: VirtAddr = VirtAddr::from(SELF_MAPPED_PAGE);
            let data = unsafe { &mut *address.as_mut_ptr::<[PTEntry;512]>() };

            log::info!("Test({:?}): {:?}",vaddr, data);
            /*
            let guard = PerCPUPageMappingGuard::create_4k(PhysAddr::from(lvl1))?;
            let vaddr: VirtAddr = guard.virt_addr();
            let entry: &mut u64 = unsafe { &mut *vaddr.as_mut_ptr::<u64>() };
            monitor_pvalidate_vaddr_4k(vaddr, PhysAddr::from(lvl1)).unwrap();
            *entry = lvl2_addr.into();
            let guard = PerCPUPageMappingGuard::create_4k(PhysAddr::from(lvl2))?;
            let vaddr: VirtAddr = guard.virt_addr();
            //let entry: &mut u64 = unsafe { &mut * }
            */
            Ok(())
        }() {
            Ok(_) => (),
            Err(e) => panic!("{:?}",e)
        };


        self.start = self.start + 3 * PAGE_SIZE;
        let mut addr: u64 = lvl1;


        /*for i in 0..10 {
            log::info!("{:#x}", self.get_free_page());
        }
        for i in 0..10 {
            self.add_free_page(PhysAddr::from(0x100c00000u64) + i * PAGE_SIZE);
        }
        for i in 0..10 {
            log::info!("{:#x}", self.get_free_page());
             }
        */
    }

    fn check_for_free_page(&mut self) -> PhysAddr {
        if self.free_pages_len == 0 {
            return PhysAddr::null();
        }
        self.free_pages_len -= 1;
        let addr = self.free_pages + (self.free_pages_len as u64 * 8);
        let entry: &mut PhysAddr = unsafe {&mut *((addr) as *mut PhysAddr)};
        let tmp = *entry;
        *entry = PhysAddr::null();
        tmp
    }

    fn add_free_page(&mut self, paddr: PhysAddr) {
        let next_entry = self.free_pages_len;
        self.free_pages_len += 1;
        let addr = self.free_pages + (next_entry as u64 * 8);
        let entry: &mut PhysAddr = unsafe {&mut *((addr) as *mut PhysAddr)};
        *entry = paddr;
    }

    pub fn get_free_page(&mut self) -> PhysAddr {
        let mut addr = self.check_for_free_page();
        if addr == PhysAddr::null() {
            addr = PhysAddr::from(self.start);
            self.start = self.start + PAGE_SIZE;
        }
        addr
    }

    pub fn get_free_page_mapped(&self) -> VirtAddr {
        VirtAddr::null()
    }

    fn remove_page_mapping(&self, vaddr: VirtAddr) {

    }

}





pub fn add_monitor_memory() -> Result<(), SvsmError>{

    PROCESS_MEM_CONFIG.lock().init();
    panic!("DONE");
    let memory_region_count = get_memory_map_len();
    let mut total_size = 0;

    let initial_memory_region = get_memory_region_from_map(0);
    if initial_memory_region.end() - initial_memory_region.start() < 2 * GiB {
        log::error!("Initial Memory Region to small (not implemented)");
        panic!();
    }

    for i in 1..memory_region_count {
        let region = get_memory_region_from_map(i);
        total_size += region.end() - region.start();
    }

    let required_size = 1 * GiB;



    let memory_region_count = get_memory_map_len();
    let memory_region_count = 2; //For now we are just considering the first free memory region
    let mut total_size = 0;
    for i in 1..memory_region_count {
        let region = get_memory_region_from_map(i);
        total_size += region.end() - region.start();
    }
    //log::info!("Region count:  {}", memory_region_count);
    //log::info!("Total memory size: {} B, {} GB, {} Pages", total_size, total_size/1024/1024/1024,total_size/4096);
    let region: MemoryRegion<PhysAddr> = get_memory_region_from_map(1);
    let region_size = region.end() - region.start();
    if region_size / PAGE_SIZE < 262144 {
        log::error!("Expecting at least 1 GiB of additional Memory for Monitor in the first Memory Region");
    }
    if region_size / PAGE_SIZE >= 134217728 {
        log::error!("Currently not handeled");
    }
    if region_size / PAGE_SIZE % 512 != 0 {
        log::error!("Unsupported Page Count; The first usable Region needs to fit into 2M Pages");
    }
    //Get the PageTableRef
    log::info!("Test");
    let mut pgtable = get_init_pgtable_locked();
    log::info!("Test2");
    // The SVSM memory is mapped at the end of the PageTable
    // We are starting at the front
    // This limits us to about 250 TB of addressable Memory (more if we extend to 5 level paging)
    //We also assume 2M pages

    // Here we map the first 1 GB into memory.
    // This will use default Monitor Memory
    // After the first GB we use this to allow for allocations

    //let lvl1_page_vaddr = allocate_zeroed_page()?;
    //let lvl2_page_vaddr = allocate_zeroed_page()?;

    //let lvl1_page_paddr = virt_to_phys(lvl1_page_vaddr);
    //let lvl2_page_paddr = virt_to_phys(lvl2_page_vaddr);

    //let lvl1_page: &mut PTEntry = unsafe { lvl1_page_vaddr.as_mut_ptr::<PTEntry>().as_mut().unwrap() };
    //lvl1_page.set(lvl2_page_paddr,PTEntryFlags::data());
    //log::info!("{:#x},{:#x}",lvl1_page_vaddr, lvl1_page_paddr);

    monitor_reserve_addr(u64::from(region.start())+4096);


    let vregion = MemoryRegion::new(
        VirtAddr::null(),
        1024*1024*1024,
    );

    log::info!("Test3");
    //log::info!("Test: {:?}", this_cpu_mut().get_pgtable().get_root());
    //let page_table_paddr = read_cr3();
    //let page_table_guard = PerCPUPageMappingGuard::create_4k(page_table_paddr);
    //let page_table_vaddr = page_table_guard?.virt_addr();
    //let page_table_entry = unsafe { page_table_vaddr.as_mut_ptr::<[PTEntry; 512]>().as_mut().unwrap() };

    let page_table_entry = PTEntry::from(read_cr3());
    let address = phys_to_virt(page_table_entry.address());
    let page_table_page = unsafe { &mut *address.as_mut_ptr::<PageTable>() };//PageTable::entry_to_pagetable(page_table_entry).unwrap();

    log::info!("Test3.5");


    //let page_table_page = PTPage{ entries: *page_table_entry };
    //let page_table_page = PageTable::entry_to_pagetable(PTEntry{0:read_cr3()}).unwrap();

    //let mut page_table_page: PTPage = Default::default();
    //page_table_page.set()
    //let mut page_table: PageTable = PageTable { root: page_table_page };
    let mut page_table = page_table_page;
    log::info!("Test4");




    match page_table.map_region_4k(
        vregion,
        region.start(),
        PTEntryFlags::data(),
    ){
        Ok(()) => (),
        Err(_) => panic!(""),
    }
    log::info!("Test5");

    //let page_table_page = unsafe { &mut *address.as_mut_ptr::<PTPage>() };
    //let mut page_table: PageTable = PageTable { root: *page_table_page };
    //log::info!("{:?}", page_table.get_root());

    //log::info!("Test: {:?}", this_cpu_mut().get_pgtable().get_root());
    let entry: PTEntry = this_cpu_mut().get_pgtable().get_root()[511];
    let guard = PerCPUPageMappingGuard::create_4k(entry.address())?;
    let vaddr = guard.virt_addr();
    let ptpage = unsafe { vaddr.as_mut_ptr::<PTPage>().as_mut().unwrap() };

    //log::info!("1: {:?}",ptpage);
    let entry: PTEntry = ptpage[0];
    let guard = PerCPUPageMappingGuard::create_4k(entry.address())?;
    let vaddr = guard.virt_addr(); let ptpage = unsafe { vaddr.as_mut_ptr::<PTPage>().as_mut().unwrap() };
    //log::info!("2: {:?}",ptpage);

    let entry: PTEntry = ptpage[0];
    let guard = PerCPUPageMappingGuard::create_4k(entry.address())?;
    let vaddr = guard.virt_addr(); let ptpage = unsafe { vaddr.as_mut_ptr::<PTPage>().as_mut().unwrap() };
    //log::info!("3: {:?}",ptpage);

    log::info!("VADDR PENTRY: {:#x}", vaddr);

    log::info!("Current cr3: {:#x}", read_cr3());
    log::info!("Page cr3: {:#x}", this_cpu_mut().get_pgtable().cr3_value());


    flush_tlb_global_sync();

    let paddr_var = region.start() + 0x1000;
    let guard_var = PerCPUPageMappingGuard::create_4k(paddr_var)?;
    let vaddr_var = guard_var.virt_addr();
    let var = unsafe { vaddr.as_mut_ptr::<u64>().as_mut().unwrap() };
    *var = 5;
    log::info!("Test var: {}", var);

    log::info!("Try mapping");
    let vaddr = VirtAddr::from(0x1000u64);
    log::info!("What: {:#x}",vaddr);
    let mut test_map = unsafe { vaddr.as_mut_ptr::<u64>().as_mut().unwrap() };
    *test_map = 10;
    log::info!("Trying to change value!");
    let test2 = *test_map;
    log::info!("Test: {}",test_map);


    //let root = pgtable.get_root();
    //log::info!(" {:?}",root);

    log::info!("Using region of size: {}", region_size);
    panic!();

    Ok(())
}

fn monitor_pvalidate_vaddr_2m(vaddr: VirtAddr, paddr: PhysAddr) -> Result<(), SvsmReqError>{
   monitor_pvalidate_vaddr(vaddr, paddr,PAGE_SIZE_2M, PageSize::Huge, PvalidateOp::Valid, false)
}
fn monitor_pvalidate_vaddr_4k(vaddr: VirtAddr, paddr: PhysAddr) -> Result<(), SvsmReqError>{
   monitor_pvalidate_vaddr(vaddr, paddr,PAGE_SIZE, PageSize::Regular, PvalidateOp::Valid, false)
}

fn monitor_pvalidate_vaddr(vaddr: VirtAddr, paddr: PhysAddr,ps_s: usize, ps: PageSize, pvop: PvalidateOp, ign_cf: bool) -> Result<(), SvsmReqError> {
    current_ghcb().page_state_change(paddr, paddr + ps_s, ps, PageStateChangeOp::PscPrivate);
    let lock = PVALIDATE_LOCK.lock_read();
    pvalidate(vaddr,PageSize::Regular, PvalidateOp::Valid).or_else(
        |err| match err{
            SvsmError::SevSnp(SevSnpError::FAIL_UNCHANGED(_)) if ign_cf => Ok(()),
            _ => {log::error!("{:?}",err); Err(err)}
        }
    )?;
    drop(lock);
    Ok(())
}

pub fn monitor_reserve_addr(entry: u64) -> Result<(),SvsmReqError>{
    let paddr = PhysAddr::from(entry);
    current_ghcb().page_state_change(paddr, paddr + PAGE_SIZE, PageSize::Regular, PageStateChangeOp::PscPrivate);
    let guard = PerCPUPageMappingGuard::create(paddr, paddr + PAGE_SIZE, VIRT_ALIGN_4K).unwrap();
    log::info!("Set one done");
    let vaddr = guard.virt_addr();
    let ign_cf = false;

    let lock = PVALIDATE_LOCK.lock_read();
    pvalidate(vaddr,PageSize::Regular, PvalidateOp::Valid).or_else(
        |err| match err{
            SvsmError::SevSnp(SevSnpError::FAIL_UNCHANGED(_)) if ign_cf => Ok(()),
            _ => {log::error!("{:?}",err); Err(err)}
        }
    )?;
    drop(lock);
    Ok(())
}

#[derive(Debug)]
pub struct ProcessMemoryArray {
    size: u64,
    paddr: *mut PhysAddr,
}

pub fn monitor_alloc() -> VirtAddr {
    let vaddr = allocate_zeroed_page().unwrap();
    vaddr
}

pub fn monitor_virt_to_phys(vaddr: VirtAddr) -> PhysAddr {
    virt_to_phys(vaddr)
}
