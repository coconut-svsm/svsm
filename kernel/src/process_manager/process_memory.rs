use crate::address::{PhysAddr, VirtAddr};
use crate::cpu::control_regs::read_cr3;
use crate::locking::SpinLock;
use crate::mm::pagetable::{get_init_pgtable_locked, PTEntry, PTEntryFlags, PageTable};
use crate::protocols::errors::SvsmReqError;
use crate::sev::SevSnpError;
use crate::types::PageSize;
use crate::sev::PvalidateOp;
use crate::sev::pvalidate;
use crate::protocols::core::PVALIDATE_LOCK;
use crate::error::SvsmError;
use crate::mm::PAGE_SIZE;
use crate::cpu::ghcb::current_ghcb;
use crate::sev::ghcb::PageStateChangeOp;
use crate::mm::PerCPUPageMappingGuard;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use crate::utils::{MemoryRegion};
use crate::mm::phys_to_virt;
use crate::{paddr_as_u64_slice, map_paddr, vaddr_as_u64_slice};
use crate::mm::memory::get_memory_region_from_map;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessMemConfig {
    initilized: bool,

    total_size: usize,
    free: usize,

    //Page List
    free_page_list: u64,
    free_page_list_used_len: usize,
    //Current Addresses
    page_top: PhysAddr,
    page_base: PhysAddr,
    page_limit: PhysAddr,
    //Allocation
    allocation_offset: u64,
    mapping_table: PhysAddr,
    free_page_list_table_entry: u64,
}

pub const ALLOCATION_RANGE_VIRT_START: u64 = 0x30000000000u64;

static PROCESS_MEM_CONFIG: SpinLock<ProcessMemConfig> = SpinLock::new(ProcessMemConfig::new());
pub static CPU_COUNT: ImmutAfterInitCell<u64> = ImmutAfterInitCell::new(0);

#[allow(non_upper_case_globals)]
const KiB: usize = 1024;
#[allow(non_upper_case_globals)]
const MiB: usize = KiB * 1024;
#[allow(non_upper_case_globals)]
const GiB: usize = MiB * 1024;

const ADDRESS_START_FREE_PAGE_LIST: usize = 0x8000000000;

const CONDITION_MIN_MEM_SIZE: usize = 1 * GiB;

const ADDRESS_LENGTH: u64 = 8;

pub const PGD: usize = 3;
pub const PUD: usize = 2;
pub const PMD: usize = 1;
pub const PTE: usize = 0;

fn addr_to_idx(addr: usize, lvl: usize) -> usize {
    (addr >> (lvl * 9 + 12)) & 0x1FF
}

impl ProcessMemConfig{

    const fn new() -> ProcessMemConfig{
        ProcessMemConfig{
            initilized: false,
            total_size: 0,
            free: 0,
            free_page_list: 0x8000000000u64,
            free_page_list_used_len: 0,
            page_top: PhysAddr::null(),
            page_base: PhysAddr::null(),
            page_limit: PhysAddr::null(),
            allocation_offset: 0,
            mapping_table: PhysAddr::null(),
            free_page_list_table_entry: 0,
        }
    }
    fn check_requirements() -> usize{
        //We only use the first two regions for now
        //The first should go from 0-2 GiB and the second starts
        //from 3 GiB and represents the userable Monitor memory
        let memory_region_count = 2;
        let mut total_size = 0;

        //The first region belongs to the guest OS running Linux
        //If this region is not 2 GiB in size we are not accounint for that
        let initial_memory_region = get_memory_region_from_map(0);
        if initial_memory_region.end() - initial_memory_region.start() < 2 * GiB {
            log::error!("Initial Memory Region to small (not implemented)");
            panic!();
        }

        for i in 1..memory_region_count {
            let region = get_memory_region_from_map(i);
            total_size += region.end() - region.start();
        }

        if CONDITION_MIN_MEM_SIZE > total_size {
            log::error!("Not enough memory given to VMPL0 (second memory region is to small)");
            panic!();
        }

        total_size
    }

    fn free_memory_list(total_memory_size: usize) -> (usize, usize) {
        //Each entry represents one page of memory
        //Thus the required list size is size / page_size * address_size
        //address_size is 8 bytes
        let free_memory_list_size = (total_memory_size / PAGE_SIZE) * 8;
        let region = get_memory_region_from_map(1);
        let usable_memory_region = region.start() + free_memory_list_size;

        if usize::from(usable_memory_region) % PAGE_SIZE != 0 {
            log::error!("Something went wrong. Memory start is not page aligned.");
            panic!();
        }

        log::info!("Total available memory: {} B", total_memory_size);
        log::info!("Usable available memory: {} B", total_memory_size - free_memory_list_size);
        log::info!("Total Memory Region: {:#x} - {:#x}", region.start(), region.end());
        log::info!("Usable Memory Region: {:#x} - {:#x}", usable_memory_region, region.end());

        (free_memory_list_size, usable_memory_region.into())
    }

    fn prepare_free_memory_list(free_memory_list_size: usize) -> u64 {

        let free_memory_list_memory_range =
            MemoryRegion::<VirtAddr>::new(VirtAddr::from(ADDRESS_START_FREE_PAGE_LIST), free_memory_list_size);
        log::info!("Reserved Memory({:#x}-{:#x}): {} B",
                   free_memory_list_memory_range.start(),
                   free_memory_list_memory_range.end(),
                   free_memory_list_memory_range.end() - free_memory_list_memory_range.start());

        //Map the memory region for the Page list into the current core's page table
        let region = get_memory_region_from_map(1);
        let mut pgtable = get_init_pgtable_locked(); //Gets the shared page table for all cores (Does not affect cores)
        pgtable.map_region_4k(free_memory_list_memory_range, region.start(), PTEntryFlags::data()).unwrap();
        let page_table_entry = PTEntry::from(read_cr3()); // Get current core's page table
        let address = phys_to_virt(page_table_entry.address());
        let page_table_page = unsafe { &mut *address.as_mut_ptr::<PageTable>() };
        page_table_page.get_root()[1] = pgtable.get_root()[1]; // Copy page table for free memory list to active page table
        for p in 0..(free_memory_list_size / PAGE_SIZE) { //Iterate over every require page
            let offset = p * PAGE_SIZE;
            let vaddr = VirtAddr::from(ADDRESS_START_FREE_PAGE_LIST);
            let paddr = region.start();
            match monitor_pvalidate_vaddr_4k(vaddr + offset, paddr + offset) {
                Ok(_) => (),
                Err(e) => {log::error!("{:?}",e); panic!("Failed to pvalidate initial list");}
            };
            let v = vaddr + offset;
            let e: &mut [u64; 512] = unsafe { &mut *v.as_mut_ptr::<[u64;512]>() };
            for i in 0..512 {
                e[i] = 0;
            }
        }
        let (_m, pt) = paddr_as_u64_slice!(read_cr3());
        pt[1]
    }

    fn validate_and_clear(addr: u64){
        let mapping = PerCPUPageMappingGuard::create_4k(PhysAddr::from(addr)).unwrap();
        let virt = mapping.virt_addr();
        let entry: &mut [u64;512] = unsafe { &mut *virt.as_mut_ptr::<[u64;512]>() };
        monitor_pvalidate_vaddr_4k(virt, PhysAddr::from(addr)).unwrap();

        for i in 0..512 {
            entry[i] = 0;
        }
    }

    fn get_current_pagetable_as_u64_slice() -> &'static mut [u64;512] {
        let page_table_entry = PTEntry::from(read_cr3());
        let address = phys_to_virt(page_table_entry.address());
        vaddr_as_u64_slice!(address)
    }

    fn init(&mut self) {

        if self.initilized {
            let (_m, pt) = paddr_as_u64_slice!(read_cr3());
            pt[1] = self.free_page_list_table_entry;
            return;
        }
        // Configure the initial additional memory
        // For now it just assumes one more memory r gion
        let total_size = ProcessMemConfig::check_requirements();

        // We need to be able to store every page that might get freed
        // With using the total size we overestimate the size we might need
        // since we require some of the memory for other purposes (pagetable etc)
        let free_memory_list_size: usize;
        let _usable_memory_region_start: usize;

        (free_memory_list_size, _usable_memory_region_start) = ProcessMemConfig::free_memory_list(total_size);

        self.free_page_list_table_entry = ProcessMemConfig::prepare_free_memory_list(free_memory_list_size);

        //Setting the base values for the current amount of memory
        //Removing the space required for the memory managment
        self.total_size = total_size - free_memory_list_size;
        self.free = total_size - free_memory_list_size;
        self.free_page_list_used_len = 0; //No pages used yet
        let region = get_memory_region_from_map(1);
        self.page_base = region.start() + free_memory_list_size;
        self.page_limit = region.end();
        self.initilized = true;
    }

    fn check_for_free_page(&mut self) -> PhysAddr {
        if self.free_page_list_used_len == 0 {
            return PhysAddr::null();
        }
        self.free_page_list_used_len -= 1;
        let addr = self.free_page_list + (self.free_page_list_used_len as u64 * ADDRESS_LENGTH);
        let entry: &mut PhysAddr = unsafe {&mut *((addr) as *mut PhysAddr)};
        let tmp = *entry;
        *entry = PhysAddr::null();
        tmp
    }

    pub fn get_free_page(&mut self) -> PhysAddr {
        let mut addr = self.check_for_free_page();
        if addr == PhysAddr::null() {
            addr = PhysAddr::from(self.page_base);
            ProcessMemConfig::validate_and_clear(u64::from(addr));
            self.page_base = self.page_base + PAGE_SIZE;
        }
        addr
    }

    pub fn virt_to_phys(&self, vaddr: VirtAddr) -> PhysAddr {
        let pgd_table = ProcessMemConfig::get_current_pagetable_as_u64_slice();
        let mut addr = pgd_table[addr_to_idx(usize::from(vaddr), PGD)];
        let (_pud_mapping, pud_table) = paddr_as_u64_slice!(PhysAddr::from(addr & 0xFFFFFFFFFFFFE000));
        addr = pud_table[addr_to_idx(usize::from(vaddr), PUD)];
        let (_pmd_mapping, pmd_table) = paddr_as_u64_slice!(PhysAddr::from(addr & 0xFFFFFFFFFFFFE000));
        addr = pmd_table[addr_to_idx(usize::from(vaddr), PMD)];
        let (_pte_mapping, pte_table) = paddr_as_u64_slice!(PhysAddr::from(addr & 0xFFFFFFFFFFFFE000));
        addr = pte_table[addr_to_idx(usize::from(vaddr), PTE)];
        PhysAddr::from(addr & 0xFFFFFFFFFFFFE000)
    }

    pub fn test(&self) {
        let pgd_table = ProcessMemConfig::get_current_pagetable_as_u64_slice();
        log::info!("{:?}",pgd_table);
        let (_pud_mapping, pud_table) = paddr_as_u64_slice!(PhysAddr::from(pgd_table[3] & !0x1FF));
        log::info!("{:?}",pud_table);
    }
}

pub fn allocate_page() -> PhysAddr {
    PROCESS_MEM_CONFIG.lock().get_free_page()
}

pub fn additional_monitor_memory_init() -> Result<(), SvsmError> {
    PROCESS_MEM_CONFIG.lock().init();
    Ok(())
}

pub fn add_monitor_memory() -> Result<(), SvsmError>{
    PROCESS_MEM_CONFIG.lock().init();
    Ok(())
}

fn monitor_pvalidate_vaddr_4k(vaddr: VirtAddr, paddr: PhysAddr) -> Result<(), SvsmReqError>{
   monitor_pvalidate_vaddr(vaddr, paddr,PAGE_SIZE, PageSize::Regular, PvalidateOp::Valid, false)
}

fn monitor_pvalidate_vaddr(vaddr: VirtAddr, paddr: PhysAddr, ps_s: usize, ps: PageSize, _pvop: PvalidateOp, ign_cf: bool) -> Result<(), SvsmReqError> {
    current_ghcb().page_state_change(paddr, paddr + ps_s, ps, PageStateChangeOp::PscPrivate).unwrap();
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
