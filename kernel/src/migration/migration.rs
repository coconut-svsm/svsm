use crate::address::PhysAddr;
use crate::cpu::flush_tlb_global_sync;
use crate::cpu::percpu::this_cpu;
use crate::error::SvsmError;
use crate::migration::guest_valid_bitmap::GuestValidBitmap;
use crate::mm::{virt_to_phys,PageBox};
use crate::mm::guestmem::copy_slice_from_guest;
use crate::mm::memory::MEMORY_MAP;
use crate::sev::{pvalidate,PvalidateOp};
use crate::sev::msr_protocol::invalidate_page_msr;
use crate::task::set_affinity;
use crate::task::schedule;
use crate::types::PageSize;
use crate::utils::memory_region::MemoryRegion;

use igvm_defs::PAGE_SIZE_4K;
use sha2::{Sha256,Digest};
use zerocopy::FromZeros;

pub static VALIDATED_PAGES: GuestValidBitmap = GuestValidBitmap::new();

// Used in communication with QEMU
const SNP_MIGRATION_STATUS_INCOMING: u8 = 0x1;
const SNP_MIGRATION_STATUS_RUNNING: u8 = 0x2;
const SNP_MIGRATION_STATUS_COMPLETED: u8 = 0x3;

const SNP_MIGRATION_DATA_READY: u8 = 0x4;
const SNP_MIGRATION_DATA_READ: u8 = 0x5;

const DATA_BUFFER_SIZE: usize = 0x800;
// DATA_BUFFER_SIZE must divide the PAGE_SIZE_4K
const _: () = assert!(PAGE_SIZE_4K as usize % DATA_BUFFER_SIZE == 0);

pub fn define_region_bitmap(region: MemoryRegion<PhysAddr>) -> Result<(), SvsmError> {
    VALIDATED_PAGES.add_region(region)?;
    Ok(())
}

pub fn count_pvalidate(paddr: PhysAddr, page_size: PageSize, op: PvalidateOp) {
    match op {
        PvalidateOp::Valid => {
            if page_size == PageSize::Huge{
                VALIDATED_PAGES.set_valid_2m(paddr);
            } else {
                VALIDATED_PAGES.set_valid_4k(paddr);
            }
        }
        PvalidateOp::Invalid => {
            if page_size == PageSize::Huge{
                VALIDATED_PAGES.clear_valid_2m(paddr);
            } else {
                VALIDATED_PAGES.clear_valid_4k(paddr);
            }
        }
    }
}


fn start_migration(context : &mut MigrationPage){
    log::info!("Migration Started");
    let mut hash = Sha256::new();
    let mut block_count = 0;
    let mut read_page_count = 0;
    let mut unread_page_count = 0;

    let mut buffer = [0; DATA_BUFFER_SIZE];

    for region in MEMORY_MAP.lock_read().iter() {
        for page in region.iter_pages(PageSize::Regular) {
            if VALIDATED_PAGES.is_valid_4k(page) {
                for offset in (0..PAGE_SIZE_4K as usize).step_by(DATA_BUFFER_SIZE) {
                    if block_count % 100_000 == 0 {
                        log::info!("Blocks sent {}", block_count);
                    }
                    let _ = copy_slice_from_guest(page + offset, &mut buffer);
                    hash.update(&buffer);
                    block_count += 1;
                    context.write_new_page(&buffer);
                }
                read_page_count += 1;
            } else {
                unread_page_count +=1;
            }
        }
    }
    context.0.status_reg = SNP_MIGRATION_STATUS_COMPLETED;
    log::info!("Blocks send {:?}", block_count);
    log::info!("Data hash: {:?}", hash.finalize());
    log::info!("Total read_page_count: {}", read_page_count);
    log::info!("Total unread_page_count: {}", unread_page_count);
}

fn start_migration_incoming(context : &mut MigrationPage){
    log::info!("Incoming migration started");
    let mut hash = Sha256::new();
    let mut block_count = 0;

    loop {
        if context.0.data_reg == SNP_MIGRATION_DATA_READY {
            hash.update(&context.0.buffer);
            context.0.data_reg = SNP_MIGRATION_DATA_READ;
            block_count += 1;
            if block_count % 100_000 == 0 {
                log::info!("Blocks received {}", block_count);
            }
        }
        // FIXME: Only for debugging. It should be this thread that ends the migration not
        // hypervisor.
        if context.0.status_reg == SNP_MIGRATION_STATUS_COMPLETED &&
           context.0.data_reg == SNP_MIGRATION_DATA_READ {
            break;
        }
    }
    log::info!("Received blocks: {:?}", block_count);
    log::info!("Data hash: {:?}", hash.finalize());
    log::info!("Incoming migration finished");
}

pub extern "C" fn migration_agent(cpu_index: usize) {
    set_affinity(cpu_index);
    log::info!("Started migration thread.");

    let mut mig_page = MigrationPage::new().expect("Cannot create migration page");
    let mig_page_pa = virt_to_phys(mig_page.0.vaddr());
    log::info!("Migration page is at address: {:x?}", mig_page_pa);

    let mut status;
    loop {
        status = mig_page.0.status_reg;
        if status == SNP_MIGRATION_STATUS_RUNNING {
            start_migration(&mut mig_page);
        }
        if status == SNP_MIGRATION_STATUS_INCOMING {
            start_migration_incoming(&mut mig_page);
        }
        schedule();
    }
}
#[repr(C)]
#[derive(Debug, FromZeros)]
pub struct MigrationContext {
    status_reg: u8,
    data_reg: u8,
    reserved: [u8; 0x800 - 2],
    buffer: [u8; DATA_BUFFER_SIZE],
}

#[derive(Debug)]
pub struct MigrationPage(PageBox<MigrationContext>);

impl MigrationPage {
    pub fn new() -> Result<Self, SvsmError> {
        let page = PageBox::<MigrationContext>::try_new_zeroed()?;
        let vaddr = page.vaddr();
        let paddr = virt_to_phys(vaddr);

        pvalidate(vaddr, PageSize::Regular, PvalidateOp::Invalid)?;

        unsafe {
            invalidate_page_msr(paddr)?;
        }
        this_cpu().get_pgtable().set_shared_4k(vaddr)?;
        flush_tlb_global_sync();

        Ok(Self(page))
    }

    fn write_new_page(&mut self, buffer: &[u8; DATA_BUFFER_SIZE]) {
        // Wait for the until the previous block is process by hypervisor
        while self.0.data_reg != SNP_MIGRATION_DATA_READ {}
        self.0.buffer = *buffer;
        self.0.data_reg = SNP_MIGRATION_DATA_READY;
    }
}
