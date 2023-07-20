// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use crate::address::VirtAddr;
use crate::cpu::percpu::this_cpu_mut;
use crate::elf;
use crate::error::SvsmError;
use crate::fs::{list_dir, open};
use crate::mm::vm::{Mapping, VMFileMapping, VMFileMappingPermission};
use crate::task::{create_task_for_module, TaskNode};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

#[derive(Debug)]
pub struct ModuleLoader {
    pub modules: Vec<Module>,
}

impl ModuleLoader {
    pub fn enumerate() -> Result<Self, SvsmError> {
        let mut modules: Vec<Module> = Vec::new();

        let module_files = list_dir("/modules")?;
        for module in module_files {
            let path = String::from("/modules/") + &module.as_str();
            // Each module is an ELF file
            let module = Module::load(path.as_str());
            match module {
                Ok(mut m) => {
                    create_task_for_module(&mut m, 0, None)?;
                    modules.push(m);
                    log::info!("Module {} loaded ok", path);
                }
                Err(_) => log::info!("Module {} load failed", path),
            }
        }
        Ok(Self { modules })
    }
}

#[derive(Debug)]
pub struct Module {
    file_segments: Vec<(VirtAddr, Arc<Mapping>)>,
    entry_point: extern "C" fn(),
    task_node: Option<Arc<TaskNode>>,
}

struct SegmentInfo {
    vaddr: VirtAddr,
    file_offset: usize,
    size: usize,
    flags: VMFileMappingPermission,
}

impl Module {
    pub fn entry_point(&self) -> extern "C" fn() {
        self.entry_point
    }

    pub fn assign(&mut self, task_node: Arc<TaskNode>) -> Result<(), SvsmError> {
        self.task_node = Some(task_node.clone());
        let mut task = task_node.task.lock_write();
        for (vaddr, segment) in &self.file_segments {
            task.vmr_user().insert_at(*vaddr, segment.clone())?;
        }
        Ok(())
    }

    fn get_segment_info(path: &str) -> Result<(extern "C" fn(), Vec<SegmentInfo>), SvsmError> {
        // Temporarily map the file's physical memory into the percpu virtual address space
        let file = open(path)?;
        let file_size = file.size();
        let file_mapping = Arc::new(Mapping::new(VMFileMapping::new(
            file,
            0,
            file_size,
            crate::mm::vm::VMFileMappingPermission::Read,
        )?));
        let mapping = this_cpu_mut().new_mapping(file_mapping)?;

        let buf =
            unsafe { core::slice::from_raw_parts_mut(mapping.virt_addr().as_mut_ptr(), file_size) };

        let elf = match elf::Elf64File::read(buf) {
            Ok(elf) => elf,
            Err(_) => return Err(SvsmError::Module),
        };
        let default_base = elf.default_base();
        let entry_point = unsafe { core::mem::transmute(elf.get_entry(default_base) as *const ()) };

        let mut info = Vec::<SegmentInfo>::new();

        // Setup the pagetable for the virtual memory ranges described in the file
        for segment in elf.image_load_segment_iter(default_base) {
            let vaddr_start = VirtAddr::from(segment.vaddr_range.vaddr_begin);
            let flags = if segment.flags.contains(elf::Elf64PhdrFlags::EXECUTE) {
                VMFileMappingPermission::Execute
            } else if segment.flags.contains(elf::Elf64PhdrFlags::WRITE) {
                VMFileMappingPermission::Write
            } else {
                VMFileMappingPermission::Read
            };

            info.push(SegmentInfo {
                vaddr: vaddr_start,
                file_offset: segment.file_range.offset_begin,
                size: segment.file_range.offset_end - segment.file_range.offset_begin,
                flags,
            });
        }
        Ok((entry_point, info))
    }

    fn load(path: &str) -> Result<Self, SvsmError> {
        let (entry_point, segments) = Module::get_segment_info(path)?;
        let mut file_segments = Vec::<(VirtAddr, Arc<Mapping>)>::new();
        for seg in segments {
            let file = open(path)?;
            let mapping = Arc::new(Mapping::new(VMFileMapping::new(
                file,
                seg.file_offset,
                seg.size,
                seg.flags,
            )?));
            file_segments.push((seg.vaddr, mapping));
        }

        Ok(Module {
            file_segments,
            entry_point,
            task_node: None,
        })
    }
}
