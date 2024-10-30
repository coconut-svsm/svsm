use cpuarch::vmsa::VMSA;

use crate::{cpu::percpu::{this_cpu, this_cpu_unsafe}, mm::PerCPUPageMappingGuard, process_manager::process::{ProcessID, PROCESS_STORE}, protocols::{errors::SvsmReqError, RequestParams}};

const TRUSTLET_VMPL: u64 = 1;

pub fn invoke_trustlet(params: &mut RequestParams) -> Result<(), SvsmReqError> {

    log::info!("Invoking Trustlet");

    let id = params.rcx;

    let trustlet = PROCESS_STORE.get(ProcessID(id.try_into().unwrap()));

    log::info!("{:?}", trustlet);

    // Getting the current processes VMSA
    let vmsa_mapping = PerCPUPageMappingGuard::create_4k(trustlet.context.vmsa).unwrap();
    let vmsa: &mut VMSA = unsafe { vmsa_mapping.virt_addr().as_mut_ptr::<VMSA>().as_mut().unwrap() };

    let apic_id = this_cpu().get_apic_id();

   
    loop {
        unsafe {(*(*this_cpu_unsafe()).ghcb).ap_create(trustlet.context.vmsa,
                                                       u64::from(apic_id),
                                                       TRUSTLET_VMPL,
                                                       trustlet.context.sev_features).unwrap()}
        if !handle_process_request(vmsa){
            break;
        }
    }


    Ok(())


}

fn handle_process_request(vmsa: &mut VMSA) -> bool {
    let rax = vmsa.rax;
    vmsa.rax = 0;

    // The Trustlet exits with cpuid (2 Bytes)
    vmsa.rip += 2;

    log::info!("Trustlet exited with {}", rax);

    false
}
