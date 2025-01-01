use kvm_ioctls::{Kvm, VcpuFd};
use kvm_bindings::{kvm_userspace_memory_region, kvm_regs, kvm_sregs};
use anyhow::{Context, Result};
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};
use vm_memory::bitmap::AtomicBitmap;

fn main() -> Result<()> {
    // open /dev/kvm
    let kvm = Kvm::new()?;
    println!("{:?}", kvm);

    // create a VM
    let vm_fd = kvm.create_vm()?;
    println!("{:?}", vm_fd);

    // guest memory
    let memory_size = 0x1000; // 4KB
    
    let guest_phys_addr = GuestAddress(0x0000_0000);
    println!("{:?}", guest_phys_addr);

    let gm = GuestMemoryMmap::<AtomicBitmap>::from_ranges(&[(guest_phys_addr, memory_size)])?;
    println!("{:?}", gm);

    let mem_region = kvm_userspace_memory_region {
        slot: 0,

        // the virtual address inside the host user-space process
        // as the VM is running in the host's user-space
        userspace_addr: gm.get_host_address(guest_phys_addr).unwrap() as u64,

        memory_size: memory_size as u64,

        // the physical address inside the guest (GPA)
        // not Guest virtual addresse (GVA)
        guest_phys_addr: guest_phys_addr.0,
        
        flags: 0,
    };
    println!("{:?}", mem_region);

    unsafe {
        vm_fd.set_user_memory_region(mem_region)?;
    }

    // create a vCPU
    let mut vcpu_fd = vm_fd.create_vcpu(0)?;
    println!("{:?}", vcpu_fd);

    println!("Successfully created VM and vCPU.");

    // print to “COM1” at port 0x3F8 can show “Hello, world!” if you connect that serial port to standard output on the host. 
    let code = [
        0xBA, 0xF8, 0x03,    // mov dx, 0x3F8
        0xB0, b'H',          // mov al, 'H'
        0xEE,                // out dx, al
        0xB0, b'e',
        0xEE,
        0xB0, b'l',
        0xEE,
        0xB0, b'l',
        0xEE,
        0xB0, b'o',
        0xEE,
        0xB0, b'\n',
        0xEE,
        0xF4                 // hlt
    ];

    // write your code bytes into the guest memory
    gm.write(&code, guest_phys_addr).context("Failed to write code into guest memory")?;
    println!("Successfully wrote code into guest memory. {:?}", code);

    setup_registers(&vcpu_fd, guest_phys_addr.0)?;

    loop {
        match vcpu_fd.run()? {
            kvm_ioctls::VcpuExit::Hlt => {
                println!("Guest halted!");
                break;
            }
            kvm_ioctls::VcpuExit::IoOut(port, data) => {
                // If port == 0x3F8, data contains the bytes your guest “out” instructions wrote
                if port == 0x3F8 {
                    for &byte in data {
                        print!("{}", byte as char);
                    }
                }
            }
            kvm_ioctls::VcpuExit::Shutdown => {
                println!("Guest shutdown");
                break;
            }
            exit_reason => {
                println!("Unhandled exit: {:?}", exit_reason);
                break;
            }
        }
    }

    println!("VM is running... (press Ctrl+C to exit)");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    //Ok(())
}

fn setup_registers(vcpu_fd: &VcpuFd, entry_point: u64) -> Result<()> {
    // 1. Get special registers (sregs)
    let mut sregs: kvm_sregs = vcpu_fd.get_sregs()?;

    // Setup real-mode segments: base=0, limit=0xFFFF, etc.
    // Typically you set them to a “flat real mode”.
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    sregs.ds.base = 0;
    sregs.ds.selector = 0;
    sregs.es.base = 0;
    sregs.es.selector = 0;
    sregs.fs.base = 0;
    sregs.fs.selector = 0;
    sregs.gs.base = 0;
    sregs.gs.selector = 0;
    sregs.ss.base = 0;
    sregs.ss.selector = 0;

    // Clear CR0[PE] bit to ensure real mode
    sregs.cr0 &= !0x1;

    // Write sregs back
    vcpu_fd.set_sregs(&sregs)?;

    // 2. Get general-purpose regs
    let mut regs: kvm_regs = vcpu_fd.get_regs()?;
    regs.rip = entry_point;
    regs.rax = 0;
    regs.rbx = 0;
    regs.rcx = 0;
    regs.rdx = 0;
    // ... etc ...
    vcpu_fd.set_regs(&regs)?;

    println!("Successfully setup registers.");

    Ok(())
}