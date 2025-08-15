use goblin::mach::{Mach, MachO};

fn main() {
    // Test endianness detection
    let data_le = vec![0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01]; // LE
    let data_be = vec![0xfe, 0xed, 0xfa, 0xcf, 0x01, 0x00, 0x00, 0x07]; // BE
    
    println!("Little endian magic: 0x{:08x}", 0xfeedfacf);
    println!("Big endian magic: 0x{:08x}", 0xcffaedfe);
    println!("MH_MAGIC_64 LE: 0x{:08x}", goblin::mach::header::MH_MAGIC_64);
    println!("MH_CIGAM_64 BE: 0x{:08x}", goblin::mach::header::MH_CIGAM_64);
    println!("MH_PIE flag: 0x{:08x}", goblin::mach::header::MH_PIE);
    
    // Parse LE data
    if let Ok(mach) = Mach::parse(&data_le) {
        if let Mach::Binary(macho) = mach {
            println!("LE parsed magic: 0x{:08x}", macho.header.magic);
        }
    }
    
    // Parse BE data  
    if let Ok(mach) = Mach::parse(&data_be) {
        if let Mach::Binary(macho) = mach {
            println!("BE parsed magic: 0x{:08x}", macho.header.magic);
        }
    }
}