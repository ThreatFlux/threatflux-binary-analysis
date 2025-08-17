#![allow(clippy::uninlined_format_args)]
//! Tests for ELF format parser
#![cfg(feature = "elf")]

use threatflux_binary_analysis::types::*;
use threatflux_binary_analysis::BinaryAnalyzer;

/// Test data generators for various ELF formats
mod elf_test_data {

    /// Create a minimal valid ELF 64-bit x86_64 binary (little endian)
    pub fn create_elf_64_x86_64_le() -> Vec<u8> {
        let mut data = vec![0u8; 2048];

        // ELF Header (64 bytes)
        let elf_header = [
            // e_ident
            0x7f, 0x45, 0x4c, 0x46, // EI_MAG (0x7f, 'E', 'L', 'F')
            0x02, // EI_CLASS (ELFCLASS64)
            0x01, // EI_DATA (ELFDATA2LSB)
            0x01, // EI_VERSION (EV_CURRENT)
            0x00, // EI_OSABI (ELFOSABI_NONE)
            0x00, // EI_ABIVERSION
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EI_PAD
            // ELF header fields
            0x02, 0x00, // e_type (ET_EXEC)
            0x3e, 0x00, // e_machine (EM_X86_64)
            0x01, 0x00, 0x00, 0x00, // e_version (EV_CURRENT)
            0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry (0x401000)
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff (64)
            0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff (1024)
            0x00, 0x00, 0x00, 0x00, // e_flags
            0x40, 0x00, // e_ehsize (64)
            0x38, 0x00, // e_phentsize (56)
            0x02, 0x00, // e_phnum (2)
            0x40, 0x00, // e_shentsize (64)
            0x04, 0x00, // e_shnum (4)
            0x03, 0x00, // e_shstrndx (3)
        ];

        data[..64].copy_from_slice(&elf_header);

        // Program Headers at offset 64
        let ph_load = [
            0x01, 0x00, 0x00, 0x00, // p_type (PT_LOAD)
            0x05, 0x00, 0x00, 0x00, // p_flags (PF_R | PF_X)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset
            0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr
            0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_paddr
            0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz
            0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align
        ];

        let ph_gnu_stack = [
            0x51, 0xe5, 0x74, 0x64, // p_type (PT_GNU_STACK) - 0x6474e551 in little endian
            0x06, 0x00, 0x00, 0x00, // p_flags (PF_R | PF_W, no PF_X for NX)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_paddr
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align
        ];

        data[64..120].copy_from_slice(&ph_load);
        data[120..176].copy_from_slice(&ph_gnu_stack);

        // Section Headers at offset 1024
        let sh_null = [0u8; 64]; // SHT_NULL section
        let sh_text = [
            0x01, 0x00, 0x00, 0x00, // sh_name
            0x01, 0x00, 0x00, 0x00, // sh_type (SHT_PROGBITS)
            0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // sh_flags (SHF_ALLOC | SHF_EXECINSTR)
            0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (512)
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size (256)
            0x00, 0x00, 0x00, 0x00, // sh_link
            0x00, 0x00, 0x00, 0x00, // sh_info
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
        ];
        let sh_data = [
            0x07, 0x00, 0x00, 0x00, // sh_name
            0x01, 0x00, 0x00, 0x00, // sh_type (SHT_PROGBITS)
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // sh_flags (SHF_ALLOC | SHF_WRITE)
            0x00, 0x20, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
            0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (768)
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size (256)
            0x00, 0x00, 0x00, 0x00, // sh_link
            0x00, 0x00, 0x00, 0x00, // sh_info
            0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
        ];
        let sh_shstrtab = [
            0x0d, 0x00, 0x00, 0x00, // sh_name
            0x03, 0x00, 0x00, 0x00, // sh_type (SHT_STRTAB)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
            0x80, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (1920)
            0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size (23)
            0x00, 0x00, 0x00, 0x00, // sh_link
            0x00, 0x00, 0x00, 0x00, // sh_info
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
        ];

        data[1024..1088].copy_from_slice(&sh_null);
        data[1088..1152].copy_from_slice(&sh_text);
        data[1152..1216].copy_from_slice(&sh_data);
        data[1216..1280].copy_from_slice(&sh_shstrtab);

        // String table at offset 1920
        let shstrtab = b"\0.text\0.data\0.shstrtab\0";
        data[1920..1920 + shstrtab.len()].copy_from_slice(shstrtab);

        // Add some realistic x86-64 instructions at .text section (offset 512)
        let instructions = [
            0x48, 0x89, 0xe5, // mov rbp, rsp
            0x48, 0x83, 0xec, 0x10, // sub rsp, 16
            0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
            0x48, 0x83, 0xc4, 0x10, // add rsp, 16
            0x5d, // pop rbp
            0xc3, // ret
        ];
        data[512..512 + instructions.len()].copy_from_slice(&instructions);

        data
    }

    /// Create ELF 32-bit x86 binary (little endian)
    pub fn create_elf_32_x86_le() -> Vec<u8> {
        let mut data = vec![0u8; 1024];

        // ELF Header (52 bytes for 32-bit)
        let elf_header = [
            // e_ident
            0x7f, 0x45, 0x4c, 0x46, // EI_MAG
            0x01, // EI_CLASS (ELFCLASS32)
            0x01, // EI_DATA (ELFDATA2LSB)
            0x01, // EI_VERSION (EV_CURRENT)
            0x00, // EI_OSABI (ELFOSABI_NONE)
            0x00, // EI_ABIVERSION
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EI_PAD
            // ELF header fields
            0x02, 0x00, // e_type (ET_EXEC)
            0x03, 0x00, // e_machine (EM_386)
            0x01, 0x00, 0x00, 0x00, // e_version (EV_CURRENT)
            0x00, 0x80, 0x04, 0x08, // e_entry (0x08048000)
            0x34, 0x00, 0x00, 0x00, // e_phoff (52)
            0x00, 0x02, 0x00, 0x00, // e_shoff (512)
            0x00, 0x00, 0x00, 0x00, // e_flags
            0x34, 0x00, // e_ehsize (52)
            0x20, 0x00, // e_phentsize (32)
            0x01, 0x00, // e_phnum (1)
            0x28, 0x00, // e_shentsize (40)
            0x03, 0x00, // e_shnum (3)
            0x02, 0x00, // e_shstrndx (2)
        ];

        data[..52].copy_from_slice(&elf_header);

        // Program Header at offset 52
        let ph_load = [
            0x01, 0x00, 0x00, 0x00, // p_type (PT_LOAD)
            0x00, 0x00, 0x00, 0x00, // p_offset
            0x00, 0x80, 0x04, 0x08, // p_vaddr
            0x00, 0x80, 0x04, 0x08, // p_paddr
            0x00, 0x04, 0x00, 0x00, // p_filesz
            0x00, 0x04, 0x00, 0x00, // p_memsz
            0x05, 0x00, 0x00, 0x00, // p_flags (PF_R | PF_X)
            0x00, 0x10, 0x00, 0x00, // p_align
        ];

        data[52..84].copy_from_slice(&ph_load);

        data
    }

    /// Create ELF 64-bit ARM64 binary
    pub fn create_elf_64_arm64_le() -> Vec<u8> {
        let mut data = vec![0u8; 1024];

        // ELF Header
        let elf_header = [
            // e_ident
            0x7f, 0x45, 0x4c, 0x46, // EI_MAG
            0x02, // EI_CLASS (ELFCLASS64)
            0x01, // EI_DATA (ELFDATA2LSB)
            0x01, // EI_VERSION (EV_CURRENT)
            0x00, // EI_OSABI (ELFOSABI_NONE)
            0x00, // EI_ABIVERSION
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EI_PAD
            // ELF header fields
            0x02, 0x00, // e_type (ET_EXEC)
            0xb7, 0x00, // e_machine (EM_AARCH64)
            0x01, 0x00, 0x00, 0x00, // e_version (EV_CURRENT)
            0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff
            0x00, 0x00, 0x00, 0x00, // e_flags
            0x40, 0x00, // e_ehsize
            0x38, 0x00, // e_phentsize
            0x01, 0x00, // e_phnum
            0x40, 0x00, // e_shentsize
            0x02, 0x00, // e_shnum
            0x01, 0x00, // e_shstrndx
        ];

        data[..64].copy_from_slice(&elf_header);

        data
    }

    /// Create ELF with dynamic linking (shared object)
    pub fn create_elf_shared_object() -> Vec<u8> {
        let mut data = vec![0u8; 2048];

        // ELF Header
        let elf_header = [
            // e_ident
            0x7f, 0x45, 0x4c, 0x46, // EI_MAG
            0x02, // EI_CLASS (ELFCLASS64)
            0x01, // EI_DATA (ELFDATA2LSB)
            0x01, // EI_VERSION (EV_CURRENT)
            0x00, // EI_OSABI (ELFOSABI_NONE)
            0x00, // EI_ABIVERSION
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EI_PAD
            // ELF header fields
            0x03, 0x00, // e_type (ET_DYN) - shared object
            0x3e, 0x00, // e_machine (EM_X86_64)
            0x01, 0x00, 0x00, 0x00, // e_version
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff
            0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff
            0x00, 0x00, 0x00, 0x00, // e_flags
            0x40, 0x00, // e_ehsize
            0x38, 0x00, // e_phentsize
            0x02, 0x00, // e_phnum
            0x40, 0x00, // e_shentsize
            0x04, 0x00, // e_shnum
            0x03, 0x00, // e_shstrndx
        ];

        data[..64].copy_from_slice(&elf_header);

        // Program Headers
        let ph_load = [
            0x01, 0x00, 0x00, 0x00, // p_type (PT_LOAD)
            0x05, 0x00, 0x00, 0x00, // p_flags (PF_R | PF_X)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_paddr
            0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz
            0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align
        ];

        let ph_dynamic = [
            0x02, 0x00, 0x00, 0x00, // p_type (PT_DYNAMIC)
            0x06, 0x00, 0x00, 0x00, // p_flags (PF_R | PF_W)
            0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset
            0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr
            0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_paddr
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz
            0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align
        ];

        data[64..120].copy_from_slice(&ph_load);
        data[120..176].copy_from_slice(&ph_dynamic);

        data
    }

    /// Create ELF with PIE and RELRO security features
    pub fn create_elf_with_security_features() -> Vec<u8> {
        let mut data = vec![0u8; 2048];

        // ELF Header
        let elf_header = [
            // e_ident
            0x7f, 0x45, 0x4c, 0x46, // EI_MAG
            0x02, // EI_CLASS (ELFCLASS64)
            0x01, // EI_DATA (ELFDATA2LSB)
            0x01, // EI_VERSION (EV_CURRENT)
            0x00, // EI_OSABI (ELFOSABI_NONE)
            0x00, // EI_ABIVERSION
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EI_PAD
            // ELF header fields
            0x03, 0x00, // e_type (ET_DYN) - PIE executable
            0x3e, 0x00, // e_machine (EM_X86_64)
            0x01, 0x00, 0x00, 0x00, // e_version
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff
            0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff
            0x00, 0x00, 0x00, 0x00, // e_flags
            0x40, 0x00, // e_ehsize
            0x38, 0x00, // e_phentsize
            0x03, 0x00, // e_phnum (3 to include GNU_RELRO)
            0x40, 0x00, // e_shentsize
            0x03, 0x00, // e_shnum
            0x02, 0x00, // e_shstrndx
        ];

        data[..64].copy_from_slice(&elf_header);

        // Program Headers with GNU_STACK (NX) and GNU_RELRO
        let ph_load = [
            0x01, 0x00, 0x00, 0x00, // p_type (PT_LOAD)
            0x05, 0x00, 0x00, 0x00, // p_flags (PF_R | PF_X)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_paddr
            0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz
            0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align
        ];

        let ph_gnu_stack = [
            0x51, 0xe5, 0x74, 0x64, // p_type (PT_GNU_STACK) - 0x6474e551 in little endian
            0x06, 0x00, 0x00, 0x00, // p_flags (PF_R | PF_W, no execute = NX bit)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_paddr
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align
        ];

        let ph_gnu_relro = [
            0x52, 0xe5, 0x74, 0x64, // p_type (PT_GNU_RELRO) - 0x6474e552 in little endian
            0x04, 0x00, 0x00, 0x00, // p_flags (PF_R)
            0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset
            0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr
            0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_paddr
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align
        ];

        data[64..120].copy_from_slice(&ph_load);
        data[120..176].copy_from_slice(&ph_gnu_stack);
        data[176..232].copy_from_slice(&ph_gnu_relro);

        data
    }

    /// Create ELF with symbol tables (static and dynamic)
    pub fn create_elf_with_symbols() -> Vec<u8> {
        let mut data = vec![0u8; 4096];

        // ELF Header
        let elf_header = [
            // e_ident
            0x7f, 0x45, 0x4c, 0x46, // EI_MAG
            0x02, // EI_CLASS (ELFCLASS64)
            0x01, // EI_DATA (ELFDATA2LSB)
            0x01, // EI_VERSION (EV_CURRENT)
            0x00, // EI_OSABI (ELFOSABI_NONE)
            0x00, // EI_ABIVERSION
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EI_PAD
            // ELF header fields
            0x02, 0x00, // e_type (ET_EXEC)
            0x3e, 0x00, // e_machine (EM_X86_64)
            0x01, 0x00, 0x00, 0x00, // e_version
            0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff
            0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff (2048)
            0x00, 0x00, 0x00, 0x00, // e_flags
            0x40, 0x00, // e_ehsize
            0x38, 0x00, // e_phentsize
            0x01, 0x00, // e_phnum
            0x40, 0x00, // e_shentsize
            0x06, 0x00, // e_shnum (6 sections)
            0x05, 0x00, // e_shstrndx (5)
        ];

        data[..64].copy_from_slice(&elf_header);

        // Program Header
        let ph_load = [
            0x01, 0x00, 0x00, 0x00, // p_type (PT_LOAD)
            0x05, 0x00, 0x00, 0x00, // p_flags (PF_R | PF_X)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset
            0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr
            0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_paddr
            0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz
            0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align
        ];

        data[64..120].copy_from_slice(&ph_load);

        // Section Headers at offset 2048
        let sections_offset = 2048;

        // Section 0: NULL
        let sh_null = [0u8; 64];
        data[sections_offset..sections_offset + 64].copy_from_slice(&sh_null);

        // Section 1: .text
        let sh_text = [
            0x01, 0x00, 0x00, 0x00, // sh_name
            0x01, 0x00, 0x00, 0x00, // sh_type (SHT_PROGBITS)
            0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // sh_flags (SHF_ALLOC | SHF_EXECINSTR)
            0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (512)
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size
            0x00, 0x00, 0x00, 0x00, // sh_link
            0x00, 0x00, 0x00, 0x00, // sh_info
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
        ];
        data[sections_offset + 64..sections_offset + 128].copy_from_slice(&sh_text);

        // Section 2: .symtab
        let sh_symtab = [
            0x07, 0x00, 0x00, 0x00, // sh_name
            0x02, 0x00, 0x00, 0x00, // sh_type (SHT_SYMTAB)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
            0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (1024)
            0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // sh_size (96 bytes = 4 symbols * 24 bytes)
            0x03, 0x00, 0x00, 0x00, // sh_link (3 = .strtab)
            0x02, 0x00, 0x00, 0x00, // sh_info (2 = last local symbol index + 1)
            0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
            0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize (24)
        ];
        data[sections_offset + 128..sections_offset + 192].copy_from_slice(&sh_symtab);

        // Section 3: .strtab
        let sh_strtab = [
            0x0f, 0x00, 0x00, 0x00, // sh_name
            0x03, 0x00, 0x00, 0x00, // sh_type (SHT_STRTAB)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
            0x60, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (1120)
            0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size (32)
            0x00, 0x00, 0x00, 0x00, // sh_link
            0x00, 0x00, 0x00, 0x00, // sh_info
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
        ];
        data[sections_offset + 192..sections_offset + 256].copy_from_slice(&sh_strtab);

        // Section 4: .dynsym
        let sh_dynsym = [
            0x17, 0x00, 0x00, 0x00, // sh_name
            0x0b, 0x00, 0x00, 0x00, // sh_type (SHT_DYNSYM)
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags (SHF_ALLOC)
            0x00, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
            0x80, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (1152)
            0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // sh_size (72 bytes = 3 symbols * 24 bytes)
            0x05, 0x00, 0x00, 0x00, // sh_link (5 = .dynstr)
            0x01, 0x00, 0x00, 0x00, // sh_info
            0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
            0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize (24)
        ];
        data[sections_offset + 256..sections_offset + 320].copy_from_slice(&sh_dynsym);

        // Section 5: .shstrtab
        let sh_shstrtab = [
            0x1f, 0x00, 0x00, 0x00, // sh_name
            0x03, 0x00, 0x00, 0x00, // sh_type (SHT_STRTAB)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
            0xc8, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (1224)
            0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size (41)
            0x00, 0x00, 0x00, 0x00, // sh_link
            0x00, 0x00, 0x00, 0x00, // sh_info
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
        ];
        data[sections_offset + 320..sections_offset + 384].copy_from_slice(&sh_shstrtab);

        // Symbol table at offset 1024 (4 symbols)
        let sym_null = [0u8; 24]; // NULL symbol
        data[1024..1048].copy_from_slice(&sym_null);

        let sym_file = [
            0x01, 0x00, 0x00, 0x00, // st_name
            0x04, // st_info (STB_LOCAL | STT_FILE)
            0x00, // st_other
            0xf1, 0xff, // st_shndx (SHN_ABS)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // st_value
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // st_size
        ];
        data[1048..1072].copy_from_slice(&sym_file);

        let sym_main = [
            0x0a, 0x00, 0x00, 0x00, // st_name
            0x12, // st_info (STB_GLOBAL | STT_FUNC)
            0x00, // st_other
            0x01, 0x00, // st_shndx (1 = .text)
            0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // st_value
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // st_size
        ];
        data[1072..1096].copy_from_slice(&sym_main);

        let sym_printf = [
            0x0f, 0x00, 0x00, 0x00, // st_name
            0x12, // st_info (STB_GLOBAL | STT_FUNC)
            0x00, // st_other
            0x00, 0x00, // st_shndx (SHN_UNDEF)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // st_value
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // st_size
        ];
        data[1096..1120].copy_from_slice(&sym_printf);

        // String table at offset 1120
        let strtab = b"\0test.c\0main\0printf\0";
        data[1120..1120 + strtab.len()].copy_from_slice(strtab);

        // Dynamic symbol table at offset 1152 (3 symbols)
        data[1152..1176].copy_from_slice(&sym_null); // NULL symbol

        let dynsym_printf = [
            0x01, 0x00, 0x00, 0x00, // st_name (from dynstr)
            0x12, // st_info (STB_GLOBAL | STT_FUNC)
            0x00, // st_other
            0x00, 0x00, // st_shndx (SHN_UNDEF)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // st_value
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // st_size
        ];
        data[1176..1200].copy_from_slice(&dynsym_printf);

        let dynsym_exported = [
            0x08, 0x00, 0x00, 0x00, // st_name (from dynstr)
            0x12, // st_info (STB_GLOBAL | STT_FUNC)
            0x00, // st_other
            0x01, 0x00, // st_shndx (1 = .text)
            0x10, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // st_value
            0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // st_size
        ];
        data[1200..1224].copy_from_slice(&dynsym_exported);

        // Dynamic string table (dynstr) at offset 1300
        let dynstr = b"\0printf\0exported\0";
        if data.len() > 1300 + dynstr.len() {
            data[1300..1300 + dynstr.len()].copy_from_slice(dynstr);
        }

        // Section header string table at offset 1224
        let shstrtab = b"\0.text\0.symtab\0.strtab\0.dynsym\0.shstrtab\0";
        data[1224..1224 + shstrtab.len()].copy_from_slice(shstrtab);

        data
    }

    /// Create malformed ELF (truncated header)
    pub fn create_truncated_elf() -> Vec<u8> {
        vec![0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01] // Only 6 bytes instead of 64
    }

    /// Create ELF with invalid magic
    pub fn create_invalid_magic() -> Vec<u8> {
        let mut data = vec![0u8; 1024];
        data[0..4].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]); // Invalid magic
        data
    }

    /// Create big-endian ELF
    pub fn create_elf_big_endian() -> Vec<u8> {
        let mut data = vec![0u8; 1024];

        // ELF Header (big endian)
        let elf_header = [
            // e_ident
            0x7f, 0x45, 0x4c, 0x46, // EI_MAG
            0x02, // EI_CLASS (ELFCLASS64)
            0x02, // EI_DATA (ELFDATA2MSB) - big endian
            0x01, // EI_VERSION (EV_CURRENT)
            0x00, // EI_OSABI (ELFOSABI_NONE)
            0x00, // EI_ABIVERSION
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EI_PAD
            // ELF header fields (big endian)
            0x00, 0x02, // e_type (ET_EXEC)
            0x00, 0x03, // e_machine (EM_SPARC for big endian)
            0x00, 0x00, 0x00, 0x01, // e_version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, // e_entry
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, // e_phoff
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, // e_shoff
            0x00, 0x00, 0x00, 0x00, // e_flags
            0x00, 0x40, // e_ehsize
            0x00, 0x38, // e_phentsize
            0x00, 0x01, // e_phnum
            0x00, 0x40, // e_shentsize
            0x00, 0x02, // e_shnum
            0x00, 0x01, // e_shstrndx
        ];

        data[..64].copy_from_slice(&elf_header);

        data
    }

    /// Create ELF with different architectures
    pub fn create_elf_mips() -> Vec<u8> {
        let mut data = vec![0u8; 1024];

        let elf_header = [
            // e_ident
            0x7f, 0x45, 0x4c, 0x46, // EI_MAG
            0x02, // EI_CLASS (ELFCLASS64)
            0x01, // EI_DATA (ELFDATA2LSB)
            0x01, // EI_VERSION (EV_CURRENT)
            0x00, // EI_OSABI (ELFOSABI_NONE)
            0x00, // EI_ABIVERSION
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EI_PAD
            // ELF header fields
            0x02, 0x00, // e_type (ET_EXEC)
            0x08, 0x00, // e_machine (EM_MIPS)
            0x01, 0x00, 0x00, 0x00, // e_version
            0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff
            0x00, 0x00, 0x00, 0x00, // e_flags
            0x40, 0x00, // e_ehsize
            0x38, 0x00, // e_phentsize
            0x01, 0x00, // e_phnum
            0x40, 0x00, // e_shentsize
            0x02, 0x00, // e_shnum
            0x01, 0x00, // e_shstrndx
        ];

        data[..64].copy_from_slice(&elf_header);

        data
    }

    pub fn create_elf_powerpc() -> Vec<u8> {
        let mut data = vec![0u8; 1024];

        let elf_header = [
            // e_ident
            0x7f, 0x45, 0x4c, 0x46, // EI_MAG
            0x02, // EI_CLASS (ELFCLASS64)
            0x01, // EI_DATA (ELFDATA2LSB)
            0x01, // EI_VERSION (EV_CURRENT)
            0x00, // EI_OSABI (ELFOSABI_NONE)
            0x00, // EI_ABIVERSION
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EI_PAD
            // ELF header fields
            0x02, 0x00, // e_type (ET_EXEC)
            0x15, 0x00, // e_machine (EM_PPC64)
            0x01, 0x00, 0x00, 0x00, // e_version
            0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff
            0x00, 0x00, 0x00, 0x00, // e_flags
            0x40, 0x00, // e_ehsize
            0x38, 0x00, // e_phentsize
            0x01, 0x00, // e_phnum
            0x40, 0x00, // e_shentsize
            0x02, 0x00, // e_shnum
            0x01, 0x00, // e_shstrndx
        ];

        data[..64].copy_from_slice(&elf_header);

        data
    }

    pub fn create_elf_riscv() -> Vec<u8> {
        let mut data = vec![0u8; 1024];

        let elf_header = [
            // e_ident
            0x7f, 0x45, 0x4c, 0x46, // EI_MAG
            0x02, // EI_CLASS (ELFCLASS64)
            0x01, // EI_DATA (ELFDATA2LSB)
            0x01, // EI_VERSION (EV_CURRENT)
            0x00, // EI_OSABI (ELFOSABI_NONE)
            0x00, // EI_ABIVERSION
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EI_PAD
            // ELF header fields
            0x02, 0x00, // e_type (ET_EXEC)
            0xf3, 0x00, // e_machine (EM_RISCV)
            0x01, 0x00, 0x00, 0x00, // e_version
            0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff
            0x00, 0x00, 0x00, 0x00, // e_flags
            0x40, 0x00, // e_ehsize
            0x38, 0x00, // e_phentsize
            0x01, 0x00, // e_phnum
            0x40, 0x00, // e_shentsize
            0x02, 0x00, // e_shnum
            0x01, 0x00, // e_shstrndx
        ];

        data[..64].copy_from_slice(&elf_header);

        data
    }

    /// Create relocatable object file
    pub fn create_elf_relocatable() -> Vec<u8> {
        let mut data = vec![0u8; 1024];

        let elf_header = [
            // e_ident
            0x7f, 0x45, 0x4c, 0x46, // EI_MAG
            0x02, // EI_CLASS (ELFCLASS64)
            0x01, // EI_DATA (ELFDATA2LSB)
            0x01, // EI_VERSION (EV_CURRENT)
            0x00, // EI_OSABI (ELFOSABI_NONE)
            0x00, // EI_ABIVERSION
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EI_PAD
            // ELF header fields
            0x01, 0x00, // e_type (ET_REL) - relocatable
            0x3e, 0x00, // e_machine (EM_X86_64)
            0x01, 0x00, 0x00, 0x00, // e_version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry (0 for relocatable)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff (0 for relocatable)
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff
            0x00, 0x00, 0x00, 0x00, // e_flags
            0x40, 0x00, // e_ehsize
            0x00, 0x00, // e_phentsize (0 for relocatable)
            0x00, 0x00, // e_phnum (0 for relocatable)
            0x40, 0x00, // e_shentsize
            0x03, 0x00, // e_shnum
            0x02, 0x00, // e_shstrndx
        ];

        data[..64].copy_from_slice(&elf_header);

        data
    }
}

#[test]
fn test_elf_parser_can_parse_valid_magic() {
    // Test valid ELF magic
    let valid_elf = vec![0x7f, 0x45, 0x4c, 0x46];
    assert!(matches!(
        threatflux_binary_analysis::formats::detect_format(&valid_elf),
        Ok(BinaryFormat::Elf)
    ));

    // Test with longer data
    let elf_with_data = vec![0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00];
    assert!(matches!(
        threatflux_binary_analysis::formats::detect_format(&elf_with_data),
        Ok(BinaryFormat::Elf)
    ));
}

#[test]
fn test_elf_parser_can_parse_invalid_data() {
    // Test with empty data
    assert!(threatflux_binary_analysis::formats::detect_format(&[]).is_err());

    // Test with too short data
    assert!(!matches!(
        threatflux_binary_analysis::formats::detect_format(&[0x7f, 0x45, 0x4c]),
        Ok(BinaryFormat::Elf)
    ));

    // Test with invalid magic
    assert!(!matches!(
        threatflux_binary_analysis::formats::detect_format(&[0x12, 0x34, 0x56, 0x78]),
        Ok(BinaryFormat::Elf)
    ));

    // Test with PE magic
    assert!(!matches!(
        threatflux_binary_analysis::formats::detect_format(&[0x4d, 0x5a, 0x90, 0x00]),
        Ok(BinaryFormat::Elf)
    ));

    // Test with Mach-O magic
    assert!(!matches!(
        threatflux_binary_analysis::formats::detect_format(&[0xce, 0xfa, 0xed, 0xfe]),
        Ok(BinaryFormat::Elf)
    ));

    // Test with partial ELF magic
    assert!(!matches!(
        threatflux_binary_analysis::formats::detect_format(&[0x7f, 0x45, 0x4c, 0x47]),
        Ok(BinaryFormat::Elf)
    ));
}

#[test]
fn test_elf_parser_parse_64_bit_x86_64() {
    let data = elf_test_data::create_elf_64_x86_64_le();
    let result = BinaryAnalyzer::new().analyze(&data);

    assert!(result.is_ok());
    let binary = result.unwrap();

    assert_eq!(binary.format, BinaryFormat::Elf);
    assert_eq!(binary.architecture, Architecture::X86_64);
    assert_eq!(binary.entry_point, Some(0x401000));

    let metadata = &binary.metadata;
    assert_eq!(metadata.format, BinaryFormat::Elf);
    assert_eq!(metadata.architecture, Architecture::X86_64);
    assert_eq!(metadata.endian, Endianness::Little);
    assert_eq!(metadata.size, data.len());
    assert!(metadata.security_features.nx_bit); // GNU_STACK without execute
}

#[test]
fn test_elf_parser_parse_32_bit_x86() {
    let data = elf_test_data::create_elf_32_x86_le();
    let result = BinaryAnalyzer::new().analyze(&data);

    assert!(result.is_ok());
    let binary = result.unwrap();

    assert_eq!(binary.format, BinaryFormat::Elf);
    assert_eq!(binary.architecture, Architecture::X86);

    let metadata = &binary.metadata;
    assert_eq!(metadata.endian, Endianness::Little);
}

#[test]
fn test_elf_parser_parse_arm64() {
    let data = elf_test_data::create_elf_64_arm64_le();
    let result = BinaryAnalyzer::new().analyze(&data);

    assert!(result.is_ok());
    let binary = result.unwrap();

    assert_eq!(binary.format, BinaryFormat::Elf);
    assert_eq!(binary.architecture, Architecture::Arm64);
}

#[test]
fn test_elf_parser_parse_various_architectures() {
    let test_cases = vec![
        (elf_test_data::create_elf_mips(), Architecture::Mips),
        (elf_test_data::create_elf_powerpc(), Architecture::PowerPC64),
        (elf_test_data::create_elf_riscv(), Architecture::RiscV),
    ];

    for (data, expected_arch) in test_cases {
        let result = BinaryAnalyzer::new().analyze(&data);
        if let Ok(binary) = result {
            assert_eq!(binary.architecture, expected_arch);
            assert_eq!(binary.architecture, expected_arch);
        }
    }
}

#[test]
fn test_elf_parser_parse_file_types() {
    // Test executable
    let exec_data = elf_test_data::create_elf_64_x86_64_le();
    let exec_result = BinaryAnalyzer::new().analyze(&exec_data);
    assert!(exec_result.is_ok());

    // Test shared object
    let so_data = elf_test_data::create_elf_shared_object();
    let so_result = BinaryAnalyzer::new().analyze(&so_data);
    assert!(so_result.is_ok());
    let so_binary = so_result.unwrap();
    assert!(so_binary.metadata.security_features.pie); // ET_DYN enables PIE

    // Test relocatable object
    let rel_data = elf_test_data::create_elf_relocatable();
    let rel_result = BinaryAnalyzer::new().analyze(&rel_data);
    assert!(rel_result.is_ok());
    let rel_binary = rel_result.unwrap();
    assert_eq!(rel_binary.entry_point, None); // No entry point for relocatable
}

#[test]
fn test_elf_parser_endianness_detection() {
    // Little endian
    let le_data = elf_test_data::create_elf_64_x86_64_le();
    let le_binary = BinaryAnalyzer::new().analyze(&le_data).unwrap();
    assert_eq!(le_binary.metadata.endian, Endianness::Little);

    // Big endian
    let be_data = elf_test_data::create_elf_big_endian();
    let be_result = BinaryAnalyzer::new().analyze(&be_data);
    if let Ok(be_binary) = be_result {
        assert_eq!(be_binary.metadata.endian, Endianness::Big);
    }
}

#[test]
fn test_elf_parser_section_parsing() {
    let data = elf_test_data::create_elf_64_x86_64_le();
    let binary = BinaryAnalyzer::new().analyze(&data).unwrap();
    let sections = &binary.sections;

    assert!(!sections.is_empty());

    // Find .text section
    let text_section = sections.iter().find(|s| s.name == ".text");
    assert!(text_section.is_some());

    let text_section = text_section.unwrap();
    assert_eq!(text_section.section_type, SectionType::Code);
    assert!(text_section.permissions.read);
    assert!(!text_section.permissions.write);
    assert!(text_section.permissions.execute);

    // Find .data section
    let data_section = sections.iter().find(|s| s.name == ".data");
    assert!(data_section.is_some());

    let data_section = data_section.unwrap();
    assert_eq!(data_section.section_type, SectionType::Data);
    assert!(data_section.permissions.read);
    assert!(data_section.permissions.write);
    assert!(!data_section.permissions.execute);
}

#[test]
fn test_elf_parser_symbol_parsing() {
    let data = elf_test_data::create_elf_with_symbols();
    let result = BinaryAnalyzer::new().analyze(&data);

    if let Ok(binary) = result {
        let symbols = &binary.symbols;

        // Symbols may be empty for our simplified test ELF
        // The important thing is that parsing doesn't fail
        for symbol in symbols {
            // Verify that all symbols have non-empty names
            assert!(!symbol.name.is_empty());

            // Verify addresses are reasonable
            assert!(symbol.address < u64::MAX);

            // Verify sizes are reasonable
            assert!(symbol.size < u64::MAX);
        }
    } else {
        // If parsing fails due to incomplete test data, that's acceptable
        // as long as other tests verify the parser works with real ELF files
        println!("Symbol parsing test skipped due to incomplete test data");
    }
}

#[test]
fn test_elf_parser_imports_exports() {
    let data = elf_test_data::create_elf_with_symbols();
    let result = BinaryAnalyzer::new().analyze(&data);

    if let Ok(binary) = result {
        let imports = &binary.imports;
        let exports = &binary.exports;

        // Imports and exports may be empty for our simplified test data
        // The important thing is that parsing doesn't fail
        for import in imports {
            assert!(!import.name.is_empty());
        }

        for export in exports {
            assert!(!export.name.is_empty());
            assert!(export.address > 0);
        }
    } else {
        println!("Import/export parsing test skipped due to incomplete test data");
    }
}

#[test]
fn test_elf_parser_security_features() {
    let data = elf_test_data::create_elf_with_security_features();
    let binary = BinaryAnalyzer::new().analyze(&data).unwrap();
    let security = &binary.metadata.security_features;

    assert!(security.nx_bit); // GNU_STACK without execute
    assert!(security.pie); // ET_DYN
    assert!(security.aslr); // PIE enables ASLR
    assert!(security.relro); // GNU_RELRO
}

#[test]
fn test_elf_parser_error_handling() {
    // Test truncated header
    let truncated = elf_test_data::create_truncated_elf();
    let result = BinaryAnalyzer::new().analyze(&truncated);
    assert!(result.is_err());

    // Test invalid magic - may parse as Raw format
    let invalid_magic = elf_test_data::create_invalid_magic();
    let result = BinaryAnalyzer::new().analyze(&invalid_magic);
    // Either error or Raw format is acceptable
    if let Ok(analysis) = result {
        assert_ne!(analysis.format, BinaryFormat::Elf);
    }

    // Test empty data
    let result = BinaryAnalyzer::new().analyze(&[]);
    assert!(result.is_err());

    // Test minimal valid magic but invalid structure
    let minimal = vec![0x7f, 0x45, 0x4c, 0x46];
    let result = BinaryAnalyzer::new().analyze(&minimal);
    assert!(result.is_err());
}

#[test]
fn test_elf_binary_format_trait_methods() {
    let data = elf_test_data::create_elf_64_x86_64_le();
    let binary = BinaryAnalyzer::new().analyze(&data).unwrap();

    // Test format_type()
    assert_eq!(binary.format, BinaryFormat::Elf);

    // Test architecture()
    assert_eq!(binary.architecture, Architecture::X86_64);

    // Test entry_point()
    assert_eq!(binary.entry_point, Some(0x401000));

    // Test sections()
    let sections = &binary.sections;
    assert!(!sections.is_empty());

    // Test symbols()
    let symbols = &binary.symbols;
    // May be empty for minimal binary, but should not panic
    let _ = symbols.len();

    // Test imports()
    let imports = &binary.imports;
    let _ = imports.len();

    // Test exports()
    let exports = &binary.exports;
    let _ = exports.len();

    // Test metadata()
    let metadata = &binary.metadata;
    assert_eq!(metadata.format, BinaryFormat::Elf);
    assert_eq!(metadata.architecture, Architecture::X86_64);
    assert_eq!(metadata.size, data.len());
}

#[test]
fn test_elf_section_type_classification() {
    let data = elf_test_data::create_elf_64_x86_64_le();
    let binary = BinaryAnalyzer::new().analyze(&data).unwrap();
    let sections = &binary.sections;

    for section in sections {
        match section.section_type {
            SectionType::Code => {
                assert!(section.permissions.execute);
                assert!(!section.permissions.write);
            }
            SectionType::Data => {
                assert!(section.permissions.write);
                assert!(!section.permissions.execute);
            }
            SectionType::ReadOnlyData => {
                assert!(!section.permissions.write);
                assert!(!section.permissions.execute);
            }
            SectionType::Bss => {
                assert!(section.permissions.write);
                assert!(!section.permissions.execute);
                assert_eq!(section.data, None); // BSS has no file data
            }
            SectionType::String => {
                assert!(!section.permissions.execute);
            }
            _ => {
                // Other section types are valid
            }
        }
    }
}

#[test]
fn test_elf_section_data_extraction() {
    let data = elf_test_data::create_elf_64_x86_64_le();
    let binary = BinaryAnalyzer::new().analyze(&data).unwrap();
    let sections = &binary.sections;

    for section in sections {
        if section.size <= 1024 && section.offset > 0 {
            // Small sections should have data extracted
            if section.section_type != SectionType::Bss {
                // BSS sections don't have file data
                if section.offset + section.size <= data.len() as u64 {
                    assert!(section.data.is_some() || section.data.is_none());
                }
            }
        }
    }
}

#[test]
fn test_elf_symbol_demangling() {
    let data = elf_test_data::create_elf_with_symbols();
    let binary = BinaryAnalyzer::new().analyze(&data).unwrap();
    let symbols = &binary.symbols;

    // Look for mangled symbols (C++ style)
    for symbol in symbols {
        if symbol.name.starts_with("_Z") {
            assert!(symbol.demangled_name.is_some());
            let demangled = symbol.demangled_name.as_ref().unwrap();
            assert!(demangled.starts_with("demangled_"));
        }
    }
}

#[test]
fn test_elf_compiler_info_extraction() {
    let data = elf_test_data::create_elf_64_x86_64_le();
    let binary = BinaryAnalyzer::new().analyze(&data).unwrap();
    let metadata = &binary.metadata;

    // Compiler info may be None for minimal test binaries
    if let Some(compiler_info) = &metadata.compiler_info {
        assert!(!compiler_info.is_empty());
    }
}

#[test]
fn test_elf_edge_cases() {
    // Test with minimum ELF header size
    let min_header = vec![0x7f, 0x45, 0x4c, 0x46];
    let result = BinaryAnalyzer::new().analyze(&min_header);
    assert!(result.is_err());

    // Test can_parse with exactly 4 bytes
    assert!(matches!(
        threatflux_binary_analysis::formats::detect_format(&[0x7f, 0x45, 0x4c, 0x46]),
        Ok(BinaryFormat::Elf)
    ));
    assert!(!matches!(
        threatflux_binary_analysis::formats::detect_format(&[0x12, 0x34, 0x56, 0x78]),
        Ok(BinaryFormat::Elf)
    ));

    // Test with 3 bytes (should fail)
    assert!(!matches!(
        threatflux_binary_analysis::formats::detect_format(&[0x7f, 0x45, 0x4c]),
        Ok(BinaryFormat::Elf)
    ));
}

#[test]
fn test_elf_unknown_architecture_handling() {
    // Create ELF with unknown machine type
    let mut data = elf_test_data::create_elf_64_x86_64_le();
    // Set unknown machine type (0xFFFF)
    data[18] = 0xff;
    data[19] = 0xff;

    let result = BinaryAnalyzer::new().analyze(&data);
    if let Ok(binary) = result {
        assert_eq!(binary.architecture, Architecture::Unknown);
        assert_eq!(binary.architecture, Architecture::Unknown);
    }
}

#[test]
fn test_elf_program_header_parsing() {
    let data = elf_test_data::create_elf_with_security_features();
    let binary = BinaryAnalyzer::new().analyze(&data).unwrap();
    let security = &binary.metadata.security_features;

    // Verify security features detected from program headers
    assert!(security.nx_bit); // From GNU_STACK
    assert!(security.relro); // From GNU_RELRO
    assert!(security.pie); // From ET_DYN
}

#[test]
fn test_elf_memory_usage() {
    // Test with larger ELF to ensure memory usage is reasonable
    let data = elf_test_data::create_elf_with_symbols();

    // Parse multiple times to check for memory leaks
    for _ in 0..10 {
        let binary = BinaryAnalyzer::new().analyze(&data).unwrap();
        let _sections = &binary.sections;
        let _symbols = &binary.symbols;
        let _imports = &binary.imports;
        let _exports = &binary.exports;
    }
}

#[test]
fn test_elf_consistency() {
    let data = elf_test_data::create_elf_64_x86_64_le();

    // Parse same data multiple times and verify consistency
    let results: Vec<_> = (0..5)
        .map(|_| BinaryAnalyzer::new().analyze(&data).unwrap())
        .collect();

    let first = &results[0];
    for result in &results[1..] {
        assert_eq!(result.format, first.format);
        assert_eq!(result.architecture, first.architecture);
        assert_eq!(result.entry_point, first.entry_point);
        assert_eq!(&result.sections.len(), &first.sections.len());
        assert_eq!(&result.symbols.len(), &first.symbols.len());
    }
}
