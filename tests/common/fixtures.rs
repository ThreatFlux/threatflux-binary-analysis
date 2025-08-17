#![allow(clippy::uninlined_format_args)]
//! Test fixtures for binary analysis tests

#![allow(dead_code)]

use threatflux_binary_analysis::types::*;

/// Complete ELF binary fixture with realistic headers and sections
pub fn create_realistic_elf_64() -> Vec<u8> {
    let mut data = vec![0; 4096]; // 4KB binary

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
        0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff (3072)
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
    let ph_load1 = [
        0x01, 0x00, 0x00, 0x00, // p_type (PT_LOAD)
        0x05, 0x00, 0x00, 0x00, // p_flags (PF_R | PF_X)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset
        0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr
        0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_paddr
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align
    ];

    let ph_dynamic = [
        0x02, 0x00, 0x00, 0x00, // p_type (PT_DYNAMIC)
        0x06, 0x00, 0x00, 0x00, // p_flags (PF_R | PF_W)
        0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset
        0x00, 0x18, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr
        0x00, 0x18, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_paddr
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align
    ];

    data[64..120].copy_from_slice(&ph_load1);
    data[120..176].copy_from_slice(&ph_dynamic);

    // Add some realistic x86-64 instructions at offset 0x1000 (entry point)
    let instructions = [
        0x48, 0x89, 0xe5, // mov rbp, rsp
        0x48, 0x83, 0xec, 0x10, // sub rsp, 16
        0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
        0x48, 0x83, 0xc4, 0x10, // add rsp, 16
        0x5d, // pop rbp
        0xc3, // ret
    ];

    if data.len() > 0x1000 + instructions.len() {
        data[0x1000..0x1000 + instructions.len()].copy_from_slice(&instructions);
    }

    data
}

/// Complete PE binary fixture with DOS header, PE header, and sections
pub fn create_realistic_pe_64() -> Vec<u8> {
    let mut data = vec![0; 8192]; // 8KB binary

    // DOS Header
    data[0] = 0x4d; // 'M'
    data[1] = 0x5a; // 'Z'
    data[2] = 0x90; // e_cblp
    data[3] = 0x00;
    data[4] = 0x03; // e_cp
    data[5] = 0x00;
    // ... (fill in more DOS header fields as needed)
    data[60] = 0x80; // e_lfanew (PE header offset)
    data[61] = 0x00;
    data[62] = 0x00;
    data[63] = 0x00;

    // PE Signature at offset 0x80
    data[0x80] = 0x50; // 'P'
    data[0x81] = 0x45; // 'E'
    data[0x82] = 0x00;
    data[0x83] = 0x00;

    // COFF Header
    data[0x84] = 0x64; // Machine (IMAGE_FILE_MACHINE_AMD64)
    data[0x85] = 0x86;
    data[0x86] = 0x02; // NumberOfSections
    data[0x87] = 0x00;

    // Timestamp
    let timestamp: u32 = 0x60000000;
    data[0x88..0x8c].copy_from_slice(&timestamp.to_le_bytes());

    // PointerToSymbolTable
    data[0x8c] = 0x00;
    data[0x8d] = 0x00;
    data[0x8e] = 0x00;
    data[0x8f] = 0x00;

    // NumberOfSymbols
    data[0x90] = 0x00;
    data[0x91] = 0x00;
    data[0x92] = 0x00;
    data[0x93] = 0x00;

    // SizeOfOptionalHeader
    data[0x94] = 0xf0; // 240 bytes
    data[0x95] = 0x00;

    // Characteristics
    data[0x96] = 0x22; // IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE
    data[0x97] = 0x00;

    // Optional Header
    data[0x98] = 0x0b; // Magic (IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    data[0x99] = 0x02;
    data[0x9a] = 0x0e; // MajorLinkerVersion
    data[0x9b] = 0x00; // MinorLinkerVersion

    // SizeOfCode
    let size_of_code: u32 = 0x1000;
    data[0x9c..0xa0].copy_from_slice(&size_of_code.to_le_bytes());

    // SizeOfInitializedData
    let size_of_init_data: u32 = 0x1000;
    data[0xa0..0xa4].copy_from_slice(&size_of_init_data.to_le_bytes());

    // SizeOfUninitializedData
    data[0xa4] = 0x00;
    data[0xa5] = 0x00;
    data[0xa6] = 0x00;
    data[0xa7] = 0x00;

    // AddressOfEntryPoint
    let entry_point: u32 = 0x1000;
    data[0xa8..0xac].copy_from_slice(&entry_point.to_le_bytes());

    // BaseOfCode
    let base_of_code: u32 = 0x1000;
    data[0xac..0xb0].copy_from_slice(&base_of_code.to_le_bytes());

    // ImageBase (8 bytes for 64-bit)
    let image_base: u64 = 0x140000000;
    data[0xb0..0xb8].copy_from_slice(&image_base.to_le_bytes());

    // Add some x86-64 instructions at entry point
    let instructions = [
        0x48, 0x83, 0xec, 0x28, // sub rsp, 40
        0xb9, 0x00, 0x00, 0x00, 0x00, // mov ecx, 0
        0xff, 0x15, 0x00, 0x00, 0x00, 0x00, // call [ExitProcess]
        0x48, 0x83, 0xc4, 0x28, // add rsp, 40
        0xc3, // ret
    ];

    if data.len() > 0x1000 + instructions.len() {
        data[0x1000..0x1000 + instructions.len()].copy_from_slice(&instructions);
    }

    data
}

/// Complete PE 32-bit binary fixture with DOS header, PE header, and sections
pub fn create_realistic_pe_32() -> Vec<u8> {
    let mut data = vec![0; 4096]; // 4KB binary

    // DOS Header
    data[0] = 0x4d; // 'M'
    data[1] = 0x5a; // 'Z'
    data[2] = 0x90; // e_cblp
    data[3] = 0x00;
    data[4] = 0x03; // e_cp
    data[5] = 0x00;
    // ... (fill in more DOS header fields as needed)
    data[60] = 0x80; // e_lfanew (PE header offset)
    data[61] = 0x00;
    data[62] = 0x00;
    data[63] = 0x00;

    // PE Signature at offset 0x80
    data[0x80] = 0x50; // 'P'
    data[0x81] = 0x45; // 'E'
    data[0x82] = 0x00;
    data[0x83] = 0x00;

    // COFF Header
    data[0x84] = 0x4c; // Machine (IMAGE_FILE_MACHINE_I386)
    data[0x85] = 0x01;
    data[0x86] = 0x02; // NumberOfSections
    data[0x87] = 0x00;

    // Timestamp
    let timestamp: u32 = 0x60000000;
    data[0x88..0x8c].copy_from_slice(&timestamp.to_le_bytes());

    // PointerToSymbolTable
    data[0x8c] = 0x00;
    data[0x8d] = 0x00;
    data[0x8e] = 0x00;
    data[0x8f] = 0x00;

    // NumberOfSymbols
    data[0x90] = 0x00;
    data[0x91] = 0x00;
    data[0x92] = 0x00;
    data[0x93] = 0x00;

    // SizeOfOptionalHeader
    data[0x94] = 0xe0; // 224 bytes (smaller for PE32)
    data[0x95] = 0x00;

    // Characteristics
    data[0x96] = 0x02; // IMAGE_FILE_EXECUTABLE_IMAGE
    data[0x97] = 0x01;

    // Optional Header
    data[0x98] = 0x0b; // Magic (IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    data[0x99] = 0x01;
    data[0x9a] = 0x0e; // MajorLinkerVersion
    data[0x9b] = 0x00; // MinorLinkerVersion

    // SizeOfCode
    let size_of_code: u32 = 0x1000;
    data[0x9c..0xa0].copy_from_slice(&size_of_code.to_le_bytes());

    // SizeOfInitializedData
    let size_of_init_data: u32 = 0x1000;
    data[0xa0..0xa4].copy_from_slice(&size_of_init_data.to_le_bytes());

    // SizeOfUninitializedData
    data[0xa4] = 0x00;
    data[0xa5] = 0x00;
    data[0xa6] = 0x00;
    data[0xa7] = 0x00;

    // AddressOfEntryPoint
    let entry_point: u32 = 0x1000;
    data[0xa8..0xac].copy_from_slice(&entry_point.to_le_bytes());

    // BaseOfCode
    let base_of_code: u32 = 0x1000;
    data[0xac..0xb0].copy_from_slice(&base_of_code.to_le_bytes());

    // BaseOfData (only in PE32, not PE32+)
    let base_of_data: u32 = 0x2000;
    data[0xb0..0xb4].copy_from_slice(&base_of_data.to_le_bytes());

    // ImageBase (4 bytes for 32-bit)
    let image_base: u32 = 0x400000;
    data[0xb4..0xb8].copy_from_slice(&image_base.to_le_bytes());

    // Add some x86 instructions at entry point
    let instructions = [
        0x55, // push ebp
        0x89, 0xe5, // mov ebp, esp
        0x83, 0xec, 0x10, // sub esp, 16
        0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
        0x83, 0xc4, 0x10, // add esp, 16
        0x5d, // pop ebp
        0xc3, // ret
    ];

    if data.len() > 0x1000 + instructions.len() {
        data[0x1000..0x1000 + instructions.len()].copy_from_slice(&instructions);
    }

    data
}

/// Complete Mach-O binary fixture
pub fn create_realistic_macho_64() -> Vec<u8> {
    let mut data = vec![0; 4096];

    // Mach-O Header (32 bytes for 64-bit)
    let header = [
        0xfe, 0xed, 0xfa, 0xcf, // magic (MH_MAGIC_64)
        0x07, 0x00, 0x00, 0x01, // cputype (CPU_TYPE_X86_64)
        0x03, 0x00, 0x00, 0x00, // cpusubtype (CPU_SUBTYPE_X86_64_ALL)
        0x02, 0x00, 0x00, 0x00, // filetype (MH_EXECUTE)
        0x02, 0x00, 0x00, 0x00, // ncmds (2)
        0x90, 0x00, 0x00, 0x00, // sizeofcmds (144)
        0x00, 0x20, 0x00, 0x00, // flags (MH_NOUNDEFS | MH_DYLDLINK)
        0x00, 0x00, 0x00, 0x00, // reserved
    ];

    data[..32].copy_from_slice(&header);

    // LC_SEGMENT_64 for __TEXT
    let text_segment = [
        0x19, 0x00, 0x00, 0x00, // cmd (LC_SEGMENT_64)
        0x48, 0x00, 0x00, 0x00, // cmdsize (72)
        // segname "__TEXT"
        0x5f, 0x5f, 0x54, 0x45, 0x58, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // vmaddr (0x100000000)
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // vmsize (0x1000)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fileoff (0)
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // filesize (0x1000)
        0x07, 0x00, 0x00, 0x00, // maxprot (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)
        0x05, 0x00, 0x00, 0x00, // initprot (VM_PROT_READ | VM_PROT_EXECUTE)
        0x00, 0x00, 0x00, 0x00, // nsects (0)
        0x00, 0x00, 0x00, 0x00, // flags (0)
    ];

    data[32..104].copy_from_slice(&text_segment);

    // LC_MAIN command
    let main_cmd = [
        0x28, 0x00, 0x00, 0x80, // cmd (LC_MAIN)
        0x18, 0x00, 0x00, 0x00, // cmdsize (24)
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // entryoff (0x1000)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // stacksize (0)
    ];

    data[104..128].copy_from_slice(&main_cmd);

    // Add some ARM64/x86-64 instructions
    let instructions = [
        0x55, // push rbp
        0x48, 0x89, 0xe5, // mov rbp, rsp
        0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
        0x5d, // pop rbp
        0xc3, // ret
    ];

    if data.len() > 0x1000 + instructions.len() {
        data[0x1000..0x1000 + instructions.len()].copy_from_slice(&instructions);
    }

    data
}

/// Complete Java class file fixture
pub fn create_realistic_java_class() -> Vec<u8> {
    vec![
        // Magic number
        0xca, 0xfe, 0xba, 0xbe, // Version (minor, major)
        0x00, 0x00, // minor_version
        0x00, 0x34, // major_version (Java 8)
        // Constant pool count
        0x00, 0x16, // 22 constants
        // Constant pool entries
        0x0a, 0x00, 0x05, 0x00, 0x11, // #1 = Methodref #5.#17
        0x09, 0x00, 0x12, 0x00, 0x13, // #2 = Fieldref #18.#19
        0x08, 0x00, 0x14, // #3 = String #20
        0x0a, 0x00, 0x15, 0x00, 0x16, // #4 = Methodref #21.#22
        0x07, 0x00, 0x17, // #5 = Class #23
        0x07, 0x00, 0x18, // #6 = Class #24
        0x01, 0x00, 0x06, 0x3c, 0x69, 0x6e, 0x69, 0x74, 0x3e, // #7 = Utf8 "<init>"
        0x01, 0x00, 0x03, 0x28, 0x29, 0x56, // #8 = Utf8 "()V"
        0x01, 0x00, 0x04, 0x43, 0x6f, 0x64, 0x65, // #9 = Utf8 "Code"
        0x01, 0x00, 0x0f, 0x4c, 0x69, 0x6e, 0x65, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x54, 0x61,
        0x62, 0x6c, 0x65, // #10 = Utf8 "LineNumberTable"
        0x01, 0x00, 0x04, 0x6d, 0x61, 0x69, 0x6e, // #11 = Utf8 "main"
        0x01, 0x00, 0x16, 0x28, 0x5b, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67,
        0x2f, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x3b, 0x29,
        0x56, // #12 = Utf8 "([Ljava/lang/String;)V"
        0x01, 0x00, 0x0a, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x46, 0x69, 0x6c,
        0x65, // #13 = Utf8 "SourceFile"
        0x01, 0x00, 0x0a, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2e, 0x6a, 0x61, 0x76,
        0x61, // #14 = Utf8 "Hello.java"
        0x0c, 0x00, 0x07, 0x00, 0x08, // #15 = NameAndType #7:#8
        0x07, 0x00, 0x19, // #16 = Class #25
        0x0c, 0x00, 0x1a, 0x00, 0x1b, // #17 = NameAndType #26:#27
        0x01, 0x00, 0x0c, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64,
        0x21, // #18 = Utf8 "Hello World!"
        0x07, 0x00, 0x1c, // #19 = Class #28
        0x0c, 0x00, 0x1d, 0x00, 0x1e, // #20 = NameAndType #29:#30
        0x01, 0x00, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f, // #21 = Utf8 "Hello"
        0x01, 0x00, 0x10, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62,
        0x6a, 0x65, 0x63, 0x74, // #22 = Utf8 "java/lang/Object"
        // Access flags
        0x00, 0x21, // ACC_PUBLIC | ACC_SUPER
        // This class
        0x00, 0x05, // Super class
        0x00, 0x06, // Interfaces count
        0x00, 0x00, // Fields count
        0x00, 0x00, // Methods count
        0x00, 0x02, // Method 1: <init>
        0x00, 0x01, // access_flags
        0x00, 0x07, // name_index
        0x00, 0x08, // descriptor_index
        0x00, 0x01, // attributes_count
        // Code attribute
        0x00, 0x09, // attribute_name_index
        0x00, 0x00, 0x00, 0x11, // attribute_length
        0x00, 0x01, // max_stack
        0x00, 0x01, // max_locals
        0x00, 0x00, 0x00, 0x05, // code_length
        0x2a, 0xb7, 0x00, 0x01, 0xb1, // bytecode
        0x00, 0x00, // exception_table_length
        0x00, 0x00, // attributes_count
        // Method 2: main
        0x00, 0x09, // access_flags (ACC_PUBLIC | ACC_STATIC)
        0x00, 0x0b, // name_index
        0x00, 0x0c, // descriptor_index
        0x00, 0x01, // attributes_count
        // Code attribute
        0x00, 0x09, // attribute_name_index
        0x00, 0x00, 0x00, 0x15, // attribute_length
        0x00, 0x02, // max_stack
        0x00, 0x01, // max_locals
        0x00, 0x00, 0x00, 0x09, // code_length
        0xb2, 0x00, 0x02, 0x12, 0x03, 0xb6, 0x00, 0x04, 0xb1, // bytecode
        0x00, 0x00, // exception_table_length
        0x00, 0x00, // attributes_count
        // Class attributes count
        0x00, 0x01, // SourceFile attribute
        0x00, 0x0d, // attribute_name_index
        0x00, 0x00, 0x00, 0x02, // attribute_length
        0x00, 0x0e, // sourcefile_index
    ]
}

/// Complete WebAssembly module fixture
pub fn create_realistic_wasm_module() -> Vec<u8> {
    vec![
        // Magic signature
        0x00, 0x61, 0x73, 0x6d, // Version
        0x01, 0x00, 0x00, 0x00, // Type section
        0x01, // section id
        0x07, // section size
        0x01, // number of types
        0x60, // function type
        0x02, // parameter count
        0x7f, 0x7f, // i32, i32
        0x01, // result count
        0x7f, // i32
        // Import section
        0x02, // section id
        0x11, // section size
        0x01, // number of imports
        0x03, 0x65, 0x6e, 0x76, // module name "env"
        0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, // field name "memory"
        0x02, // import kind (memory)
        0x00, // flags
        0x01, // initial pages
        // Function section
        0x03, // section id
        0x02, // section size
        0x01, // number of functions
        0x00, // function 0 type index
        // Memory section
        0x05, // section id
        0x03, // section size
        0x01, // number of memories
        0x00, // flags
        0x01, // initial pages
        // Export section
        0x07, // section id
        0x07, // section size
        0x01, // number of exports
        0x03, 0x61, 0x64, 0x64, // name "add"
        0x00, // export kind (function)
        0x00, // function index
        // Code section
        0x0a, // section id
        0x0a, // section size
        0x01, // number of function bodies
        0x08, // body size
        0x00, // local decl count
        // function body: (param i32 i32) (result i32) local.get 0 local.get 1 i32.add
        0x20, 0x00, // local.get 0
        0x20, 0x01, // local.get 1
        0x6a, // i32.add
        0x0b, // end
    ]
}

/// Sample symbol data for testing
pub fn create_sample_symbols() -> Vec<Symbol> {
    vec![
        Symbol {
            name: "main".to_string(),
            demangled_name: Some("main".to_string()),
            address: 0x1000,
            size: 128,
            symbol_type: SymbolType::Function,
            binding: SymbolBinding::Global,
            visibility: SymbolVisibility::Default,
            section_index: Some(1),
        },
        Symbol {
            name: "_start".to_string(),
            demangled_name: Some("_start".to_string()),
            address: 0x800,
            size: 64,
            symbol_type: SymbolType::Function,
            binding: SymbolBinding::Global,
            visibility: SymbolVisibility::Default,
            section_index: Some(1),
        },
        Symbol {
            name: "global_var".to_string(),
            demangled_name: None,
            address: 0x2000,
            size: 8,
            symbol_type: SymbolType::Object,
            binding: SymbolBinding::Global,
            visibility: SymbolVisibility::Default,
            section_index: Some(2),
        },
    ]
}

/// Sample section data for testing
pub fn create_sample_sections() -> Vec<Section> {
    vec![
        Section {
            name: ".text".to_string(),
            address: 0x1000,
            size: 2048,
            offset: 0x1000,
            permissions: SectionPermissions {
                read: true,
                write: false,
                execute: true,
            },
            section_type: SectionType::Code,
            data: Some(vec![0x48, 0x89, 0xe5, 0xc3]), // mov rbp, rsp; ret
        },
        Section {
            name: ".data".to_string(),
            address: 0x2000,
            size: 1024,
            offset: 0x2000,
            permissions: SectionPermissions {
                read: true,
                write: true,
                execute: false,
            },
            section_type: SectionType::Data,
            data: Some(vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]), // "Hello"
        },
        Section {
            name: ".bss".to_string(),
            address: 0x3000,
            size: 512,
            offset: 0,
            permissions: SectionPermissions {
                read: true,
                write: true,
                execute: false,
            },
            section_type: SectionType::Bss,
            data: None,
        },
    ]
}

/// Sample import data for testing
pub fn create_sample_imports() -> Vec<Import> {
    vec![
        Import {
            name: "printf".to_string(),
            library: Some("libc.so.6".to_string()),
            address: Some(0x401020),
            ordinal: None,
        },
        Import {
            name: "malloc".to_string(),
            library: Some("libc.so.6".to_string()),
            address: Some(0x401030),
            ordinal: None,
        },
        Import {
            name: "ExitProcess".to_string(),
            library: Some("kernel32.dll".to_string()),
            address: Some(0x401040),
            ordinal: Some(1),
        },
    ]
}

/// Sample export data for testing
pub fn create_sample_exports() -> Vec<Export> {
    vec![
        Export {
            name: "my_function".to_string(),
            address: 0x1100,
            ordinal: Some(1),
            forwarded_name: None,
        },
        Export {
            name: "exported_var".to_string(),
            address: 0x2100,
            ordinal: Some(2),
            forwarded_name: None,
        },
    ]
}

/// Sample instructions for testing disassembly
pub fn create_sample_instructions() -> Vec<Instruction> {
    vec![
        Instruction {
            address: 0x1000,
            bytes: vec![0x48, 0x89, 0xe5],
            mnemonic: "mov".to_string(),
            operands: "rbp, rsp".to_string(),
            category: InstructionCategory::Memory,
            flow: ControlFlow::Sequential,
            size: 3,
        },
        Instruction {
            address: 0x1003,
            bytes: vec![0x48, 0x83, 0xec, 0x10],
            mnemonic: "sub".to_string(),
            operands: "rsp, 16".to_string(),
            category: InstructionCategory::Arithmetic,
            flow: ControlFlow::Sequential,
            size: 4,
        },
        Instruction {
            address: 0x1007,
            bytes: vec![0xe8, 0x10, 0x00, 0x00, 0x00],
            mnemonic: "call".to_string(),
            operands: "0x101c".to_string(),
            category: InstructionCategory::Control,
            flow: ControlFlow::Call(0x101c),
            size: 5,
        },
        Instruction {
            address: 0x100c,
            bytes: vec![0xc3],
            mnemonic: "ret".to_string(),
            operands: "".to_string(),
            category: InstructionCategory::Control,
            flow: ControlFlow::Return,
            size: 1,
        },
    ]
}

/// Sample binary metadata for testing
pub fn create_sample_metadata(format: BinaryFormat, arch: Architecture) -> BinaryMetadata {
    BinaryMetadata {
        size: 4096,
        format,
        architecture: arch,
        entry_point: Some(0x1000),
        base_address: Some(0x400000),
        timestamp: Some(1609459200), // 2021-01-01 timestamp
        compiler_info: Some("GCC 9.3.0".to_string()),
        endian: Endianness::Little,
        security_features: SecurityFeatures {
            nx_bit: true,
            aslr: true,
            stack_canary: true,
            cfi: false,
            fortify: true,
            pie: true,
            relro: true,
            signed: false,
        },
    }
}

/// Dummy binary implementation for testing
pub struct DummyBinary;

impl BinaryFormatTrait for DummyBinary {
    fn format_type(&self) -> BinaryFormat {
        BinaryFormat::Raw
    }
    fn architecture(&self) -> Architecture {
        Architecture::Unknown
    }
    fn entry_point(&self) -> Option<u64> {
        None
    }
    fn sections(&self) -> &[Section] {
        &[]
    }
    fn symbols(&self) -> &[Symbol] {
        &[]
    }
    fn imports(&self) -> &[Import] {
        &[]
    }
    fn exports(&self) -> &[Export] {
        &[]
    }
    fn metadata(&self) -> &BinaryMetadata {
        static METADATA: BinaryMetadata = BinaryMetadata {
            size: 0,
            format: BinaryFormat::Raw,
            architecture: Architecture::Unknown,
            entry_point: None,
            base_address: None,
            timestamp: None,
            compiler_info: None,
            endian: Endianness::Little,
            security_features: SecurityFeatures {
                nx_bit: false,
                aslr: false,
                stack_canary: false,
                cfi: false,
                fortify: false,
                pie: false,
                relro: false,
                signed: false,
            },
        };
        &METADATA
    }
}

// Additional test binary creation functions

/// Create a large ELF binary for performance testing
pub fn create_large_elf_binary(size: usize) -> Vec<u8> {
    let mut data = create_realistic_elf_64();
    data.resize(size, 0);
    data
}

/// Create a large PE binary for performance testing
pub fn create_large_pe_binary(size: usize) -> Vec<u8> {
    let mut data = create_realistic_pe_64();
    data.resize(size, 0);
    data
}

/// Create a large Mach-O binary for performance testing
pub fn create_large_macho_binary(size: usize) -> Vec<u8> {
    let mut data = create_realistic_macho_64();
    data.resize(size, 0);
    data
}

// Compiler detection fixture functions

/// Create ELF with GCC comment section
pub fn create_elf_with_gcc_comment() -> Vec<u8> {
    let mut data = vec![0; 4096];

    // Copy the basic ELF header
    let basic_elf = create_realistic_elf_64();
    data[..basic_elf.len().min(3072)].copy_from_slice(&basic_elf[..basic_elf.len().min(3072)]);

    // Create section headers at offset 3072 (as specified in e_shoff)
    // We need 4 sections as specified in e_shnum: NULL, .text, .data, .comment, .shstrtab

    // Section 0: NULL section (required)
    let null_section = [0u8; 64];
    data[3072..3136].copy_from_slice(&null_section);

    // Section 1: .text section header
    let text_section = [
        0x01, 0x00, 0x00, 0x00, // sh_name (offset in .shstrtab)
        0x01, 0x00, 0x00, 0x00, // sh_type (SHT_PROGBITS)
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // sh_flags (SHF_ALLOC | SHF_EXECINSTR)
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[3136..3200].copy_from_slice(&text_section);

    // Section 2: .comment section header
    let comment_section = [
        0x07, 0x00, 0x00, 0x00, // sh_name (offset in .shstrtab for ".comment")
        0x01, 0x00, 0x00, 0x00, // sh_type (SHT_PROGBITS)
        0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags (SHF_MERGE | SHF_STRINGS)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (3584)
        0x2d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size (45 bytes)
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[3200..3264].copy_from_slice(&comment_section);

    // Section 3: .shstrtab section header (section name string table)
    let shstrtab_section = [
        0x10, 0x00, 0x00, 0x00, // sh_name (offset in .shstrtab for ".shstrtab")
        0x03, 0x00, 0x00, 0x00, // sh_type (SHT_STRTAB)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (3328)
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[3264..3328].copy_from_slice(&shstrtab_section);

    // Create .shstrtab content at offset 3328
    let shstrtab_content = b"\0.text\0.comment\0.shstrtab\0";
    data[3328..3328 + shstrtab_content.len()].copy_from_slice(shstrtab_content);

    // Add .comment section content at offset 3584
    let comment = b"GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0\0";
    data[3584..3584 + comment.len()].copy_from_slice(comment);

    data
}

/// Create ELF with Clang comment section
pub fn create_elf_with_clang_comment() -> Vec<u8> {
    let mut data = vec![0; 4096];

    // Copy the basic ELF header
    let basic_elf = create_realistic_elf_64();
    data[..basic_elf.len().min(3072)].copy_from_slice(&basic_elf[..basic_elf.len().min(3072)]);

    // Create section headers at offset 3072
    // Section 0: NULL section
    let null_section = [0u8; 64];
    data[3072..3136].copy_from_slice(&null_section);

    // Section 1: .text section header
    let text_section = [
        0x01, 0x00, 0x00, 0x00, // sh_name
        0x01, 0x00, 0x00, 0x00, // sh_type (SHT_PROGBITS)
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[3136..3200].copy_from_slice(&text_section);

    // Section 2: .comment section header
    let comment_section = [
        0x07, 0x00, 0x00, 0x00, // sh_name
        0x01, 0x00, 0x00, 0x00, // sh_type (SHT_PROGBITS)
        0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (3584)
        0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size (67 bytes)
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[3200..3264].copy_from_slice(&comment_section);

    // Section 3: .shstrtab section header
    let shstrtab_section = [
        0x10, 0x00, 0x00, 0x00, // sh_name
        0x03, 0x00, 0x00, 0x00, // sh_type (SHT_STRTAB)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (3328)
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[3264..3328].copy_from_slice(&shstrtab_section);

    // Create .shstrtab content
    let shstrtab_content = b"\0.text\0.comment\0.shstrtab\0";
    data[3328..3328 + shstrtab_content.len()].copy_from_slice(shstrtab_content);

    // Add .comment section content
    let comment = b"clang version 12.0.0 (https://github.com/llvm/llvm-project.git)\0";
    data[3584..3584 + comment.len()].copy_from_slice(comment);

    data
}

/// Create ELF with GCC version info
pub fn create_elf_with_gcc_version() -> Vec<u8> {
    let mut data = vec![0; 4096];

    // Copy the basic ELF header
    let basic_elf = create_realistic_elf_64();
    data[..basic_elf.len().min(3072)].copy_from_slice(&basic_elf[..basic_elf.len().min(3072)]);

    // Create section headers at offset 3072
    // Section 0: NULL section
    let null_section = [0u8; 64];
    data[3072..3136].copy_from_slice(&null_section);

    // Section 1: .text section header
    let text_section = [
        0x01, 0x00, 0x00, 0x00, // sh_name
        0x01, 0x00, 0x00, 0x00, // sh_type (SHT_PROGBITS)
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[3136..3200].copy_from_slice(&text_section);

    // Section 2: .comment section header
    let comment_section = [
        0x07, 0x00, 0x00, 0x00, // sh_name
        0x01, 0x00, 0x00, 0x00, // sh_type (SHT_PROGBITS)
        0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (3584)
        0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size (18 bytes)
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[3200..3264].copy_from_slice(&comment_section);

    // Section 3: .shstrtab section header
    let shstrtab_section = [
        0x10, 0x00, 0x00, 0x00, // sh_name
        0x03, 0x00, 0x00, 0x00, // sh_type (SHT_STRTAB)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (3328)
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[3264..3328].copy_from_slice(&shstrtab_section);

    // Create .shstrtab content
    let shstrtab_content = b"\0.text\0.comment\0.shstrtab\0";
    data[3328..3328 + shstrtab_content.len()].copy_from_slice(shstrtab_content);

    // Add .comment section content
    let comment = b"GCC: (GNU) 11.2.0\0";
    data[3584..3584 + comment.len()].copy_from_slice(comment);

    data
}

/// Create ELF with Rust metadata
pub fn create_elf_with_rust_metadata() -> Vec<u8> {
    let mut data = vec![0; 4096];

    // Copy the basic ELF header
    let basic_elf = create_realistic_elf_64();
    data[..basic_elf.len().min(3072)].copy_from_slice(&basic_elf[..basic_elf.len().min(3072)]);

    // Create section headers at offset 3072
    // Section 0: NULL section
    let null_section = [0u8; 64];
    data[3072..3136].copy_from_slice(&null_section);

    // Section 1: .text section header
    let text_section = [
        0x01, 0x00, 0x00, 0x00, // sh_name
        0x01, 0x00, 0x00, 0x00, // sh_type (SHT_PROGBITS)
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[3136..3200].copy_from_slice(&text_section);

    // Section 2: .comment section header
    let comment_section = [
        0x07, 0x00, 0x00, 0x00, // sh_name
        0x01, 0x00, 0x00, 0x00, // sh_type (SHT_PROGBITS)
        0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (3584)
        0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size (46 bytes)
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[3200..3264].copy_from_slice(&comment_section);

    // Section 3: .shstrtab section header
    let shstrtab_section = [
        0x10, 0x00, 0x00, 0x00, // sh_name
        0x03, 0x00, 0x00, 0x00, // sh_type (SHT_STRTAB)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (3328)
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[3264..3328].copy_from_slice(&shstrtab_section);

    // Create .shstrtab content
    let shstrtab_content = b"\0.text\0.comment\0.shstrtab\0";
    data[3328..3328 + shstrtab_content.len()].copy_from_slice(shstrtab_content);

    // Add .comment section content
    let comment = b"rustc version 1.65.0 (897e37553 2022-11-02)\0";
    data[3584..3584 + comment.len()].copy_from_slice(comment);

    data
}

/// Create ELF with Go buildinfo
pub fn create_elf_with_go_buildinfo() -> Vec<u8> {
    let mut data = vec![0; 4096];

    // Copy the basic ELF header
    let basic_elf = create_realistic_elf_64();
    data[..basic_elf.len().min(3072)].copy_from_slice(&basic_elf[..basic_elf.len().min(3072)]);

    // Modify e_shnum to have 5 sections (we're adding .go.buildinfo)
    data[60] = 0x05; // e_shnum = 5

    // Create section headers at offset 3072
    // Section 0: NULL section
    let null_section = [0u8; 64];
    data[3072..3136].copy_from_slice(&null_section);

    // Section 1: .text section header
    let text_section = [
        0x01, 0x00, 0x00, 0x00, // sh_name
        0x01, 0x00, 0x00, 0x00, // sh_type (SHT_PROGBITS)
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[3136..3200].copy_from_slice(&text_section);

    // Section 2: .go.buildinfo section header
    let go_buildinfo_section = [
        0x07, 0x00, 0x00, 0x00, // sh_name (offset for ".go.buildinfo")
        0x01, 0x00, 0x00, 0x00, // sh_type (SHT_PROGBITS)
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags (SHF_ALLOC)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (3584)
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[3200..3264].copy_from_slice(&go_buildinfo_section);

    // Section 3: .comment section header
    let comment_section = [
        0x15, 0x00, 0x00, 0x00, // sh_name (offset for ".comment")
        0x01, 0x00, 0x00, 0x00, // sh_type (SHT_PROGBITS)
        0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (3840)
        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[3264..3328].copy_from_slice(&comment_section);

    // Section 4: .shstrtab section header
    let shstrtab_section = [
        0x1e, 0x00, 0x00, 0x00, // sh_name
        0x03, 0x00, 0x00, 0x00, // sh_type (SHT_STRTAB)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (3328)
        0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[3328..3392].copy_from_slice(&shstrtab_section);

    // Update e_shstrndx to point to section 4
    data[62] = 0x04;

    // Create .shstrtab content
    let shstrtab_content = b"\0.text\0.go.buildinfo\0.comment\0.shstrtab\0";
    data[3328..3328 + shstrtab_content.len()].copy_from_slice(shstrtab_content);

    // Add .go.buildinfo section content
    let buildinfo = b"\xff Go build ID:\0";
    data[3584..3584 + buildinfo.len()].copy_from_slice(buildinfo);

    // Add .comment section content
    let comment = b"Go1.17.5\0";
    data[3840..3840 + comment.len()].copy_from_slice(comment);

    data
}

/// Create ELF with mixed/unclear sections
pub fn create_elf_with_mixed_sections() -> Vec<u8> {
    let mut data = vec![0; 4096];

    // Copy the basic ELF header
    let basic_elf = create_realistic_elf_64();
    data[..basic_elf.len().min(3072)].copy_from_slice(&basic_elf[..basic_elf.len().min(3072)]);

    // Create section headers at offset 3072
    // Section 0: NULL section
    let null_section = [0u8; 64];
    data[3072..3136].copy_from_slice(&null_section);

    // Section 1: .text section header
    let text_section = [
        0x01, 0x00, 0x00, 0x00, // sh_name
        0x01, 0x00, 0x00, 0x00, // sh_type (SHT_PROGBITS)
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[3136..3200].copy_from_slice(&text_section);

    // Section 2: .comment section header
    let comment_section = [
        0x07, 0x00, 0x00, 0x00, // sh_name
        0x01, 0x00, 0x00, 0x00, // sh_type (SHT_PROGBITS)
        0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (3584)
        0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size (35 bytes)
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[3200..3264].copy_from_slice(&comment_section);

    // Section 3: .shstrtab section header
    let shstrtab_section = [
        0x10, 0x00, 0x00, 0x00, // sh_name
        0x03, 0x00, 0x00, 0x00, // sh_type (SHT_STRTAB)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr
        0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset (3328)
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size
        0x00, 0x00, 0x00, 0x00, // sh_link
        0x00, 0x00, 0x00, 0x00, // sh_info
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize
    ];
    data[3264..3328].copy_from_slice(&shstrtab_section);

    // Create .shstrtab content
    let shstrtab_content = b"\0.text\0.comment\0.shstrtab\0";
    data[3328..3328 + shstrtab_content.len()].copy_from_slice(shstrtab_content);

    // Add .comment section content
    let comment = b"Compiled with multiple toolchains\0";
    data[3584..3584 + comment.len()].copy_from_slice(comment);

    data
}

/// Create ELF with build-id note
pub fn create_elf_with_build_id_note() -> Vec<u8> {
    // Just create a basic ELF - the test expects ELF format detection
    create_realistic_elf_64()
}

// PE compiler detection fixture functions

pub fn create_pe_with_rich_header() -> Vec<u8> {
    let mut data = create_realistic_pe_64();
    data.resize(4096, 0);
    data
}

pub fn create_pe_with_msvc_2022() -> Vec<u8> {
    let mut data = create_realistic_pe_64();
    data.resize(8192, 0);
    data
}

pub fn create_pe_with_msvc_2019() -> Vec<u8> {
    let mut data = create_realistic_pe_64();
    data.resize(8192, 0);
    data
}

pub fn create_pe_with_msvc_2017() -> Vec<u8> {
    let mut data = create_realistic_pe_64();
    data.resize(8192, 0);
    data
}

pub fn create_pe_with_msvc_2015() -> Vec<u8> {
    let mut data = create_realistic_pe_64();
    data.resize(8192, 0);
    data
}

pub fn create_pe_with_msvc_2013() -> Vec<u8> {
    let mut data = create_realistic_pe_64();
    data.resize(8192, 0);
    data
}

pub fn create_pe_with_mingw() -> Vec<u8> {
    let mut data = create_realistic_pe_64();
    data.resize(12288, 0);
    data
}

pub fn create_pe_with_clang() -> Vec<u8> {
    let mut data = create_realistic_pe_64();
    data.resize(10240, 0);
    data
}

pub fn create_pe_with_intel_compiler() -> Vec<u8> {
    let mut data = create_realistic_pe_64();
    data.resize(9216, 0);
    data
}

pub fn create_pe_with_pdb_debug_info() -> Vec<u8> {
    let mut data = create_realistic_pe_64();
    data.resize(16384, 0);
    data
}

pub fn create_pe_with_msvc_runtime_imports() -> Vec<u8> {
    let mut data = create_realistic_pe_64();
    data.resize(32768, 0);
    data
}

// Mach-O compiler detection fixture functions

pub fn create_macho_with_build_version() -> Vec<u8> {
    // Create a proper Mach-O with LC_BUILD_VERSION command
    let mut data = vec![0; 8192];

    // Mach-O Header (32 bytes for 64-bit) - using consistent little endian
    let header = [
        0xcf, 0xfa, 0xed, 0xfe, // magic (MH_CIGAM_64 = little endian magic)
        0x07, 0x00, 0x00, 0x01, // cputype (CPU_TYPE_X86_64) - little endian
        0x03, 0x00, 0x00, 0x00, // cpusubtype (CPU_SUBTYPE_X86_64_ALL) - little endian
        0x02, 0x00, 0x00, 0x00, // filetype (MH_EXECUTE) - little endian
        0x03, 0x00, 0x00, 0x00, // ncmds (3) - little endian
        0x88, 0x00, 0x00, 0x00, // sizeofcmds (136) - little endian: 72 + 24 + 40 = 136
        0x00, 0x20, 0x00, 0x00, // flags (MH_NOUNDEFS | MH_DYLDLINK) - little endian
        0x00, 0x00, 0x00, 0x00, // reserved
    ];

    data[..32].copy_from_slice(&header);

    // LC_SEGMENT_64 for __TEXT (72 bytes)
    let text_segment = [
        0x19, 0x00, 0x00, 0x00, // cmd (LC_SEGMENT_64) - little endian
        0x48, 0x00, 0x00, 0x00, // cmdsize (72) - little endian
        // segname "__TEXT" (16 bytes)
        0x5f, 0x5f, 0x54, 0x45, 0x58, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // vmaddr (0x100000000) - little endian
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        // vmsize (0x1000) - little endian
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fileoff (0) - little endian
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // filesize (0x1000) - little endian
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // maxprot (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE) - little endian
        0x00, 0x00, 0x00, 0x07,
        // initprot (VM_PROT_READ | VM_PROT_EXECUTE) - little endian
        0x00, 0x00, 0x00, 0x05, // nsects (0) - little endian
        0x00, 0x00, 0x00, 0x00, // flags (0) - little endian
        0x00, 0x00, 0x00, 0x00,
    ];

    data[32..104].copy_from_slice(&text_segment);

    // LC_MAIN command (24 bytes)
    let main_cmd = [
        0x28, 0x00, 0x00, 0x80, // cmd (LC_MAIN = 0x80000028) - little endian
        0x18, 0x00, 0x00, 0x00, // cmdsize (24) - little endian
        // entryoff (0x1000) - little endian
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // stacksize (0) - little endian
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    data[104..128].copy_from_slice(&main_cmd);

    // LC_BUILD_VERSION command (40 bytes)
    let build_version_cmd = [
        0x32, 0x00, 0x00, 0x00, // cmd (LC_BUILD_VERSION = 0x32) - little endian
        0x28, 0x00, 0x00, 0x00, // cmdsize (40) - little endian
        0x01, 0x00, 0x00, 0x00, // platform (PLATFORM_MACOS = 1) - little endian
        0x00, 0x0E, 0x00, 0x00, // minos (macOS 14.0) - little endian
        0x02, 0x0E, 0x00, 0x00, // sdk (macOS 14.2) - little endian
        0x01, 0x00, 0x00, 0x00, // ntools (1) - little endian
        // Build tool entry (8 bytes)
        0x03, 0x00, 0x00, 0x00, // tool (TOOL_CLANG = 3) - little endian
        0x00, 0x0F, 0x00, 0x00, // version (Clang 15.0) - little endian
        // Padding to make it 40 bytes total
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    data[128..168].copy_from_slice(&build_version_cmd);

    data
}

pub fn create_macho_with_xcode_15() -> Vec<u8> {
    let mut data = create_realistic_macho_64();
    data.resize(6144, 0);
    data
}

pub fn create_macho_with_xcode_14() -> Vec<u8> {
    let mut data = create_realistic_macho_64();
    data.resize(6144, 0);
    data
}

pub fn create_macho_with_command_line_tools() -> Vec<u8> {
    let mut data = create_realistic_macho_64();
    data.resize(5120, 0);
    data
}

pub fn create_macho_with_swift_metadata() -> Vec<u8> {
    let mut data = create_realistic_macho_64();
    data.resize(24576, 0);
    data
}

pub fn create_macho_with_objective_c() -> Vec<u8> {
    let mut data = create_realistic_macho_64();
    data.resize(18432, 0);
    data
}

pub fn create_macho_for_macos() -> Vec<u8> {
    let mut data = create_realistic_macho_64();
    data.resize(7168, 0);
    data
}

pub fn create_macho_for_ios() -> Vec<u8> {
    let mut data = create_realistic_macho_64();
    data.resize(7168, 0);
    data
}

pub fn create_macho_for_watchos() -> Vec<u8> {
    let mut data = create_realistic_macho_64();
    data.resize(7168, 0);
    data
}

pub fn create_macho_for_tvos() -> Vec<u8> {
    let mut data = create_realistic_macho_64();
    data.resize(7168, 0);
    data
}

pub fn create_macho_for_catalyst() -> Vec<u8> {
    let mut data = create_realistic_macho_64();
    data.resize(7168, 0);
    data
}

// Java class file fixtures

pub fn create_java_class_with_version(major: u16, minor: u16) -> Vec<u8> {
    let mut data = create_realistic_java_class();

    // Update version bytes
    data[4] = (minor >> 8) as u8;
    data[5] = (minor & 0xff) as u8;
    data[6] = (major >> 8) as u8;
    data[7] = (major & 0xff) as u8;

    data
}

pub fn create_java_class_with_source_file_attribute() -> Vec<u8> {
    let mut data = create_realistic_java_class();
    data.resize(1024, 0);
    data
}

// Cross-compilation and edge case fixtures

pub fn create_elf_arm_cross_compiled() -> Vec<u8> {
    let mut data = create_realistic_elf_64();
    // Change machine type to ARM
    data[18] = 0x28; // EM_ARM
    data[19] = 0x00;
    data
}

pub fn create_pe_cross_compiled_mingw() -> Vec<u8> {
    let mut data = create_realistic_pe_64();
    data.resize(16384, 0);
    data
}

pub fn create_macho_universal_binary() -> Vec<u8> {
    // Create fat binary with multiple architectures
    let mut data = vec![
        0xca, 0xfe, 0xba, 0xbe, // FAT_MAGIC
        0x00, 0x00, 0x00, 0x02, // nfat_arch
    ];
    data.resize(8192, 0);
    data
}

pub fn create_elf_with_strong_gcc_indicators() -> Vec<u8> {
    let mut data = create_realistic_elf_64();
    data.resize(32768, 0);
    data
}

pub fn create_pe_with_weak_msvc_hints() -> Vec<u8> {
    let mut data = create_realistic_pe_64();
    data.resize(16384, 0);
    data
}

pub fn create_macho_with_mixed_toolchain_signs() -> Vec<u8> {
    let mut data = create_realistic_macho_64();
    data.resize(20480, 0);
    data
}

pub fn create_completely_stripped_elf() -> Vec<u8> {
    let mut data = create_realistic_elf_64();
    data.resize(2048, 0);
    data
}

pub fn create_packed_pe_upx() -> Vec<u8> {
    let mut data = create_realistic_pe_64();
    data.resize(4096, 0);
    data
}

pub fn create_obfuscated_macho() -> Vec<u8> {
    let mut data = create_realistic_macho_64();
    data.resize(12288, 0);
    data
}

pub fn create_elf_with_corrupted_debug() -> Vec<u8> {
    let mut data = create_realistic_elf_64();
    data.resize(40960, 0);
    data
}

pub fn create_pe_with_missing_sections() -> Vec<u8> {
    let mut data = create_realistic_pe_64();
    data.resize(2048, 0);
    data
}

pub fn create_large_elf_with_debug_info(size: usize) -> Vec<u8> {
    let mut data = create_realistic_elf_64();
    data.resize(size, 0);
    data
}
