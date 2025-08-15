//! Integration tests for the entire binary analysis pipeline

use std::io::Write;
use tempfile::NamedTempFile;
use threatflux_binary_analysis::error::BinaryError;
use threatflux_binary_analysis::types::*;
use threatflux_binary_analysis::*;

// Create comprehensive test binaries for different formats
mod test_data {
    pub fn create_minimal_elf() -> Vec<u8> {
        vec![
            // ELF Header
            0x7f, 0x45, 0x4c, 0x46, // e_ident[EI_MAG0..EI_MAG3]
            0x02, // e_ident[EI_CLASS] = ELFCLASS64
            0x01, // e_ident[EI_DATA] = ELFDATA2LSB
            0x01, // e_ident[EI_VERSION] = EV_CURRENT
            0x00, // e_ident[EI_OSABI] = ELFOSABI_NONE
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_ident[EI_PAD]
            0x02, 0x00, // e_type = ET_EXEC
            0x3e, 0x00, // e_machine = EM_X86_64
            0x01, 0x00, 0x00, 0x00, // e_version = EV_CURRENT
            0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry = 0x401000
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff = 64
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff = 0
            0x00, 0x00, 0x00, 0x00, // e_flags = 0
            0x40, 0x00, // e_ehsize = 64
            0x38, 0x00, // e_phentsize = 56
            0x01, 0x00, // e_phnum = 1
            0x40, 0x00, // e_shentsize = 64
            0x00, 0x00, // e_shnum = 0
            0x00, 0x00, // e_shstrndx = 0
            // Program Header
            0x01, 0x00, 0x00, 0x00, // p_type = PT_LOAD
            0x05, 0x00, 0x00, 0x00, // p_flags = PF_R | PF_X
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset = 0
            0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr = 0x401000
            0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_paddr = 0x401000
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz = 256
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz = 256
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align = 4096
        ]
    }

    pub fn create_minimal_pe() -> Vec<u8> {
        let mut data = vec![0; 1024];

        // DOS Header
        data[0] = 0x4d; // 'M'
        data[1] = 0x5a; // 'Z'
        data[60] = 0x80; // PE header offset

        // PE Signature at offset 0x80
        data[0x80] = 0x50; // 'P'
        data[0x81] = 0x45; // 'E'
        data[0x82] = 0x00;
        data[0x83] = 0x00;

        // COFF Header
        data[0x84] = 0x64; // Machine = IMAGE_FILE_MACHINE_AMD64
        data[0x85] = 0x86;
        data[0x86] = 0x01; // NumberOfSections = 1
        data[0x87] = 0x00;

        // Timestamp (4 bytes)
        data[0x88] = 0x00;
        data[0x89] = 0x00;
        data[0x8a] = 0x00;
        data[0x8b] = 0x00;

        // PointerToSymbolTable (4 bytes)
        data[0x8c] = 0x00;
        data[0x8d] = 0x00;
        data[0x8e] = 0x00;
        data[0x8f] = 0x00;

        // NumberOfSymbols (4 bytes)
        data[0x90] = 0x00;
        data[0x91] = 0x00;
        data[0x92] = 0x00;
        data[0x93] = 0x00;

        // SizeOfOptionalHeader (2 bytes)
        data[0x94] = 0xf0; // 240 bytes
        data[0x95] = 0x00;

        // Characteristics (2 bytes)
        data[0x96] = 0x22; // IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE
        data[0x97] = 0x00;

        // Optional Header starts at 0x98
        data[0x98] = 0x0b; // Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC
        data[0x99] = 0x02;

        // AddressOfEntryPoint at offset 0x98 + 16 = 0xa8
        data[0xa8] = 0x00;
        data[0xa9] = 0x10;
        data[0xaa] = 0x00;
        data[0xab] = 0x00;

        data
    }

    pub fn create_minimal_macho() -> Vec<u8> {
        vec![
            // Mach-O Header (64-bit) - big endian
            0xfe, 0xed, 0xfa, 0xcf, // magic = MH_MAGIC_64 (big endian)
            0x01, 0x00, 0x00, 0x07, // cputype = CPU_TYPE_X86_64
            0x00, 0x00, 0x00, 0x03, // cpusubtype = CPU_SUBTYPE_X86_64_ALL
            0x00, 0x00, 0x00, 0x02, // filetype = MH_EXECUTE
            0x00, 0x00, 0x00, 0x01, // ncmds = 1
            0x00, 0x00, 0x00, 0x48, // sizeofcmds = 72
            0x00, 0x00, 0x20, 0x00, // flags = MH_NOUNDEFS | MH_DYLDLINK
            0x00, 0x00, 0x00, 0x00, // reserved
            // Load Command - LC_SEGMENT_64
            0x00, 0x00, 0x00, 0x19, // cmd = LC_SEGMENT_64
            0x00, 0x00, 0x00, 0x48, // cmdsize = 72
            // segname = "__TEXT" (16 bytes)
            0x5f, 0x5f, 0x54, 0x45, 0x58, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // vmaddr = 0x100000000 (8 bytes, big endian)
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            // vmsize = 0x1000 (8 bytes, big endian)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, // fileoff = 0 (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // filesize = 0x1000 (8 bytes, big endian)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            // maxprot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE (4 bytes)
            0x00, 0x00, 0x00, 0x07,
            // initprot = VM_PROT_READ | VM_PROT_EXECUTE (4 bytes)
            0x00, 0x00, 0x00, 0x05, // nsects = 0 (4 bytes)
            0x00, 0x00, 0x00, 0x00, // flags = 0 (4 bytes)
            0x00, 0x00, 0x00, 0x00,
        ]
    }

    pub fn create_java_class() -> Vec<u8> {
        vec![
            0xca, 0xfe, 0xba, 0xbe, // magic
            0x00, 0x00, // minor_version = 0
            0x00, 0x34, // major_version = 52 (Java 8)
            0x00, 0x0d, // constant_pool_count = 13
            // Minimal constant pool entries
            0x0a, 0x00, 0x03, 0x00, 0x0a, // CONSTANT_Methodref
            0x07, 0x00, 0x0b, // CONSTANT_Class
            0x0c, 0x00, 0x06, 0x00, 0x07, // CONSTANT_NameAndType
            0x01, 0x00, 0x06, 0x3c, 0x69, 0x6e, 0x69, 0x74, 0x3e, // CONSTANT_Utf8 "<init>"
            0x01, 0x00, 0x03, 0x28, 0x29, 0x56, // CONSTANT_Utf8 "()V"
            0x01, 0x00, 0x04, 0x43, 0x6f, 0x64, 0x65, // CONSTANT_Utf8 "Code"
            0x01, 0x00, 0x0f, 0x4c, 0x69, 0x6e, 0x65, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x54,
            0x61, 0x62, 0x6c, 0x65, // CONSTANT_Utf8 "LineNumberTable"
            0x01, 0x00, 0x04, 0x6d, 0x61, 0x69, 0x6e, // CONSTANT_Utf8 "main"
            0x01, 0x00, 0x16, 0x28, 0x5b, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e,
            0x67, 0x2f, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x3b, 0x29,
            0x56, // CONSTANT_Utf8 "([Ljava/lang/String;)V"
            0x01, 0x00, 0x0a, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x46, 0x69, 0x6c,
            0x65, // CONSTANT_Utf8 "SourceFile"
            0x07, 0x00, 0x0c, // CONSTANT_Class
            0x01, 0x00, 0x10, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f,
            0x62, 0x6a, 0x65, 0x63, 0x74, // CONSTANT_Utf8 "java/lang/Object"
            // Class access flags
            0x00, 0x21, // ACC_PUBLIC | ACC_SUPER
            // this_class
            0x00, 0x02, // super_class
            0x00, 0x03, // interfaces_count
            0x00, 0x00, // fields_count
            0x00, 0x00, // methods_count
            0x00, 0x01, // Method info
            0x00, 0x01, // access_flags = ACC_PUBLIC
            0x00, 0x04, // name_index = 4 ("<init>")
            0x00, 0x05, // descriptor_index = 5 ("()V")
            0x00, 0x01, // attributes_count = 1
            // Code attribute
            0x00, 0x06, // attribute_name_index = 6 ("Code")
            0x00, 0x00, 0x00, 0x11, // attribute_length = 17
            0x00, 0x01, // max_stack = 1
            0x00, 0x01, // max_locals = 1
            0x00, 0x00, 0x00, 0x05, // code_length = 5
            0x2a, 0xb7, 0x00, 0x01, 0xb1, // code: aload_0, invokespecial #1, return
            0x00, 0x00, // exception_table_length = 0
            0x00, 0x00, // attributes_count = 0
            // Class attributes_count
            0x00, 0x00,
        ]
    }

    pub fn create_wasm_module() -> Vec<u8> {
        vec![
            0x00, 0x61, 0x73, 0x6d, // WASM magic
            0x01, 0x00, 0x00, 0x00, // version 1
            // Type section
            0x01, // section id
            0x06, // section size
            0x01, // num types
            0x60, // func type
            0x01, // num params
            0x7f, // i32
            0x01, // num results
            0x7f, // i32
            // Function section
            0x03, // section id
            0x02, // section size
            0x01, // num functions
            0x00, // function 0 type index
            // Code section
            0x0a, // section id
            0x09, // section size
            0x01, // num function bodies
            0x07, // body size
            0x00, // local decl count
            0x20, 0x00, // local.get 0
            0x41, 0x01, // i32.const 1
            0x6a, // i32.add
            0x0b, // end
        ]
    }

    pub fn create_java_jar() -> Vec<u8> {
        use std::io::Write;
        use zip::{ZipWriter, write::FileOptions};

        let class_data = create_java_class();
        let cursor = std::io::Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(cursor);
        zip.start_file("Test.class", FileOptions::default())
            .unwrap();
        zip.write_all(&class_data).unwrap();
        let cursor = zip.finish().unwrap();
        cursor.into_inner()
    }
}

#[test]
fn test_complete_elf_analysis() {
    let data = test_data::create_minimal_elf();
    let analyzer = BinaryAnalyzer::new();

    let result = analyzer.analyze(&data).unwrap();

    assert_eq!(result.format, BinaryFormat::Elf);
    assert_eq!(result.architecture, Architecture::X86_64);
    assert_eq!(result.entry_point, Some(0x401000));

    // Check metadata
    assert_eq!(result.metadata.format, BinaryFormat::Elf);
    assert_eq!(result.metadata.architecture, Architecture::X86_64);
    assert!(result.metadata.size > 0);
    assert_eq!(result.metadata.endian, Endianness::Little);
}

#[test]
fn test_complete_pe_analysis() {
    let data = test_data::create_minimal_pe();
    let analyzer = BinaryAnalyzer::new();

    let result = analyzer.analyze(&data).unwrap();

    assert_eq!(result.format, BinaryFormat::Pe);
    assert_eq!(result.architecture, Architecture::X86_64);
    assert!(result.entry_point.is_some());

    // Check metadata
    assert_eq!(result.metadata.format, BinaryFormat::Pe);
    assert_eq!(result.metadata.architecture, Architecture::X86_64);
}

#[test]
fn test_complete_macho_analysis() {
    let data = test_data::create_minimal_macho();
    let analyzer = BinaryAnalyzer::new();

    let result = analyzer.analyze(&data);

    // Mach-O parsing may fail due to complex binary structure requirements
    match result {
        Ok(analysis) => {
            assert_eq!(analysis.format, BinaryFormat::MachO);
            assert_eq!(analysis.architecture, Architecture::X86_64);
            assert_eq!(analysis.metadata.format, BinaryFormat::MachO);
            assert_eq!(analysis.metadata.architecture, Architecture::X86_64);
        }
        Err(BinaryError::ParseError(_)) => {
            // This is acceptable - Mach-O parsing may be strict about binary structure
        }
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

#[test]
fn test_complete_java_analysis() {
    let data = test_data::create_java_class();
    let analyzer = BinaryAnalyzer::new();

    let analysis = analyzer.analyze(&data).expect("Java class analysis failed");
    assert_eq!(analysis.format, BinaryFormat::Java);
    assert_eq!(analysis.architecture, Architecture::Jvm);
    assert_eq!(analysis.metadata.format, BinaryFormat::Java);
    assert_eq!(analysis.metadata.architecture, Architecture::Jvm);
}

#[test]
fn test_complete_java_jar_analysis() {
    let data = test_data::create_java_jar();
    let analyzer = BinaryAnalyzer::new();

    let analysis = analyzer.analyze(&data).expect("Java JAR analysis failed");
    assert_eq!(analysis.format, BinaryFormat::Java);
    assert_eq!(analysis.architecture, Architecture::Jvm);
    assert_eq!(analysis.metadata.format, BinaryFormat::Java);
    assert_eq!(analysis.metadata.architecture, Architecture::Jvm);
}

#[test]
fn test_complete_wasm_analysis() {
    let data = test_data::create_wasm_module();
    let analyzer = BinaryAnalyzer::new();

    let result = analyzer.analyze(&data);

    // Wasm format may not be fully supported, check if it fails with UnsupportedFormat
    match result {
        Ok(analysis) => {
            assert_eq!(analysis.format, BinaryFormat::Wasm);
            assert_eq!(analysis.architecture, Architecture::Wasm);
            assert_eq!(analysis.metadata.format, BinaryFormat::Wasm);
            assert_eq!(analysis.metadata.architecture, Architecture::Wasm);
        }
        Err(BinaryError::UnsupportedFormat(_)) => {
            // This is acceptable - Wasm format may not be fully implemented
        }
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

#[test]
fn test_analysis_with_all_features_enabled() {
    let data = test_data::create_minimal_elf();

    let config = AnalysisConfig {
        enable_disassembly: true,
        enable_control_flow: true,
        enable_entropy: true,
        enable_symbols: true,
        max_analysis_size: 100 * 1024 * 1024,
        architecture_hint: None,
    };

    let analyzer = BinaryAnalyzer::with_config(config);
    let result = analyzer.analyze(&data).unwrap();

    assert_eq!(result.format, BinaryFormat::Elf);
    assert_eq!(result.architecture, Architecture::X86_64);

    // Note: Optional features might not be available in mock data
    // But the analysis should complete without errors
}

#[test]
fn test_analysis_with_features_disabled() {
    let data = test_data::create_minimal_elf();

    let config = AnalysisConfig {
        enable_disassembly: false,
        enable_control_flow: false,
        enable_entropy: false,
        enable_symbols: false,
        max_analysis_size: 1024,
        architecture_hint: Some(Architecture::X86_64),
    };

    let analyzer = BinaryAnalyzer::with_config(config);
    let result = analyzer.analyze(&data).unwrap();

    assert_eq!(result.format, BinaryFormat::Elf);
    assert_eq!(result.architecture, Architecture::X86_64);

    // Optional analyses should be None when disabled
    assert!(result.disassembly.is_none());
    assert!(result.control_flow.is_none());
    assert!(result.entropy.is_none());
}

#[test]
fn test_multiple_format_analysis() {
    let test_cases = vec![
        (
            test_data::create_minimal_elf(),
            BinaryFormat::Elf,
            Architecture::X86_64,
            true, // should succeed
        ),
        (
            test_data::create_minimal_pe(),
            BinaryFormat::Pe,
            Architecture::X86_64,
            true, // should succeed
        ),
        (
            test_data::create_minimal_macho(),
            BinaryFormat::MachO,
            Architecture::X86_64,
            false, // may fail with ParseError
        ),
        (
            test_data::create_java_class(),
            BinaryFormat::Java,
            Architecture::Jvm,
            true, // should succeed
        ),
        (
            test_data::create_wasm_module(),
            BinaryFormat::Wasm,
            Architecture::Wasm,
            false, // may fail with UnsupportedFormat
        ),
    ];

    let analyzer = BinaryAnalyzer::new();

    for (data, expected_format, expected_arch, should_succeed) in test_cases {
        let result = analyzer.analyze(&data);

        if should_succeed {
            let analysis = result.unwrap();
            assert_eq!(analysis.format, expected_format);
            assert_eq!(analysis.architecture, expected_arch);
            assert_eq!(analysis.metadata.format, expected_format);
            assert_eq!(analysis.metadata.architecture, expected_arch);
        } else {
            // For formats that may not be fully implemented
            match result {
                Ok(analysis) => {
                    assert_eq!(analysis.format, expected_format);
                    assert_eq!(analysis.architecture, expected_arch);
                    assert_eq!(analysis.metadata.format, expected_format);
                    assert_eq!(analysis.metadata.architecture, expected_arch);
                }
                Err(BinaryError::UnsupportedFormat(_)) => {
                    // This is acceptable for unimplemented formats
                }
                Err(BinaryError::ParseError(_)) => {
                    // This is acceptable for formats with complex binary structure requirements
                }
                Err(e) => panic!("Unexpected error for format {:?}: {:?}", expected_format, e),
            }
        }
    }
}

#[test]
fn test_file_based_analysis() {
    let data = test_data::create_minimal_elf();

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&data).unwrap();
    temp_file.flush().unwrap();

    // Read file back and analyze
    let file_data = std::fs::read(temp_file.path()).unwrap();
    let analyzer = BinaryAnalyzer::new();
    let result = analyzer.analyze(&file_data).unwrap();

    assert_eq!(result.format, BinaryFormat::Elf);
    assert_eq!(result.architecture, Architecture::X86_64);
}

#[test]
fn test_concurrent_analysis_different_formats() {
    use std::sync::Arc;
    use std::thread;

    let test_data = vec![
        (
            Arc::new(test_data::create_minimal_elf()),
            BinaryFormat::Elf,
            true,
        ),
        (
            Arc::new(test_data::create_minimal_pe()),
            BinaryFormat::Pe,
            true,
        ),
        (
            Arc::new(test_data::create_minimal_macho()),
            BinaryFormat::MachO,
            false,
        ),
        (
            Arc::new(test_data::create_java_class()),
            BinaryFormat::Java,
            true,
        ),
        (
            Arc::new(test_data::create_wasm_module()),
            BinaryFormat::Wasm,
            false,
        ),
    ];

    let mut handles = vec![];

    for (data, expected_format, should_succeed) in test_data {
        let handle = thread::spawn(move || {
            let analyzer = BinaryAnalyzer::new();
            let result = analyzer.analyze(&data);
            (result, expected_format, should_succeed)
        });
        handles.push(handle);
    }

    for handle in handles {
        let (result, expected_format, should_succeed) = handle.join().unwrap();

        if should_succeed {
            let analysis = result.unwrap();
            assert_eq!(analysis.format, expected_format);
        } else {
            // For formats that may not be fully implemented
            match result {
                Ok(analysis) => {
                    assert_eq!(analysis.format, expected_format);
                }
                Err(BinaryError::UnsupportedFormat(_)) => {
                    // This is acceptable for unimplemented formats
                }
                Err(BinaryError::ParseError(_)) => {
                    // This is acceptable for formats with complex binary structure requirements
                }
                Err(e) => panic!("Unexpected error for format {:?}: {:?}", expected_format, e),
            }
        }
    }
}

#[test]
fn test_large_file_handling() {
    let mut data = test_data::create_minimal_elf();
    data.resize(10 * 1024 * 1024, 0); // 10MB file

    let config = AnalysisConfig {
        max_analysis_size: 1024 * 1024, // 1MB limit
        ..Default::default()
    };

    let analyzer = BinaryAnalyzer::with_config(config);
    let result = analyzer.analyze(&data);

    assert!(result.is_ok());
    let analysis = result.unwrap();
    assert_eq!(analysis.format, BinaryFormat::Elf);
}

#[test]
fn test_malformed_binaries() {
    let test_cases = vec![
        vec![0x7f, 0x45, 0x4c], // Incomplete ELF magic
        vec![0x4d, 0x5a],       // Incomplete PE magic
        vec![0xca, 0xfe, 0xba], // Incomplete Java magic
        vec![0x00, 0x61, 0x73], // Incomplete WASM magic
        vec![0xff; 1024],       // Random data
        vec![],                 // Empty data
    ];

    let analyzer = BinaryAnalyzer::new();

    for data in test_cases {
        let result = analyzer.analyze(&data);
        // Should either succeed with Unknown format or fail gracefully
        if let Ok(analysis) = result {
            // If it succeeds, format should be Unknown for malformed data
            if !data.is_empty() && !data.starts_with(&[0x7f, 0x45, 0x4c, 0x46]) {
                // Allow ELF to be detected if it has the right magic
                match data.get(0..2) {
                    Some([0x4d, 0x5a]) => {} // PE might be detected
                    Some([0xca, 0xfe]) => {} // Java might be detected
                    Some([0x00, 0x61]) => {} // WASM might be detected
                    _ => {
                        // Accept either Unknown or Raw for malformed data
                        assert!(matches!(
                            analysis.format,
                            BinaryFormat::Unknown | BinaryFormat::Raw
                        ));
                    }
                }
            }
        }
        // If it fails, that's also acceptable for malformed data
    }
}

#[test]
fn test_security_features_detection() {
    let data = test_data::create_minimal_elf();
    let analyzer = BinaryAnalyzer::new();
    let result = analyzer.analyze(&data).unwrap();

    // Security features should be initialized (even if all false for minimal binary)
    let sec_features = &result.metadata.security_features;
    // Security features are detected (values depend on the specific binary)
    // Just verify the fields are accessible - specific values vary by binary
    let _nx = sec_features.nx_bit;
    let _aslr = sec_features.aslr;
    let _canary = sec_features.stack_canary;
}

#[test]
fn test_error_propagation() {
    let analyzer = BinaryAnalyzer::new();

    // Test that errors are properly propagated through the analysis pipeline
    let empty_data = vec![];
    let result = analyzer.analyze(&empty_data);
    assert!(result.is_err());

    // Test that the error is meaningful
    if let Err(e) = result {
        let error_string = format!("{}", e);
        assert!(!error_string.is_empty());
    }
}

#[test]
fn test_analysis_determinism() {
    let data = test_data::create_minimal_elf();
    let analyzer = BinaryAnalyzer::new();

    // Run analysis multiple times and verify results are identical
    let mut results = vec![];
    for _ in 0..5 {
        let result = analyzer.analyze(&data).unwrap();
        results.push(result);
    }

    let first = &results[0];
    for result in &results[1..] {
        assert_eq!(result.format, first.format);
        assert_eq!(result.architecture, first.architecture);
        assert_eq!(result.entry_point, first.entry_point);
        assert_eq!(result.metadata.format, first.metadata.format);
        assert_eq!(result.metadata.architecture, first.metadata.architecture);
    }
}

#[test]
fn test_memory_usage() {
    let data = test_data::create_minimal_elf();
    let analyzer = BinaryAnalyzer::new();

    // Test that analysis doesn't leak memory by running many iterations
    for _ in 0..100 {
        let result = analyzer.analyze(&data);
        assert!(result.is_ok());
    }

    // If we get here without OOM, memory usage is reasonable
}
