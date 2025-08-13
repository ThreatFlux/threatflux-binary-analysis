//! Tests for core types and data structures

use threatflux_binary_analysis::types::*;

#[test]
fn test_binary_format_display() {
    assert_eq!(BinaryFormat::Elf.to_string(), "ELF");
    assert_eq!(BinaryFormat::Pe.to_string(), "PE");
    assert_eq!(BinaryFormat::MachO.to_string(), "Mach-O");
    assert_eq!(BinaryFormat::Java.to_string(), "Java");
    assert_eq!(BinaryFormat::Wasm.to_string(), "WebAssembly");
    assert_eq!(BinaryFormat::Raw.to_string(), "Raw");
    assert_eq!(BinaryFormat::Unknown.to_string(), "Unknown");
}

#[test]
fn test_architecture_display() {
    assert_eq!(Architecture::X86.to_string(), "x86");
    assert_eq!(Architecture::X86_64.to_string(), "x86-64");
    assert_eq!(Architecture::Arm.to_string(), "ARM");
    assert_eq!(Architecture::Arm64.to_string(), "ARM64");
    assert_eq!(Architecture::Mips.to_string(), "MIPS");
    assert_eq!(Architecture::Mips64.to_string(), "MIPS64");
    assert_eq!(Architecture::PowerPC.to_string(), "PowerPC");
    assert_eq!(Architecture::PowerPC64.to_string(), "PowerPC64");
    assert_eq!(Architecture::RiscV.to_string(), "RISC-V");
    assert_eq!(Architecture::RiscV64.to_string(), "RISC-V64");
    assert_eq!(Architecture::Wasm.to_string(), "WebAssembly");
    assert_eq!(Architecture::Jvm.to_string(), "JVM");
    assert_eq!(Architecture::Unknown.to_string(), "Unknown");
}

#[test]
fn test_binary_metadata_default() {
    let metadata = BinaryMetadata::default();
    assert_eq!(metadata.size, 0);
    assert_eq!(metadata.format, BinaryFormat::Unknown);
    assert_eq!(metadata.architecture, Architecture::Unknown);
    assert!(metadata.entry_point.is_none());
    assert!(metadata.base_address.is_none());
    assert!(metadata.timestamp.is_none());
    assert!(metadata.compiler_info.is_none());
    assert_eq!(metadata.endian, Endianness::Little);
}

#[test]
fn test_security_features_default() {
    let features = SecurityFeatures::default();
    assert!(!features.nx_bit);
    assert!(!features.aslr);
    assert!(!features.stack_canary);
    assert!(!features.cfi);
    assert!(!features.fortify);
    assert!(!features.pie);
    assert!(!features.relro);
    assert!(!features.signed);
}

#[test]
fn test_section_permissions_default() {
    let perms = SectionPermissions::default();
    assert!(!perms.read);
    assert!(!perms.write);
    assert!(!perms.execute);
}

#[test]
fn test_section_types() {
    assert_eq!(SectionType::Code, SectionType::Code);
    assert_eq!(SectionType::Data, SectionType::Data);
    assert_eq!(SectionType::ReadOnlyData, SectionType::ReadOnlyData);
    assert_eq!(SectionType::Bss, SectionType::Bss);
    assert_eq!(SectionType::Debug, SectionType::Debug);
    assert_eq!(SectionType::Symbol, SectionType::Symbol);
    assert_eq!(SectionType::String, SectionType::String);
    assert_eq!(SectionType::Relocation, SectionType::Relocation);
    assert_eq!(SectionType::Dynamic, SectionType::Dynamic);
    assert_eq!(SectionType::Note, SectionType::Note);
    assert_eq!(
        SectionType::Other("custom".to_string()),
        SectionType::Other("custom".to_string())
    );
}

#[test]
fn test_symbol_types() {
    assert_eq!(SymbolType::Function, SymbolType::Function);
    assert_eq!(SymbolType::Object, SymbolType::Object);
    assert_eq!(SymbolType::Section, SymbolType::Section);
    assert_eq!(SymbolType::File, SymbolType::File);
    assert_eq!(SymbolType::Common, SymbolType::Common);
    assert_eq!(SymbolType::Thread, SymbolType::Thread);
    assert_eq!(
        SymbolType::Other("custom".to_string()),
        SymbolType::Other("custom".to_string())
    );
}

#[test]
fn test_symbol_binding() {
    assert_eq!(SymbolBinding::Local, SymbolBinding::Local);
    assert_eq!(SymbolBinding::Global, SymbolBinding::Global);
    assert_eq!(SymbolBinding::Weak, SymbolBinding::Weak);
    assert_eq!(
        SymbolBinding::Other("custom".to_string()),
        SymbolBinding::Other("custom".to_string())
    );
}

#[test]
fn test_symbol_visibility() {
    assert_eq!(SymbolVisibility::Default, SymbolVisibility::Default);
    assert_eq!(SymbolVisibility::Internal, SymbolVisibility::Internal);
    assert_eq!(SymbolVisibility::Hidden, SymbolVisibility::Hidden);
    assert_eq!(SymbolVisibility::Protected, SymbolVisibility::Protected);
}

#[test]
fn test_instruction_category() {
    assert_eq!(
        InstructionCategory::Arithmetic,
        InstructionCategory::Arithmetic
    );
    assert_eq!(InstructionCategory::Logic, InstructionCategory::Logic);
    assert_eq!(InstructionCategory::Memory, InstructionCategory::Memory);
    assert_eq!(InstructionCategory::Control, InstructionCategory::Control);
    assert_eq!(InstructionCategory::System, InstructionCategory::System);
    assert_eq!(InstructionCategory::Crypto, InstructionCategory::Crypto);
    assert_eq!(InstructionCategory::Vector, InstructionCategory::Vector);
    assert_eq!(InstructionCategory::Float, InstructionCategory::Float);
    assert_eq!(InstructionCategory::Unknown, InstructionCategory::Unknown);
}

#[test]
fn test_control_flow() {
    assert_eq!(ControlFlow::Sequential, ControlFlow::Sequential);
    assert_eq!(ControlFlow::Jump(0x1000), ControlFlow::Jump(0x1000));
    assert_eq!(
        ControlFlow::ConditionalJump(0x2000),
        ControlFlow::ConditionalJump(0x2000)
    );
    assert_eq!(ControlFlow::Call(0x3000), ControlFlow::Call(0x3000));
    assert_eq!(ControlFlow::Return, ControlFlow::Return);
    assert_eq!(ControlFlow::Interrupt, ControlFlow::Interrupt);
    assert_eq!(ControlFlow::Unknown, ControlFlow::Unknown);
}

#[test]
fn test_function_type() {
    assert_eq!(FunctionType::Normal, FunctionType::Normal);
    assert_eq!(FunctionType::Constructor, FunctionType::Constructor);
    assert_eq!(FunctionType::Destructor, FunctionType::Destructor);
    assert_eq!(FunctionType::Operator, FunctionType::Operator);
    assert_eq!(FunctionType::Main, FunctionType::Main);
    assert_eq!(FunctionType::Entrypoint, FunctionType::Entrypoint);
    assert_eq!(FunctionType::Import, FunctionType::Import);
    assert_eq!(FunctionType::Export, FunctionType::Export);
    assert_eq!(FunctionType::Thunk, FunctionType::Thunk);
    assert_eq!(FunctionType::Unknown, FunctionType::Unknown);
}

#[test]
fn test_parameter_location() {
    assert_eq!(
        ParameterLocation::Register("eax".to_string()),
        ParameterLocation::Register("eax".to_string())
    );
    assert_eq!(ParameterLocation::Stack(8), ParameterLocation::Stack(8));
    assert_eq!(ParameterLocation::Unknown, ParameterLocation::Unknown);
}

#[test]
fn test_complexity_metrics_default() {
    let metrics = ComplexityMetrics::default();
    assert_eq!(metrics.cyclomatic_complexity, 0);
    assert_eq!(metrics.basic_block_count, 0);
    assert_eq!(metrics.edge_count, 0);
    assert_eq!(metrics.nesting_depth, 0);
    assert_eq!(metrics.loop_count, 0);
}

#[test]
fn test_obfuscation_level() {
    assert_eq!(ObfuscationLevel::None, ObfuscationLevel::None);
    assert_eq!(ObfuscationLevel::Low, ObfuscationLevel::Low);
    assert_eq!(ObfuscationLevel::Medium, ObfuscationLevel::Medium);
    assert_eq!(ObfuscationLevel::High, ObfuscationLevel::High);
    assert_eq!(ObfuscationLevel::Extreme, ObfuscationLevel::Extreme);
    assert_eq!(ObfuscationLevel::default(), ObfuscationLevel::None);
}

#[test]
fn test_packing_indicators_default() {
    let indicators = PackingIndicators::default();
    assert!(!indicators.is_packed);
    assert!(indicators.packer_name.is_none());
    assert!(indicators.compression_ratio.is_none());
    assert_eq!(indicators.obfuscation_level, ObfuscationLevel::None);
}

#[test]
fn test_security_indicators_default() {
    let indicators = SecurityIndicators::default();
    assert!(indicators.suspicious_apis.is_empty());
    assert!(indicators.anti_debug.is_empty());
    assert!(indicators.anti_vm.is_empty());
    assert!(indicators.crypto_indicators.is_empty());
    assert!(indicators.network_indicators.is_empty());
    assert!(indicators.filesystem_indicators.is_empty());
    assert!(indicators.registry_indicators.is_empty());
}

#[test]
fn test_analysis_result_default() {
    let result = AnalysisResult::default();
    assert_eq!(result.format, BinaryFormat::Unknown);
    assert_eq!(result.architecture, Architecture::Unknown);
    assert!(result.entry_point.is_none());
    assert!(result.sections.is_empty());
    assert!(result.symbols.is_empty());
    assert!(result.imports.is_empty());
    assert!(result.exports.is_empty());
    assert!(result.disassembly.is_none());
    assert!(result.control_flow.is_none());
    assert!(result.entropy.is_none());
    assert!(result.security.is_none());
}

#[test]
fn test_binary_metadata_construction() {
    let metadata = BinaryMetadata {
        size: 1024,
        format: BinaryFormat::Elf,
        architecture: Architecture::X86_64,
        entry_point: Some(0x1000),
        base_address: Some(0x400000),
        timestamp: Some(1609459200), // 2021-01-01
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
    };

    assert_eq!(metadata.size, 1024);
    assert_eq!(metadata.format, BinaryFormat::Elf);
    assert_eq!(metadata.architecture, Architecture::X86_64);
    assert_eq!(metadata.entry_point, Some(0x1000));
    assert_eq!(metadata.base_address, Some(0x400000));
    assert_eq!(metadata.timestamp, Some(1609459200));
    assert_eq!(metadata.compiler_info, Some("GCC 9.3.0".to_string()));
    assert_eq!(metadata.endian, Endianness::Little);
    assert!(metadata.security_features.nx_bit);
    assert!(metadata.security_features.aslr);
    assert!(metadata.security_features.stack_canary);
    assert!(!metadata.security_features.cfi);
    assert!(metadata.security_features.fortify);
    assert!(metadata.security_features.pie);
    assert!(metadata.security_features.relro);
    assert!(!metadata.security_features.signed);
}

#[test]
fn test_section_construction() {
    let section = Section {
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
        data: Some(vec![0x48, 0x89, 0xe5]), // mov rbp, rsp
    };

    assert_eq!(section.name, ".text");
    assert_eq!(section.address, 0x1000);
    assert_eq!(section.size, 2048);
    assert_eq!(section.offset, 0x1000);
    assert!(section.permissions.read);
    assert!(!section.permissions.write);
    assert!(section.permissions.execute);
    assert_eq!(section.section_type, SectionType::Code);
    assert_eq!(section.data, Some(vec![0x48, 0x89, 0xe5]));
}

#[test]
fn test_symbol_construction() {
    let symbol = Symbol {
        name: "main".to_string(),
        demangled_name: Some("main()".to_string()),
        address: 0x1040,
        size: 128,
        symbol_type: SymbolType::Function,
        binding: SymbolBinding::Global,
        visibility: SymbolVisibility::Default,
        section_index: Some(1),
    };

    assert_eq!(symbol.name, "main");
    assert_eq!(symbol.demangled_name, Some("main()".to_string()));
    assert_eq!(symbol.address, 0x1040);
    assert_eq!(symbol.size, 128);
    assert_eq!(symbol.symbol_type, SymbolType::Function);
    assert_eq!(symbol.binding, SymbolBinding::Global);
    assert_eq!(symbol.visibility, SymbolVisibility::Default);
    assert_eq!(symbol.section_index, Some(1));
}

#[test]
fn test_import_construction() {
    let import = Import {
        name: "printf".to_string(),
        library: Some("libc.so.6".to_string()),
        address: Some(0x2000),
        ordinal: None,
    };

    assert_eq!(import.name, "printf");
    assert_eq!(import.library, Some("libc.so.6".to_string()));
    assert_eq!(import.address, Some(0x2000));
    assert!(import.ordinal.is_none());
}

#[test]
fn test_export_construction() {
    let export = Export {
        name: "my_function".to_string(),
        address: 0x1100,
        ordinal: Some(1),
        forwarded_name: None,
    };

    assert_eq!(export.name, "my_function");
    assert_eq!(export.address, 0x1100);
    assert_eq!(export.ordinal, Some(1));
    assert!(export.forwarded_name.is_none());
}

#[test]
fn test_instruction_construction() {
    let instruction = Instruction {
        address: 0x1000,
        bytes: vec![0x48, 0x89, 0xe5],
        mnemonic: "mov".to_string(),
        operands: "rbp, rsp".to_string(),
        category: InstructionCategory::Memory,
        flow: ControlFlow::Sequential,
        size: 3,
    };

    assert_eq!(instruction.address, 0x1000);
    assert_eq!(instruction.bytes, vec![0x48, 0x89, 0xe5]);
    assert_eq!(instruction.mnemonic, "mov");
    assert_eq!(instruction.operands, "rbp, rsp");
    assert_eq!(instruction.category, InstructionCategory::Memory);
    assert_eq!(instruction.flow, ControlFlow::Sequential);
    assert_eq!(instruction.size, 3);
}

#[test]
fn test_basic_block_construction() {
    let bb = BasicBlock {
        id: 0,
        start_address: 0x1000,
        end_address: 0x1010,
        instructions: vec![],
        successors: vec![1, 2],
        predecessors: vec![],
    };

    assert_eq!(bb.id, 0);
    assert_eq!(bb.start_address, 0x1000);
    assert_eq!(bb.end_address, 0x1010);
    assert!(bb.instructions.is_empty());
    assert_eq!(bb.successors, vec![1, 2]);
    assert!(bb.predecessors.is_empty());
}

#[test]
fn test_function_construction() {
    let function = Function {
        name: "test_func".to_string(),
        start_address: 0x1000,
        end_address: 0x1100,
        size: 256,
        function_type: FunctionType::Normal,
        calling_convention: Some("__cdecl".to_string()),
        parameters: vec![],
        return_type: Some("int".to_string()),
    };

    assert_eq!(function.name, "test_func");
    assert_eq!(function.start_address, 0x1000);
    assert_eq!(function.end_address, 0x1100);
    assert_eq!(function.size, 256);
    assert_eq!(function.function_type, FunctionType::Normal);
    assert_eq!(function.calling_convention, Some("__cdecl".to_string()));
    assert!(function.parameters.is_empty());
    assert_eq!(function.return_type, Some("int".to_string()));
}

#[test]
fn test_parameter_construction() {
    let param = Parameter {
        name: Some("value".to_string()),
        param_type: "int".to_string(),
        location: ParameterLocation::Register("edi".to_string()),
    };

    assert_eq!(param.name, Some("value".to_string()));
    assert_eq!(param.param_type, "int");
    assert_eq!(
        param.location,
        ParameterLocation::Register("edi".to_string())
    );
}

#[cfg(feature = "serde-support")]
#[test]
fn test_serialization() {
    use serde_json;

    let format = BinaryFormat::Elf;
    let json = serde_json::to_string(&format).unwrap();
    let deserialized: BinaryFormat = serde_json::from_str(&json).unwrap();
    assert_eq!(format, deserialized);

    let arch = Architecture::X86_64;
    let json = serde_json::to_string(&arch).unwrap();
    let deserialized: Architecture = serde_json::from_str(&json).unwrap();
    assert_eq!(arch, deserialized);
}
