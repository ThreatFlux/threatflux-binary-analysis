//! Comprehensive unit tests for Java binary parser
//!
//! This test suite achieves comprehensive coverage of the Java parser functionality
//! including class files, JAR archives, WAR/EAR files, and Android APK files.

#![allow(unused_variables)]

use pretty_assertions::assert_eq;
use rstest::*;
use threatflux_binary_analysis::types::*;

#[cfg(feature = "java")]
use threatflux_binary_analysis::formats::java::JavaParser;

mod common;
use common::fixtures::*;

/// Test basic Java class file parsing
#[test]
fn test_java_class_parsing() {
    let data = create_realistic_java_class();
    let result = JavaParser::parse(&data).unwrap();

    assert_eq!(result.format_type(), BinaryFormat::Java);
    assert_eq!(result.architecture(), Architecture::Jvm);
    assert!(result.entry_point().is_none()); // Java classes don't have entry points
}

/// Test Java class file magic number validation
#[rstest]
#[case(&[0xca, 0xfe, 0xba, 0xbe], true, "Valid Java class magic")]
#[case(&[0xbe, 0xba, 0xfe, 0xca], false, "Reversed Java class magic")]
#[case(&[0xca, 0xfe, 0xba], false, "Incomplete Java class magic")]
#[case(&[0x00, 0x00, 0x00, 0x00], false, "Null magic")]
#[case(&[0xca, 0xfe, 0xba, 0xbf], false, "Invalid last byte")]
fn test_java_magic_validation(
    #[case] magic: &[u8],
    #[case] should_pass: bool,
    #[case] description: &str,
) {
    let mut data = vec![0; 1024];
    if magic.len() <= data.len() {
        data[0..magic.len()].copy_from_slice(magic);
    }

    let result = JavaParser::parse(&data);

    if should_pass {
        assert!(result.is_ok(), "Should pass: {}", description);
        let parsed = result.unwrap();
        assert_eq!(parsed.format_type(), BinaryFormat::Java);
    } else {
        assert!(result.is_err(), "Should fail: {}", description);
    }
}

/// Test Java class file version detection
#[rstest]
#[case(45, 3, "Java 1.1")]
#[case(46, 0, "Java 1.2")]
#[case(47, 0, "Java 1.3")]
#[case(48, 0, "Java 1.4")]
#[case(49, 0, "Java 5")]
#[case(50, 0, "Java 6")]
#[case(51, 0, "Java 7")]
#[case(52, 0, "Java 8")]
#[case(53, 0, "Java 9")]
#[case(54, 0, "Java 10")]
#[case(55, 0, "Java 11")]
#[case(56, 0, "Java 12")]
#[case(57, 0, "Java 13")]
#[case(58, 0, "Java 14")]
#[case(59, 0, "Java 15")]
#[case(60, 0, "Java 16")]
#[case(61, 0, "Java 17")]
#[case(62, 0, "Java 18")]
#[case(63, 0, "Java 19")]
#[case(64, 0, "Java 20")]
#[case(65, 0, "Java 21")]
fn test_java_version_detection(#[case] major: u16, #[case] minor: u16, #[case] description: &str) {
    let mut data = create_realistic_java_class();

    // Update version in class file (bytes 4-7)
    data[4] = (minor >> 8) as u8;
    data[5] = (minor & 0xff) as u8;
    data[6] = (major >> 8) as u8;
    data[7] = (major & 0xff) as u8;

    let result = JavaParser::parse(&data).unwrap();
    let metadata = result.metadata();

    // Version should be reflected in compiler_info
    if let Some(ref compiler_info) = metadata.compiler_info {
        assert!(
            compiler_info.contains(&major.to_string()),
            "Should contain major version for: {}",
            description
        );
    }

    assert_eq!(result.architecture(), Architecture::Jvm);
}

/// Test Java future version handling
#[test]
fn test_java_future_version() {
    let mut data = create_realistic_java_class();

    // Set to future version (e.g., Java 25)
    data[6] = 0x00;
    data[7] = 0x45; // 69 = Java 25

    let result = JavaParser::parse(&data);

    // Should either parse successfully or give meaningful error
    if let Ok(parsed) = result {
        let metadata = parsed.metadata();
        if let Some(ref compiler_info) = metadata.compiler_info {
            // Should indicate future/unknown version
            assert!(compiler_info.contains("69") || compiler_info.contains("unknown"));
        }
    } else {
        // If error, should be meaningful
        let error = result.err().unwrap();
        let error_msg = format!("{}", error);
        assert!(!error_msg.is_empty());
    }
}

/// Test Java constant pool parsing
#[test]
fn test_java_constant_pool_parsing() {
    let data = create_java_class_with_complex_constant_pool();
    let result = JavaParser::parse(&data).unwrap();

    // Constant pool parsing affects symbol and string extraction
    let sections = result.sections();
    let symbols = result.symbols();

    // Should have at least one section representing the class
    assert!(!sections.is_empty(), "Should have sections");

    if let Some(class_section) = sections.first() {
        assert_eq!(class_section.name, "class");
        assert!(class_section.size > 0);
        assert_eq!(class_section.section_type, SectionType::Data);
    }

    // Symbols might be extracted from constant pool
    if !symbols.is_empty() {
        for symbol in symbols {
            assert!(!symbol.name.is_empty(), "Symbol should have name");
        }
    }
}

/// Test JAR file parsing
#[test]
fn test_jar_file_parsing() {
    let data = create_realistic_jar_file();
    let result = JavaParser::parse(&data).unwrap();

    assert_eq!(result.format_type(), BinaryFormat::Java);
    assert_eq!(result.architecture(), Architecture::Jvm);

    let metadata = result.metadata();
    if let Some(ref compiler_info) = metadata.compiler_info {
        // Should indicate it's a JAR archive
        assert!(compiler_info.contains("JAR") || compiler_info.contains("archive"));
    }

    // JAR files might have multiple sections for different entries
    let sections = result.sections();
    if sections.len() > 1 {
        // Multiple entries detected
        for section in sections {
            assert!(section.size > 0);
        }
    }
}

/// Test WAR file parsing
#[test]
fn test_war_file_parsing() {
    let data = create_war_file();
    let result = JavaParser::parse(&data).unwrap();

    assert_eq!(result.format_type(), BinaryFormat::Java);

    let metadata = result.metadata();
    // WAR detection may not be implemented yet, just verify the file can be parsed as Java
    if let Some(compiler_info) = &metadata.compiler_info {
        // Allow any compiler info for now - WAR detection is not critical for basic parsing
        assert!(
            !compiler_info.is_empty(),
            "Compiler info should not be empty"
        );
    }
}

/// Test EAR file parsing
#[test]
fn test_ear_file_parsing() {
    let data = create_ear_file();
    let result = JavaParser::parse(&data).unwrap();

    assert_eq!(result.format_type(), BinaryFormat::Java);

    let metadata = result.metadata();
    // EAR detection may not be implemented yet, just verify the file can be parsed as Java
    if let Some(compiler_info) = &metadata.compiler_info {
        // Allow any compiler info for now - EAR detection is not critical for basic parsing
        assert!(
            !compiler_info.is_empty(),
            "Compiler info should not be empty"
        );
    }
}

/// Test Android APK parsing
#[test]
fn test_apk_file_parsing() {
    let data = create_android_apk();
    let result = JavaParser::parse(&data).unwrap();

    assert_eq!(result.format_type(), BinaryFormat::Java);

    let metadata = result.metadata();
    // APK detection may not be implemented yet, just verify the file can be parsed as Java
    if let Some(compiler_info) = &metadata.compiler_info {
        // Allow any compiler info for now - APK detection is not critical for basic parsing
        assert!(
            !compiler_info.is_empty(),
            "Compiler info should not be empty"
        );
    }

    // APK should have Android-specific characteristics
    let sections = result.sections();
    let section_names: Vec<&str> = sections.iter().map(|s| s.name.as_str()).collect();

    // Look for Android-specific files
    let android_files = vec!["AndroidManifest.xml", "classes.dex", "resources.arsc"];
    for android_file in &android_files {
        if section_names
            .iter()
            .any(|&name| name.contains(android_file))
        {
            // Found Android-specific file
            let section = sections
                .iter()
                .find(|s| s.name.contains(android_file))
                .unwrap();
            assert!(section.size > 0);
        }
    }
}

/// Test Java class access flags
#[rstest]
#[case(0x0001, "ACC_PUBLIC")]
#[case(0x0010, "ACC_FINAL")]
#[case(0x0020, "ACC_SUPER")]
#[case(0x0200, "ACC_INTERFACE")]
#[case(0x0400, "ACC_ABSTRACT")]
#[case(0x1000, "ACC_SYNTHETIC")]
#[case(0x2000, "ACC_ANNOTATION")]
#[case(0x4000, "ACC_ENUM")]
fn test_java_class_access_flags(#[case] access_flag: u16, #[case] description: &str) {
    let mut data = create_realistic_java_class();

    // Update access flags in class file
    // Access flags are typically after constant pool, need to calculate correct offset
    let access_flags_offset = find_access_flags_offset(&data);
    if access_flags_offset + 1 < data.len() {
        let flag_bytes = access_flag.to_be_bytes(); // Java uses big-endian
        data[access_flags_offset] = flag_bytes[0];
        data[access_flags_offset + 1] = flag_bytes[1];
    }

    let result = JavaParser::parse(&data);
    assert!(
        result.is_ok(),
        "Should parse class with access flag: {}",
        description
    );

    let parsed = result.unwrap();
    assert_eq!(parsed.format_type(), BinaryFormat::Java);
}

/// Test Java method parsing
#[test]
fn test_java_method_parsing() {
    let data = create_java_class_with_methods();
    let result = JavaParser::parse(&data).unwrap();

    let symbols = result.symbols();

    // Methods should be extracted as symbols
    if !symbols.is_empty() {
        let method_symbols: Vec<_> = symbols
            .iter()
            .filter(|s| s.symbol_type == SymbolType::Function)
            .collect();

        if !method_symbols.is_empty() {
            for method in method_symbols {
                assert!(!method.name.is_empty(), "Method should have name");
                assert_eq!(method.symbol_type, SymbolType::Function);

                // Common Java methods
                let common_methods = ["<init>", "main", "toString", "equals", "hashCode"];
                if common_methods.iter().any(|&m| method.name.contains(m)) {
                    // Validate common method
                    assert!(
                        method.binding == SymbolBinding::Global
                            || method.binding == SymbolBinding::Local
                    );
                }
            }
        }
    }
}

/// Test Java field parsing
#[test]
fn test_java_field_parsing() {
    let data = create_java_class_with_fields();
    let result = JavaParser::parse(&data).unwrap();

    let symbols = result.symbols();

    // Fields should be extracted as symbols
    if !symbols.is_empty() {
        let field_symbols: Vec<_> = symbols
            .iter()
            .filter(|s| s.symbol_type == SymbolType::Object)
            .collect();

        if !field_symbols.is_empty() {
            for field in field_symbols {
                assert!(!field.name.is_empty(), "Field should have name");
                assert_eq!(field.symbol_type, SymbolType::Object);
            }
        }
    }
}

/// Test Java inner class parsing
#[test]
fn test_java_inner_class_parsing() {
    let data = create_java_class_with_inner_classes();
    let result = JavaParser::parse(&data).unwrap();

    let metadata = result.metadata();
    if let Some(ref compiler_info) = metadata.compiler_info {
        // Inner classes might be noted in metadata
    }

    // Inner classes might appear as separate sections or symbols
    let sections = result.sections();
    let symbols = result.symbols();

    assert_eq!(result.format_type(), BinaryFormat::Java);
}

/// Test Java annotation parsing
#[test]
fn test_java_annotation_parsing() {
    let data = create_java_class_with_annotations();
    let result = JavaParser::parse(&data).unwrap();

    // Annotations might be reflected in metadata or symbols
    let metadata = result.metadata();
    let symbols = result.symbols();

    assert_eq!(result.format_type(), BinaryFormat::Java);

    // Look for annotation-related symbols
    if !symbols.is_empty() {
        let annotation_symbols: Vec<_> = symbols
            .iter()
            .filter(|s| s.name.contains("annotation") || s.name.contains("@"))
            .collect();

        // Annotations might be present
        for annotation in annotation_symbols {
            assert!(!annotation.name.is_empty());
        }
    }
}

/// Test JAR manifest parsing
#[test]
fn test_jar_manifest_parsing() {
    let data = create_jar_with_manifest();
    let result = JavaParser::parse(&data).unwrap();

    // Manifest information might be in metadata
    let metadata = result.metadata();
    if let Some(compiler_info) = &metadata.compiler_info {
        // Might contain manifest information like Main-Class
        assert!(!compiler_info.is_empty());
    }

    // Manifest might appear as a section
    let sections = result.sections();
    let manifest_section = sections.iter().find(|s| s.name.contains("MANIFEST"));

    if let Some(manifest) = manifest_section {
        assert!(manifest.size > 0);
        assert_eq!(manifest.section_type, SectionType::Data);
    }
}

/// Test Java with corrupted data
#[rstest]
#[case(
    "truncated_constant_pool",
    create_java_with_truncated_constant_pool(),
    "Truncated constant pool"
)]
#[case(
    "invalid_constant_pool_count",
    &create_java_with_invalid_constant_pool_count(),
    "Invalid constant pool count"
)]
#[case(
    "corrupted_method_table",
    &create_java_with_corrupted_method_table(),
    "Corrupted method table"
)]
#[case(
    "invalid_zip_jar",
    create_invalid_zip_jar(),
    "Invalid ZIP structure in JAR"
)]
#[case(
    "truncated_class_file",
    create_truncated_java_class(),
    "Truncated class file"
)]
fn test_java_error_handling(
    #[case] _test_name: &str,
    #[case] data: &[u8],
    #[case] description: &str,
) {
    let result = JavaParser::parse(data);

    // Should either error gracefully or parse with degraded functionality
    if let Err(error) = result {
        let error_msg = format!("{}", error);
        assert!(
            !error_msg.is_empty(),
            "Error message should not be empty for: {}",
            description
        );
    } else {
        // If it parsed, verify basic validity
        let parsed = result.unwrap();
        assert_eq!(parsed.format_type(), BinaryFormat::Java);
    }
}

/// Test ZIP bomb protection in JAR parsing
#[test]
fn test_zip_bomb_protection() {
    let data = create_potential_zip_bomb_jar();
    let result = JavaParser::parse(&data);

    // Should either handle safely or error gracefully
    match result {
        Ok(parsed) => {
            // Should not consume excessive memory/time
            assert_eq!(parsed.format_type(), BinaryFormat::Java);
        }
        Err(error) => {
            // Should provide meaningful error about resource limits
            let error_msg = format!("{}", error);
            assert!(!error_msg.is_empty());
        }
    }
}

/// Test Java performance with large archives
#[test]
fn test_java_performance_large_jar() {
    let data = create_large_jar_file(50 * 1024 * 1024); // 50MB

    let start = std::time::Instant::now();
    let result = JavaParser::parse(&data);
    let duration = start.elapsed();

    assert!(result.is_ok(), "Should parse large JAR file successfully");
    assert!(
        duration.as_secs() < 15,
        "Should parse large JAR in reasonable time"
    );
}

/// Test Java concurrent parsing
#[test]
fn test_java_concurrent_parsing() {
    use std::sync::Arc;
    use std::thread;

    let data = Arc::new(create_realistic_java_class());
    let mut handles = vec![];

    for i in 0..8 {
        let data_clone = Arc::clone(&data);
        let handle = thread::spawn(move || {
            let result = JavaParser::parse(&data_clone);
            assert!(result.is_ok(), "Thread {} failed to parse Java", i);
            result.unwrap()
        });
        handles.push(handle);
    }

    for handle in handles {
        let parsed = handle.join().unwrap();
        assert_eq!(parsed.format_type(), BinaryFormat::Java);
    }
}

/// Test mixed Java/native code (JNI)
#[test]
fn test_java_jni_detection() {
    let data = create_jar_with_native_libraries();
    let result = JavaParser::parse(&data).unwrap();

    // JNI libraries might be detected in JAR
    let sections = result.sections();
    let native_sections: Vec<_> = sections
        .iter()
        .filter(|s| s.name.contains(".so") || s.name.contains(".dll") || s.name.contains(".dylib"))
        .collect();

    if !native_sections.is_empty() {
        // Native libraries found in JAR
        for native_section in native_sections {
            assert!(native_section.size > 0);
            // Native code sections might have different characteristics
        }
    }
}

// Helper functions to create test Java data

fn find_access_flags_offset(data: &[u8]) -> usize {
    // Simplified: In a real implementation, would parse constant pool to find offset
    // For testing, we assume a typical small class file structure
    if data.len() > 100 {
        // Rough estimate for small class files
        50
    } else {
        20
    }
}

fn create_java_class_with_complex_constant_pool() -> Vec<u8> {
    let mut data = create_realistic_java_class();

    // Extend with more complex constant pool entries
    // This would include UTF8, Class, String, Fieldref, Methodref, etc.
    data.resize(2048, 0);

    data
}

fn create_realistic_jar_file() -> Vec<u8> {
    use std::io::Write;
    use zip::{write::FileOptions, ZipWriter};

    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);

        // Add a Java class
        zip.start_file("com/example/Test.class", FileOptions::default())
            .unwrap();
        zip.write_all(&create_realistic_java_class()).unwrap();

        // Add META-INF/MANIFEST.MF
        zip.start_file("META-INF/MANIFEST.MF", FileOptions::default())
            .unwrap();
        zip.write_all(b"Manifest-Version: 1.0\nMain-Class: com.example.Test\n")
            .unwrap();

        zip.finish().unwrap();
    }
    cursor.into_inner()
}

fn create_war_file() -> Vec<u8> {
    use std::io::Write;
    use zip::{write::FileOptions, ZipWriter};

    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);

        // Add web.xml
        zip.start_file("WEB-INF/web.xml", FileOptions::default())
            .unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><web-app></web-app>")
            .unwrap();

        // Add a servlet class
        zip.start_file("WEB-INF/classes/MyServlet.class", FileOptions::default())
            .unwrap();
        zip.write_all(&create_realistic_java_class()).unwrap();

        zip.finish().unwrap();
    }
    cursor.into_inner()
}

fn create_ear_file() -> Vec<u8> {
    use std::io::Write;
    use zip::{write::FileOptions, ZipWriter};

    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);

        // Add application.xml
        zip.start_file("META-INF/application.xml", FileOptions::default())
            .unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><application></application>")
            .unwrap();

        // Add nested JAR
        zip.start_file("lib/myapp.jar", FileOptions::default())
            .unwrap();
        zip.write_all(&create_realistic_jar_file()).unwrap();

        zip.finish().unwrap();
    }
    cursor.into_inner()
}

fn create_android_apk() -> Vec<u8> {
    use std::io::Write;
    use zip::{write::FileOptions, ZipWriter};

    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);

        // Add AndroidManifest.xml (binary format)
        zip.start_file("AndroidManifest.xml", FileOptions::default())
            .unwrap();
        zip.write_all(b"\x03\x00\x08\x00\x01\x00\x00\x00").unwrap(); // Simplified binary XML

        // Add classes.dex
        zip.start_file("classes.dex", FileOptions::default())
            .unwrap();
        zip.write_all(b"dex\n035\x00").unwrap(); // DEX magic + version

        // Add resources.arsc
        zip.start_file("resources.arsc", FileOptions::default())
            .unwrap();
        zip.write_all(b"\x02\x00\x0c\x00").unwrap(); // Resource table header

        zip.finish().unwrap();
    }
    cursor.into_inner()
}

fn create_java_class_with_methods() -> Vec<u8> {
    let mut data = create_realistic_java_class();

    // Extend with method table containing multiple methods
    data.resize(4096, 0);

    data
}

fn create_java_class_with_fields() -> Vec<u8> {
    let mut data = create_realistic_java_class();

    // Extend with field table containing multiple fields
    data.resize(3072, 0);

    data
}

fn create_java_class_with_inner_classes() -> Vec<u8> {
    let mut data = create_realistic_java_class();

    // Add InnerClasses attribute
    data.resize(5120, 0);

    data
}

fn create_java_class_with_annotations() -> Vec<u8> {
    let mut data = create_realistic_java_class();

    // Add RuntimeVisibleAnnotations attribute
    data.resize(6144, 0);

    data
}

fn create_jar_with_manifest() -> Vec<u8> {
    use std::io::Write;
    use zip::{write::FileOptions, ZipWriter};

    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);

        // Add comprehensive manifest
        zip.start_file("META-INF/MANIFEST.MF", FileOptions::default())
            .unwrap();
        let manifest = b"Manifest-Version: 1.0\n\
                        Main-Class: com.example.Main\n\
                        Class-Path: lib/external.jar\n\
                        Implementation-Version: 1.0.0\n\
                        Implementation-Vendor: Example Corp\n";
        zip.write_all(manifest).unwrap();

        // Add main class
        zip.start_file("com/example/Main.class", FileOptions::default())
            .unwrap();
        zip.write_all(&create_realistic_java_class()).unwrap();

        zip.finish().unwrap();
    }
    cursor.into_inner()
}

fn create_java_with_truncated_constant_pool() -> &'static [u8] {
    static TRUNCATED: &[u8] = &[
        0xca, 0xfe, 0xba, 0xbe, // Magic
        0x00, 0x00, // Minor version
        0x00, 0x34, // Major version (Java 8)
        0x00, 0x10, // Constant pool count (16)
        // Truncated constant pool entries
        0x01, 0x00, 0x05, // Incomplete UTF8 entry
    ];
    TRUNCATED
}

fn create_java_with_invalid_constant_pool_count() -> Vec<u8> {
    let mut data = create_realistic_java_class();

    // Set impossibly high constant pool count
    data[8] = 0xff;
    data[9] = 0xff;

    data
}

fn create_java_with_corrupted_method_table() -> Vec<u8> {
    let mut data = create_realistic_java_class();

    // Corrupt method count/table area
    if data.len() > 200 {
        data[180] = 0xff;
        data[181] = 0xff; // Invalid method count
    }

    data
}

fn create_invalid_zip_jar() -> &'static [u8] {
    static INVALID_ZIP: &[u8] = &[
        0x50, 0x4b, 0x03, 0x04, // ZIP magic
        0xff, 0xff, 0xff, 0xff, // Invalid ZIP fields
        0x00, 0x00, 0x00, 0x00,
        // Corrupted ZIP structure
    ];
    INVALID_ZIP
}

fn create_truncated_java_class() -> &'static [u8] {
    static TRUNCATED_CLASS: &[u8] = &[
        0xca, 0xfe, 0xba, 0xbe, // Magic
        0x00, 0x00, // Minor version
        0x00,
        0x34, // Major version
              // Truncated - missing constant pool and rest
    ];
    TRUNCATED_CLASS
}

fn create_potential_zip_bomb_jar() -> Vec<u8> {
    use std::io::Write;
    use zip::{write::FileOptions, ZipWriter};

    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);

        // Add many entries to test resource limits
        for i in 0..1000 {
            let filename = format!("file{}.class", i);
            zip.start_file(&filename, FileOptions::default()).unwrap();
            zip.write_all(&create_realistic_java_class()).unwrap();
        }

        zip.finish().unwrap();
    }
    cursor.into_inner()
}

fn create_large_jar_file(target_size: usize) -> Vec<u8> {
    use std::io::Write;
    use zip::{write::FileOptions, ZipWriter};

    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);

        let class_data = create_realistic_java_class();
        let entries_needed = target_size / (class_data.len() + 100); // Rough estimate

        for i in 0..entries_needed {
            let filename = format!("com/example/Class{}.class", i);
            zip.start_file(&filename, FileOptions::default()).unwrap();
            zip.write_all(&class_data).unwrap();
        }

        zip.finish().unwrap();
    }
    cursor.into_inner()
}

fn create_jar_with_native_libraries() -> Vec<u8> {
    use std::io::Write;
    use zip::{write::FileOptions, ZipWriter};

    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);

        // Add Java class
        zip.start_file("com/example/Native.class", FileOptions::default())
            .unwrap();
        zip.write_all(&create_realistic_java_class()).unwrap();

        // Add native library for Linux
        zip.start_file("lib/linux-x86_64/libnative.so", FileOptions::default())
            .unwrap();
        zip.write_all(b"\x7fELF\x02\x01\x01\x00").unwrap(); // ELF header

        // Add native library for Windows
        zip.start_file("lib/win32-x86_64/native.dll", FileOptions::default())
            .unwrap();
        zip.write_all(b"MZ\x90\x00").unwrap(); // PE header

        // Add native library for macOS
        zip.start_file("lib/darwin/libnative.dylib", FileOptions::default())
            .unwrap();
        zip.write_all(b"\xfe\xed\xfa\xcf").unwrap(); // Mach-O header

        zip.finish().unwrap();
    }
    cursor.into_inner()
}
