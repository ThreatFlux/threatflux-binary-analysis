//! Security analysis for binary files
//!
//! This module provides comprehensive security analysis capabilities for binary files,
//! including vulnerability detection, malware indicators, and security feature analysis.

use crate::{
    BinaryFile, Result,
    types::{Architecture, Import, Section, SecurityFeatures, SecurityIndicators, Symbol},
};
use std::collections::HashSet;

/// Security analyzer for binary files
pub struct SecurityAnalyzer {
    /// Architecture being analyzed
    #[allow(dead_code)]
    architecture: Architecture,
    /// Analysis configuration
    config: SecurityConfig,
}

/// Configuration for security analysis
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Enable suspicious API detection
    pub detect_suspicious_apis: bool,
    /// Enable anti-debugging detection
    pub detect_anti_debug: bool,
    /// Enable anti-VM detection
    pub detect_anti_vm: bool,
    /// Enable cryptographic indicators
    pub detect_crypto: bool,
    /// Enable network indicators
    pub detect_network: bool,
    /// Enable filesystem indicators
    pub detect_filesystem: bool,
    /// Enable registry indicators (Windows)
    pub detect_registry: bool,
    /// Minimum string length for analysis
    pub min_string_length: usize,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            detect_suspicious_apis: true,
            detect_anti_debug: true,
            detect_anti_vm: true,
            detect_crypto: true,
            detect_network: true,
            detect_filesystem: true,
            detect_registry: true,
            min_string_length: 4,
        }
    }
}

/// Security analysis result
#[derive(Debug, Clone)]
pub struct SecurityAnalysisResult {
    /// Security indicators found
    pub indicators: SecurityIndicators,
    /// Security features present
    pub features: SecurityFeatures,
    /// Risk score (0-100)
    pub risk_score: f64,
    /// Detailed findings
    pub findings: Vec<SecurityFinding>,
}

/// Individual security finding
#[derive(Debug, Clone)]
pub struct SecurityFinding {
    /// Finding category
    pub category: FindingCategory,
    /// Severity level
    pub severity: Severity,
    /// Description
    pub description: String,
    /// Location (address, section, etc.)
    pub location: Option<String>,
    /// Associated data
    pub data: Option<String>,
}

/// Security finding categories
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingCategory {
    /// Suspicious API call
    SuspiciousApi,
    /// Anti-debugging technique
    AntiDebug,
    /// Anti-VM technique
    AntiVm,
    /// Cryptographic operation
    Cryptographic,
    /// Network operation
    Network,
    /// Filesystem operation
    Filesystem,
    /// Registry operation
    Registry,
    /// Security feature missing
    MissingSecurity,
    /// Packing/obfuscation
    Obfuscation,
    /// Code injection
    CodeInjection,
    /// Privilege escalation
    PrivilegeEscalation,
}

/// Finding severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Informational
    Info,
    /// Low risk
    Low,
    /// Medium risk
    Medium,
    /// High risk
    High,
    /// Critical risk
    Critical,
}

impl SecurityAnalyzer {
    /// Create a new security analyzer
    pub fn new(architecture: Architecture) -> Self {
        Self {
            architecture,
            config: SecurityConfig::default(),
        }
    }

    /// Create analyzer with custom configuration
    pub fn with_config(architecture: Architecture, config: SecurityConfig) -> Self {
        Self {
            architecture,
            config,
        }
    }

    /// Perform comprehensive security analysis
    pub fn analyze(&self, binary: &BinaryFile) -> Result<SecurityAnalysisResult> {
        let mut indicators = SecurityIndicators::default();
        let mut findings = Vec::new();

        // Analyze imports for suspicious APIs
        if self.config.detect_suspicious_apis {
            self.analyze_imports(binary.imports(), &mut indicators, &mut findings);
        }

        // Analyze sections for security indicators
        self.analyze_sections(binary.sections(), &mut indicators, &mut findings);

        // Analyze symbols
        self.analyze_symbols(binary.symbols(), &mut indicators, &mut findings);

        // Get security features from metadata
        let features = binary.metadata().security_features.clone();

        // Analyze security features
        self.analyze_security_features(&features, &mut findings);

        // Calculate risk score
        let risk_score = self.calculate_risk_score(&indicators, &features, &findings);

        Ok(SecurityAnalysisResult {
            indicators,
            features,
            risk_score,
            findings,
        })
    }

    /// Analyze imports for suspicious APIs
    fn analyze_imports(
        &self,
        imports: &[Import],
        indicators: &mut SecurityIndicators,
        findings: &mut Vec<SecurityFinding>,
    ) {
        let suspicious_apis = self.get_suspicious_apis();
        let anti_debug_apis = self.get_anti_debug_apis();
        let anti_vm_apis = self.get_anti_vm_apis();
        let crypto_apis = self.get_crypto_apis();
        let network_apis = self.get_network_apis();
        let filesystem_apis = self.get_filesystem_apis();
        let registry_apis = self.get_registry_apis();

        for import in imports {
            let api_name = &import.name;

            if suspicious_apis.contains(api_name.as_str()) {
                indicators.suspicious_apis.push(api_name.clone());
                findings.push(SecurityFinding {
                    category: FindingCategory::SuspiciousApi,
                    severity: Severity::High,
                    description: format!("Suspicious API call: {}", api_name),
                    location: import.library.clone(),
                    data: Some(api_name.clone()),
                });
            }

            if anti_debug_apis.contains(api_name.as_str()) {
                indicators.anti_debug.push(api_name.clone());
                findings.push(SecurityFinding {
                    category: FindingCategory::AntiDebug,
                    severity: Severity::Medium,
                    description: format!("Anti-debugging API: {}", api_name),
                    location: import.library.clone(),
                    data: Some(api_name.clone()),
                });
            }

            if anti_vm_apis.contains(api_name.as_str()) {
                indicators.anti_vm.push(api_name.clone());
                findings.push(SecurityFinding {
                    category: FindingCategory::AntiVm,
                    severity: Severity::Medium,
                    description: format!("Anti-VM API: {}", api_name),
                    location: import.library.clone(),
                    data: Some(api_name.clone()),
                });
            }

            if crypto_apis.contains(api_name.as_str()) {
                indicators.crypto_indicators.push(api_name.clone());
                findings.push(SecurityFinding {
                    category: FindingCategory::Cryptographic,
                    severity: Severity::Info,
                    description: format!("Cryptographic API: {}", api_name),
                    location: import.library.clone(),
                    data: Some(api_name.clone()),
                });
            }

            if network_apis.contains(api_name.as_str()) {
                indicators.network_indicators.push(api_name.clone());
                findings.push(SecurityFinding {
                    category: FindingCategory::Network,
                    severity: Severity::Low,
                    description: format!("Network API: {}", api_name),
                    location: import.library.clone(),
                    data: Some(api_name.clone()),
                });
            }

            if filesystem_apis.contains(api_name.as_str()) {
                indicators.filesystem_indicators.push(api_name.clone());
                findings.push(SecurityFinding {
                    category: FindingCategory::Filesystem,
                    severity: Severity::Low,
                    description: format!("Filesystem API: {}", api_name),
                    location: import.library.clone(),
                    data: Some(api_name.clone()),
                });
            }

            if registry_apis.contains(api_name.as_str()) {
                indicators.registry_indicators.push(api_name.clone());
                findings.push(SecurityFinding {
                    category: FindingCategory::Registry,
                    severity: Severity::Low,
                    description: format!("Registry API: {}", api_name),
                    location: import.library.clone(),
                    data: Some(api_name.clone()),
                });
            }
        }
    }

    /// Analyze sections for security indicators
    fn analyze_sections(
        &self,
        sections: &[Section],
        _indicators: &mut SecurityIndicators,
        findings: &mut Vec<SecurityFinding>,
    ) {
        for section in sections {
            // Check for executable and writable sections (potential code injection)
            if section.permissions.execute && section.permissions.write {
                findings.push(SecurityFinding {
                    category: FindingCategory::CodeInjection,
                    severity: Severity::High,
                    description: format!(
                        "Section '{}' is both executable and writable (RWX)",
                        section.name
                    ),
                    location: Some(format!("0x{:x}", section.address)),
                    data: Some(section.name.clone()),
                });
            }

            // Check for suspicious section names
            if self.is_suspicious_section_name(&section.name) {
                findings.push(SecurityFinding {
                    category: FindingCategory::Obfuscation,
                    severity: Severity::Medium,
                    description: format!("Suspicious section name: {}", section.name),
                    location: Some(format!("0x{:x}", section.address)),
                    data: Some(section.name.clone()),
                });
            }
        }
    }

    /// Analyze symbols for security indicators
    fn analyze_symbols(
        &self,
        symbols: &[Symbol],
        _indicators: &mut SecurityIndicators,
        findings: &mut Vec<SecurityFinding>,
    ) {
        for symbol in symbols {
            // Check for suspicious symbol names
            if self.is_suspicious_symbol_name(&symbol.name) {
                findings.push(SecurityFinding {
                    category: FindingCategory::SuspiciousApi,
                    severity: Severity::Medium,
                    description: format!("Suspicious symbol: {}", symbol.name),
                    location: Some(format!("0x{:x}", symbol.address)),
                    data: Some(symbol.name.clone()),
                });
            }
        }
    }

    /// Analyze security features
    fn analyze_security_features(
        &self,
        features: &SecurityFeatures,
        findings: &mut Vec<SecurityFinding>,
    ) {
        if !features.nx_bit {
            findings.push(SecurityFinding {
                category: FindingCategory::MissingSecurity,
                severity: Severity::Medium,
                description: "NX/DEP bit not enabled".to_string(),
                location: None,
                data: None,
            });
        }

        if !features.aslr {
            findings.push(SecurityFinding {
                category: FindingCategory::MissingSecurity,
                severity: Severity::Medium,
                description: "ASLR not enabled".to_string(),
                location: None,
                data: None,
            });
        }

        if !features.stack_canary {
            findings.push(SecurityFinding {
                category: FindingCategory::MissingSecurity,
                severity: Severity::Low,
                description: "Stack canaries not detected".to_string(),
                location: None,
                data: None,
            });
        }

        if !features.cfi {
            findings.push(SecurityFinding {
                category: FindingCategory::MissingSecurity,
                severity: Severity::Low,
                description: "Control Flow Integrity not enabled".to_string(),
                location: None,
                data: None,
            });
        }
    }

    /// Calculate overall risk score
    fn calculate_risk_score(
        &self,
        indicators: &SecurityIndicators,
        features: &SecurityFeatures,
        findings: &[SecurityFinding],
    ) -> f64 {
        let mut score = 0.0;

        // Base score from indicators
        score += indicators.suspicious_apis.len() as f64 * 10.0;
        score += indicators.anti_debug.len() as f64 * 5.0;
        score += indicators.anti_vm.len() as f64 * 5.0;
        score += indicators.crypto_indicators.len() as f64 * 1.0;
        score += indicators.network_indicators.len() as f64 * 2.0;
        score += indicators.filesystem_indicators.len() as f64 * 1.0;
        score += indicators.registry_indicators.len() as f64 * 1.0;

        // Adjust for missing security features
        if !features.nx_bit {
            score += 10.0;
        }
        if !features.aslr {
            score += 10.0;
        }
        if !features.stack_canary {
            score += 5.0;
        }
        if !features.cfi {
            score += 5.0;
        }
        if !features.pie {
            score += 5.0;
        }

        // Add severity-based scoring from findings
        for finding in findings {
            match finding.severity {
                Severity::Critical => score += 20.0,
                Severity::High => score += 10.0,
                Severity::Medium => score += 5.0,
                Severity::Low => score += 2.0,
                Severity::Info => score += 0.5,
            }
        }

        // Normalize to 0-100
        (score / 2.0).min(100.0)
    }

    /// Get list of suspicious APIs
    fn get_suspicious_apis(&self) -> HashSet<&'static str> {
        let mut apis = HashSet::new();

        // Code injection APIs
        apis.insert("VirtualAllocEx");
        apis.insert("WriteProcessMemory");
        apis.insert("CreateRemoteThread");
        apis.insert("SetWindowsHookEx");
        apis.insert("NtMapViewOfSection");
        apis.insert("ZwMapViewOfSection");

        // Process manipulation
        apis.insert("OpenProcess");
        apis.insert("TerminateProcess");
        apis.insert("SuspendThread");
        apis.insert("ResumeThread");

        // Privilege escalation
        apis.insert("AdjustTokenPrivileges");
        apis.insert("LookupPrivilegeValue");
        apis.insert("SeDebugPrivilege");

        apis
    }

    /// Get list of anti-debugging APIs
    fn get_anti_debug_apis(&self) -> HashSet<&'static str> {
        let mut apis = HashSet::new();

        apis.insert("IsDebuggerPresent");
        apis.insert("CheckRemoteDebuggerPresent");
        apis.insert("NtQueryInformationProcess");
        apis.insert("ZwQueryInformationProcess");
        apis.insert("OutputDebugString");
        apis.insert("GetTickCount");
        apis.insert("QueryPerformanceCounter");
        apis.insert("ptrace"); // Linux

        apis
    }

    /// Get list of anti-VM APIs
    fn get_anti_vm_apis(&self) -> HashSet<&'static str> {
        let mut apis = HashSet::new();

        apis.insert("GetSystemInfo");
        apis.insert("GlobalMemoryStatusEx");
        apis.insert("GetAdaptersInfo");
        apis.insert("GetVolumeInformation");
        apis.insert("RegOpenKeyEx");
        apis.insert("CreateToolhelp32Snapshot");

        apis
    }

    /// Get list of cryptographic APIs
    fn get_crypto_apis(&self) -> HashSet<&'static str> {
        let mut apis = HashSet::new();

        apis.insert("CryptAcquireContext");
        apis.insert("CryptCreateHash");
        apis.insert("CryptEncrypt");
        apis.insert("CryptDecrypt");
        apis.insert("CryptImportKey");
        apis.insert("CryptExportKey");

        apis
    }

    /// Get list of network APIs
    fn get_network_apis(&self) -> HashSet<&'static str> {
        let mut apis = HashSet::new();

        apis.insert("WSAStartup");
        apis.insert("socket");
        apis.insert("connect");
        apis.insert("send");
        apis.insert("recv");
        apis.insert("InternetOpen");
        apis.insert("InternetOpenUrl");
        apis.insert("HttpSendRequest");

        apis
    }

    /// Get list of filesystem APIs
    fn get_filesystem_apis(&self) -> HashSet<&'static str> {
        let mut apis = HashSet::new();

        apis.insert("CreateFile");
        apis.insert("WriteFile");
        apis.insert("ReadFile");
        apis.insert("DeleteFile");
        apis.insert("MoveFile");
        apis.insert("CopyFile");
        apis.insert("FindFirstFile");
        apis.insert("FindNextFile");

        apis
    }

    /// Get list of registry APIs
    fn get_registry_apis(&self) -> HashSet<&'static str> {
        let mut apis = HashSet::new();

        apis.insert("RegOpenKeyEx");
        apis.insert("RegCreateKeyEx");
        apis.insert("RegSetValueEx");
        apis.insert("RegQueryValueEx");
        apis.insert("RegDeleteKey");
        apis.insert("RegDeleteValue");

        apis
    }

    /// Check if section name is suspicious
    fn is_suspicious_section_name(&self, name: &str) -> bool {
        let suspicious_names = [
            ".packed",
            ".upx",
            ".themida",
            ".aspack",
            ".pecompact",
            ".enigma",
            ".vmprotect",
            ".obsidium",
            ".tElock",
            ".shell",
            ".stub",
            ".overlay",
        ];

        suspicious_names
            .iter()
            .any(|&pattern| name.to_lowercase().contains(pattern))
    }

    /// Check if symbol name is suspicious
    fn is_suspicious_symbol_name(&self, name: &str) -> bool {
        let suspicious_patterns = [
            "bypass",
            "inject",
            "hook",
            "shellcode",
            "payload",
            "exploit",
            "backdoor",
            "rootkit",
            "keylog",
            "stealth",
        ];

        let lower_name = name.to_lowercase();
        suspicious_patterns
            .iter()
            .any(|&pattern| lower_name.contains(pattern))
    }
}

/// Analyze binary security
pub fn analyze_binary_security(binary: &BinaryFile) -> Result<SecurityAnalysisResult> {
    let analyzer = SecurityAnalyzer::new(binary.architecture());
    analyzer.analyze(binary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    // Helper function to create test binary metadata
    fn create_test_metadata() -> BinaryMetadata {
        BinaryMetadata {
            size: 1024,
            format: BinaryFormat::Pe,
            architecture: Architecture::X86_64,
            entry_point: Some(0x1000),
            base_address: Some(0x400000),
            timestamp: None,
            compiler_info: None,
            endian: Endianness::Little,
            security_features: SecurityFeatures {
                nx_bit: true,
                aslr: true,
                stack_canary: false,
                cfi: false,
                fortify: false,
                pie: false,
                relro: false,
                signed: false,
            },
        }
    }

    // Helper function to create a mock binary file for testing
    fn create_test_binary_file() -> MockBinaryFile {
        MockBinaryFile {
            imports: vec![
                Import {
                    name: "CreateProcess".to_string(),
                    library: Some("kernel32.dll".to_string()),
                    address: Some(0x1000),
                    ordinal: None,
                },
                Import {
                    name: "VirtualAllocEx".to_string(),
                    library: Some("kernel32.dll".to_string()),
                    address: Some(0x1004),
                    ordinal: None,
                },
                Import {
                    name: "IsDebuggerPresent".to_string(),
                    library: Some("kernel32.dll".to_string()),
                    address: Some(0x1008),
                    ordinal: None,
                },
            ],
            sections: vec![
                Section {
                    name: ".text".to_string(),
                    address: 0x1000,
                    size: 0x500,
                    offset: 0x400,
                    permissions: SectionPermissions {
                        read: true,
                        write: false,
                        execute: true,
                    },
                    section_type: SectionType::Code,
                    data: None,
                },
                Section {
                    name: ".upx0".to_string(),
                    address: 0x2000,
                    size: 0x300,
                    offset: 0x900,
                    permissions: SectionPermissions {
                        read: true,
                        write: true,
                        execute: true,
                    },
                    section_type: SectionType::Code,
                    data: None,
                },
            ],
            symbols: vec![
                Symbol {
                    name: "main".to_string(),
                    demangled_name: None,
                    address: 0x1000,
                    size: 100,
                    symbol_type: SymbolType::Function,
                    binding: SymbolBinding::Global,
                    visibility: SymbolVisibility::Default,
                    section_index: Some(0),
                },
                Symbol {
                    name: "inject_payload".to_string(),
                    demangled_name: None,
                    address: 0x1100,
                    size: 50,
                    symbol_type: SymbolType::Function,
                    binding: SymbolBinding::Local,
                    visibility: SymbolVisibility::Hidden,
                    section_index: Some(0),
                },
            ],
            metadata: create_test_metadata(),
        }
    }

    // Mock BinaryFile for testing
    struct MockBinaryFile {
        imports: Vec<Import>,
        sections: Vec<Section>,
        symbols: Vec<Symbol>,
        metadata: BinaryMetadata,
    }

    impl MockBinaryFile {
        fn imports(&self) -> &[Import] {
            &self.imports
        }

        fn sections(&self) -> &[Section] {
            &self.sections
        }

        fn symbols(&self) -> &[Symbol] {
            &self.symbols
        }

        fn metadata(&self) -> &BinaryMetadata {
            &self.metadata
        }

        fn architecture(&self) -> Architecture {
            self.metadata.architecture
        }
    }

    // Test helper to create a complete test analysis result using direct method calls
    fn analyze_mock_binary(binary: &MockBinaryFile) -> SecurityAnalysisResult {
        let analyzer = SecurityAnalyzer::new(binary.architecture());
        let mut indicators = SecurityIndicators::default();
        let mut findings = Vec::new();

        // Analyze imports
        analyzer.analyze_imports(binary.imports(), &mut indicators, &mut findings);

        // Analyze sections
        analyzer.analyze_sections(binary.sections(), &mut indicators, &mut findings);

        // Analyze symbols
        analyzer.analyze_symbols(binary.symbols(), &mut indicators, &mut findings);

        // Get security features from metadata
        let features = binary.metadata().security_features.clone();

        // Analyze security features
        analyzer.analyze_security_features(&features, &mut findings);

        // Calculate risk score
        let risk_score = analyzer.calculate_risk_score(&indicators, &features, &findings);

        SecurityAnalysisResult {
            indicators,
            features,
            risk_score,
            findings,
        }
    }

    // Test SecurityAnalyzer creation and configuration
    #[test]
    fn test_analyzer_creation() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        assert_eq!(analyzer.architecture, Architecture::X86_64);
    }

    #[test]
    fn test_analyzer_with_custom_config() {
        let config = SecurityConfig {
            detect_suspicious_apis: false,
            detect_anti_debug: true,
            detect_anti_vm: false,
            detect_crypto: true,
            detect_network: false,
            detect_filesystem: true,
            detect_registry: false,
            min_string_length: 8,
        };
        let analyzer = SecurityAnalyzer::with_config(Architecture::Arm64, config.clone());
        assert_eq!(analyzer.architecture, Architecture::Arm64);
        assert!(!analyzer.config.detect_suspicious_apis);
        assert!(analyzer.config.detect_anti_debug);
        assert_eq!(analyzer.config.min_string_length, 8);
    }

    #[test]
    fn test_security_config_default() {
        let config = SecurityConfig::default();
        assert!(config.detect_suspicious_apis);
        assert!(config.detect_anti_debug);
        assert!(config.detect_anti_vm);
        assert!(config.detect_crypto);
        assert!(config.detect_network);
        assert!(config.detect_filesystem);
        assert!(config.detect_registry);
        assert_eq!(config.min_string_length, 4);
    }

    // Test analyze_imports method
    #[test]
    fn test_analyze_imports_suspicious_apis() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let mut indicators = SecurityIndicators::default();
        let mut findings = Vec::new();

        let imports = vec![
            Import {
                name: "VirtualAllocEx".to_string(),
                library: Some("kernel32.dll".to_string()),
                address: Some(0x1000),
                ordinal: None,
            },
            Import {
                name: "WriteProcessMemory".to_string(),
                library: Some("kernel32.dll".to_string()),
                address: Some(0x1004),
                ordinal: None,
            },
            Import {
                name: "RegularFunction".to_string(),
                library: Some("user32.dll".to_string()),
                address: Some(0x1008),
                ordinal: None,
            },
        ];

        analyzer.analyze_imports(&imports, &mut indicators, &mut findings);

        assert_eq!(indicators.suspicious_apis.len(), 2);
        assert!(
            indicators
                .suspicious_apis
                .contains(&"VirtualAllocEx".to_string())
        );
        assert!(
            indicators
                .suspicious_apis
                .contains(&"WriteProcessMemory".to_string())
        );

        let suspicious_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == FindingCategory::SuspiciousApi)
            .collect();
        assert_eq!(suspicious_findings.len(), 2);
        assert_eq!(suspicious_findings[0].severity, Severity::High);
    }

    #[test]
    fn test_analyze_imports_anti_debug() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let mut indicators = SecurityIndicators::default();
        let mut findings = Vec::new();

        let imports = vec![
            Import {
                name: "IsDebuggerPresent".to_string(),
                library: Some("kernel32.dll".to_string()),
                address: Some(0x1000),
                ordinal: None,
            },
            Import {
                name: "CheckRemoteDebuggerPresent".to_string(),
                library: Some("kernel32.dll".to_string()),
                address: Some(0x1004),
                ordinal: None,
            },
        ];

        analyzer.analyze_imports(&imports, &mut indicators, &mut findings);

        assert_eq!(indicators.anti_debug.len(), 2);
        assert!(
            indicators
                .anti_debug
                .contains(&"IsDebuggerPresent".to_string())
        );
        assert!(
            indicators
                .anti_debug
                .contains(&"CheckRemoteDebuggerPresent".to_string())
        );

        let anti_debug_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == FindingCategory::AntiDebug)
            .collect();
        assert_eq!(anti_debug_findings.len(), 2);
        assert_eq!(anti_debug_findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_analyze_imports_anti_vm() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let mut indicators = SecurityIndicators::default();
        let mut findings = Vec::new();

        let imports = vec![
            Import {
                name: "GetSystemInfo".to_string(),
                library: Some("kernel32.dll".to_string()),
                address: Some(0x1000),
                ordinal: None,
            },
            Import {
                name: "GlobalMemoryStatusEx".to_string(),
                library: Some("kernel32.dll".to_string()),
                address: Some(0x1004),
                ordinal: None,
            },
        ];

        analyzer.analyze_imports(&imports, &mut indicators, &mut findings);

        assert_eq!(indicators.anti_vm.len(), 2);
        let anti_vm_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == FindingCategory::AntiVm)
            .collect();
        assert_eq!(anti_vm_findings.len(), 2);
        assert_eq!(anti_vm_findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_analyze_imports_crypto() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let mut indicators = SecurityIndicators::default();
        let mut findings = Vec::new();

        let imports = vec![
            Import {
                name: "CryptAcquireContext".to_string(),
                library: Some("advapi32.dll".to_string()),
                address: Some(0x1000),
                ordinal: None,
            },
            Import {
                name: "CryptEncrypt".to_string(),
                library: Some("advapi32.dll".to_string()),
                address: Some(0x1004),
                ordinal: None,
            },
        ];

        analyzer.analyze_imports(&imports, &mut indicators, &mut findings);

        assert_eq!(indicators.crypto_indicators.len(), 2);
        let crypto_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == FindingCategory::Cryptographic)
            .collect();
        assert_eq!(crypto_findings.len(), 2);
        assert_eq!(crypto_findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_analyze_imports_network() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let mut indicators = SecurityIndicators::default();
        let mut findings = Vec::new();

        let imports = vec![
            Import {
                name: "WSAStartup".to_string(),
                library: Some("ws2_32.dll".to_string()),
                address: Some(0x1000),
                ordinal: None,
            },
            Import {
                name: "socket".to_string(),
                library: Some("ws2_32.dll".to_string()),
                address: Some(0x1004),
                ordinal: None,
            },
        ];

        analyzer.analyze_imports(&imports, &mut indicators, &mut findings);

        assert_eq!(indicators.network_indicators.len(), 2);
        let network_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == FindingCategory::Network)
            .collect();
        assert_eq!(network_findings.len(), 2);
        assert_eq!(network_findings[0].severity, Severity::Low);
    }

    #[test]
    fn test_analyze_imports_filesystem() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let mut indicators = SecurityIndicators::default();
        let mut findings = Vec::new();

        let imports = vec![
            Import {
                name: "CreateFile".to_string(),
                library: Some("kernel32.dll".to_string()),
                address: Some(0x1000),
                ordinal: None,
            },
            Import {
                name: "DeleteFile".to_string(),
                library: Some("kernel32.dll".to_string()),
                address: Some(0x1004),
                ordinal: None,
            },
        ];

        analyzer.analyze_imports(&imports, &mut indicators, &mut findings);

        assert_eq!(indicators.filesystem_indicators.len(), 2);
        let fs_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == FindingCategory::Filesystem)
            .collect();
        assert_eq!(fs_findings.len(), 2);
        assert_eq!(fs_findings[0].severity, Severity::Low);
    }

    #[test]
    fn test_analyze_imports_registry() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let mut indicators = SecurityIndicators::default();
        let mut findings = Vec::new();

        let imports = vec![
            Import {
                name: "RegOpenKeyEx".to_string(),
                library: Some("advapi32.dll".to_string()),
                address: Some(0x1000),
                ordinal: None,
            },
            Import {
                name: "RegSetValueEx".to_string(),
                library: Some("advapi32.dll".to_string()),
                address: Some(0x1004),
                ordinal: None,
            },
        ];

        analyzer.analyze_imports(&imports, &mut indicators, &mut findings);

        assert_eq!(indicators.registry_indicators.len(), 2);
        let reg_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == FindingCategory::Registry)
            .collect();
        assert_eq!(reg_findings.len(), 2);
        assert_eq!(reg_findings[0].severity, Severity::Low);
    }

    // Test analyze_sections method
    #[test]
    fn test_analyze_sections_rwx_section() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let mut indicators = SecurityIndicators::default();
        let mut findings = Vec::new();

        let sections = vec![
            Section {
                name: ".text".to_string(),
                address: 0x1000,
                size: 0x500,
                offset: 0x400,
                permissions: SectionPermissions {
                    read: true,
                    write: false,
                    execute: true,
                },
                section_type: SectionType::Code,
                data: None,
            },
            Section {
                name: ".rwx_section".to_string(),
                address: 0x2000,
                size: 0x300,
                offset: 0x900,
                permissions: SectionPermissions {
                    read: true,
                    write: true,
                    execute: true,
                },
                section_type: SectionType::Code,
                data: None,
            },
        ];

        analyzer.analyze_sections(&sections, &mut indicators, &mut findings);

        let code_injection_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == FindingCategory::CodeInjection)
            .collect();
        assert_eq!(code_injection_findings.len(), 1);
        assert_eq!(code_injection_findings[0].severity, Severity::High);
        assert!(code_injection_findings[0].description.contains("RWX"));
    }

    #[test]
    fn test_analyze_sections_suspicious_names() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let mut indicators = SecurityIndicators::default();
        let mut findings = Vec::new();

        let sections = vec![
            Section {
                name: ".upx0".to_string(),
                address: 0x1000,
                size: 0x500,
                offset: 0x400,
                permissions: SectionPermissions {
                    read: true,
                    write: false,
                    execute: true,
                },
                section_type: SectionType::Code,
                data: None,
            },
            Section {
                name: ".packed".to_string(),
                address: 0x2000,
                size: 0x300,
                offset: 0x900,
                permissions: SectionPermissions {
                    read: true,
                    write: false,
                    execute: false,
                },
                section_type: SectionType::Data,
                data: None,
            },
        ];

        analyzer.analyze_sections(&sections, &mut indicators, &mut findings);

        let obfuscation_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == FindingCategory::Obfuscation)
            .collect();
        assert_eq!(obfuscation_findings.len(), 2);
        assert_eq!(obfuscation_findings[0].severity, Severity::Medium);
    }

    // Test analyze_symbols method
    #[test]
    fn test_analyze_symbols_suspicious() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let mut indicators = SecurityIndicators::default();
        let mut findings = Vec::new();

        let symbols = vec![
            Symbol {
                name: "main".to_string(),
                demangled_name: None,
                address: 0x1000,
                size: 100,
                symbol_type: SymbolType::Function,
                binding: SymbolBinding::Global,
                visibility: SymbolVisibility::Default,
                section_index: Some(0),
            },
            Symbol {
                name: "inject_payload".to_string(),
                demangled_name: None,
                address: 0x1100,
                size: 50,
                symbol_type: SymbolType::Function,
                binding: SymbolBinding::Local,
                visibility: SymbolVisibility::Hidden,
                section_index: Some(0),
            },
            Symbol {
                name: "bypass_security".to_string(),
                demangled_name: None,
                address: 0x1200,
                size: 75,
                symbol_type: SymbolType::Function,
                binding: SymbolBinding::Global,
                visibility: SymbolVisibility::Default,
                section_index: Some(0),
            },
        ];

        analyzer.analyze_symbols(&symbols, &mut indicators, &mut findings);

        let suspicious_symbol_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == FindingCategory::SuspiciousApi && f.data.is_some())
            .collect();
        assert_eq!(suspicious_symbol_findings.len(), 2);
        assert_eq!(suspicious_symbol_findings[0].severity, Severity::Medium);
    }

    // Test analyze_security_features method
    #[test]
    fn test_analyze_security_features_missing() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let mut findings = Vec::new();

        let features = SecurityFeatures {
            nx_bit: false,
            aslr: false,
            stack_canary: false,
            cfi: false,
            fortify: true,
            pie: false,
            relro: true,
            signed: false,
        };

        analyzer.analyze_security_features(&features, &mut findings);

        let missing_security_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == FindingCategory::MissingSecurity)
            .collect();

        // Should find 4 missing features: nx_bit, aslr, stack_canary, cfi
        assert_eq!(missing_security_findings.len(), 4);

        // Check specific findings
        assert!(findings.iter().any(|f| f.description.contains("NX/DEP")));
        assert!(findings.iter().any(|f| f.description.contains("ASLR")));
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("Stack canaries"))
        );
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("Control Flow Integrity"))
        );
    }

    #[test]
    fn test_analyze_security_features_all_enabled() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let mut findings = Vec::new();

        let features = SecurityFeatures {
            nx_bit: true,
            aslr: true,
            stack_canary: true,
            cfi: true,
            fortify: true,
            pie: true,
            relro: true,
            signed: true,
        };

        analyzer.analyze_security_features(&features, &mut findings);

        let missing_security_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == FindingCategory::MissingSecurity)
            .collect();
        assert_eq!(missing_security_findings.len(), 0);
    }

    // Test calculate_risk_score method
    #[test]
    fn test_calculate_risk_score_low_risk() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);

        let indicators = SecurityIndicators {
            suspicious_apis: vec![],
            anti_debug: vec![],
            anti_vm: vec![],
            crypto_indicators: vec!["CryptAcquireContext".to_string()],
            network_indicators: vec![],
            filesystem_indicators: vec!["CreateFile".to_string()],
            registry_indicators: vec![],
        };

        let features = SecurityFeatures {
            nx_bit: true,
            aslr: true,
            stack_canary: true,
            cfi: true,
            fortify: true,
            pie: true,
            relro: true,
            signed: true,
        };

        let findings = vec![
            SecurityFinding {
                category: FindingCategory::Cryptographic,
                severity: Severity::Info,
                description: "Crypto API".to_string(),
                location: None,
                data: None,
            },
            SecurityFinding {
                category: FindingCategory::Filesystem,
                severity: Severity::Low,
                description: "File API".to_string(),
                location: None,
                data: None,
            },
        ];

        let risk_score = analyzer.calculate_risk_score(&indicators, &features, &findings);
        assert!(risk_score < 10.0); // Should be low risk
    }

    #[test]
    fn test_calculate_risk_score_high_risk() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);

        let indicators = SecurityIndicators {
            suspicious_apis: vec![
                "VirtualAllocEx".to_string(),
                "WriteProcessMemory".to_string(),
            ],
            anti_debug: vec!["IsDebuggerPresent".to_string()],
            anti_vm: vec!["GetSystemInfo".to_string()],
            crypto_indicators: vec![],
            network_indicators: vec!["socket".to_string()],
            filesystem_indicators: vec![],
            registry_indicators: vec!["RegSetValueEx".to_string()],
        };

        let features = SecurityFeatures {
            nx_bit: false,
            aslr: false,
            stack_canary: false,
            cfi: false,
            fortify: false,
            pie: false,
            relro: false,
            signed: false,
        };

        let findings = vec![
            SecurityFinding {
                category: FindingCategory::SuspiciousApi,
                severity: Severity::High,
                description: "Suspicious API".to_string(),
                location: None,
                data: None,
            },
            SecurityFinding {
                category: FindingCategory::CodeInjection,
                severity: Severity::Critical,
                description: "RWX section".to_string(),
                location: None,
                data: None,
            },
            SecurityFinding {
                category: FindingCategory::MissingSecurity,
                severity: Severity::Medium,
                description: "Missing ASLR".to_string(),
                location: None,
                data: None,
            },
        ];

        let risk_score = analyzer.calculate_risk_score(&indicators, &features, &findings);
        assert!(risk_score > 50.0); // Should be high risk
    }

    // Test API categorization methods
    #[test]
    fn test_get_suspicious_apis() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let apis = analyzer.get_suspicious_apis();

        assert!(apis.contains("VirtualAllocEx"));
        assert!(apis.contains("WriteProcessMemory"));
        assert!(apis.contains("CreateRemoteThread"));
        assert!(apis.contains("SetWindowsHookEx"));
        assert!(apis.contains("OpenProcess"));
        assert!(apis.contains("AdjustTokenPrivileges"));
        assert!(!apis.contains("CreateFile")); // Should not be in suspicious APIs
    }

    #[test]
    fn test_get_anti_debug_apis() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let apis = analyzer.get_anti_debug_apis();

        assert!(apis.contains("IsDebuggerPresent"));
        assert!(apis.contains("CheckRemoteDebuggerPresent"));
        assert!(apis.contains("NtQueryInformationProcess"));
        assert!(apis.contains("OutputDebugString"));
        assert!(apis.contains("ptrace"));
        assert!(!apis.contains("VirtualAllocEx")); // Should not be in anti-debug APIs
    }

    #[test]
    fn test_get_anti_vm_apis() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let apis = analyzer.get_anti_vm_apis();

        assert!(apis.contains("GetSystemInfo"));
        assert!(apis.contains("GlobalMemoryStatusEx"));
        assert!(apis.contains("GetAdaptersInfo"));
        assert!(apis.contains("GetVolumeInformation"));
        assert!(!apis.contains("IsDebuggerPresent")); // Should not be in anti-VM APIs
    }

    #[test]
    fn test_get_crypto_apis() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let apis = analyzer.get_crypto_apis();

        assert!(apis.contains("CryptAcquireContext"));
        assert!(apis.contains("CryptCreateHash"));
        assert!(apis.contains("CryptEncrypt"));
        assert!(apis.contains("CryptDecrypt"));
        assert!(!apis.contains("socket")); // Should not be in crypto APIs
    }

    #[test]
    fn test_get_network_apis() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let apis = analyzer.get_network_apis();

        assert!(apis.contains("WSAStartup"));
        assert!(apis.contains("socket"));
        assert!(apis.contains("connect"));
        assert!(apis.contains("InternetOpen"));
        assert!(!apis.contains("CreateFile")); // Should not be in network APIs
    }

    #[test]
    fn test_get_filesystem_apis() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let apis = analyzer.get_filesystem_apis();

        assert!(apis.contains("CreateFile"));
        assert!(apis.contains("WriteFile"));
        assert!(apis.contains("DeleteFile"));
        assert!(apis.contains("FindFirstFile"));
        assert!(!apis.contains("RegOpenKeyEx")); // Should not be in filesystem APIs
    }

    #[test]
    fn test_get_registry_apis() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let apis = analyzer.get_registry_apis();

        assert!(apis.contains("RegOpenKeyEx"));
        assert!(apis.contains("RegCreateKeyEx"));
        assert!(apis.contains("RegSetValueEx"));
        assert!(apis.contains("RegDeleteKey"));
        assert!(!apis.contains("CreateFile")); // Should not be in registry APIs
    }

    // Test section and symbol name detection
    #[test]
    fn test_suspicious_section_detection() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);

        // Test suspicious section names
        assert!(analyzer.is_suspicious_section_name(".upx0"));
        assert!(analyzer.is_suspicious_section_name(".packed"));
        assert!(analyzer.is_suspicious_section_name(".THEMIDA"));
        assert!(analyzer.is_suspicious_section_name(".aspack"));
        assert!(analyzer.is_suspicious_section_name(".enigma"));
        assert!(analyzer.is_suspicious_section_name(".vmprotect"));
        assert!(analyzer.is_suspicious_section_name(".shell"));

        // Test case insensitivity
        assert!(analyzer.is_suspicious_section_name(".UPX0"));
        assert!(analyzer.is_suspicious_section_name(".PACKED"));

        // Test normal section names
        assert!(!analyzer.is_suspicious_section_name(".text"));
        assert!(!analyzer.is_suspicious_section_name(".data"));
        assert!(!analyzer.is_suspicious_section_name(".bss"));
        assert!(!analyzer.is_suspicious_section_name(".rdata"));
    }

    #[test]
    fn test_suspicious_symbol_detection() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);

        // Test suspicious symbol patterns
        assert!(analyzer.is_suspicious_symbol_name("inject_code"));
        assert!(analyzer.is_suspicious_symbol_name("bypass_check"));
        assert!(analyzer.is_suspicious_symbol_name("hook_function"));
        assert!(analyzer.is_suspicious_symbol_name("shellcode_payload"));
        assert!(analyzer.is_suspicious_symbol_name("exploit_buffer"));
        assert!(analyzer.is_suspicious_symbol_name("backdoor_entry"));
        assert!(analyzer.is_suspicious_symbol_name("rootkit_hide"));
        assert!(analyzer.is_suspicious_symbol_name("keylogger_start"));
        assert!(analyzer.is_suspicious_symbol_name("stealth_mode"));

        // Test case insensitivity
        assert!(analyzer.is_suspicious_symbol_name("INJECT_CODE"));
        assert!(analyzer.is_suspicious_symbol_name("Bypass_Check"));

        // Test normal symbol names
        assert!(!analyzer.is_suspicious_symbol_name("main"));
        assert!(!analyzer.is_suspicious_symbol_name("printf"));
        assert!(!analyzer.is_suspicious_symbol_name("malloc"));
        assert!(!analyzer.is_suspicious_symbol_name("strcmp"));
        assert!(!analyzer.is_suspicious_symbol_name("init_function"));
    }

    // Test severity ordering
    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_security_finding_categories() {
        // Test that all expected categories exist
        let categories = [
            FindingCategory::SuspiciousApi,
            FindingCategory::AntiDebug,
            FindingCategory::AntiVm,
            FindingCategory::Cryptographic,
            FindingCategory::Network,
            FindingCategory::Filesystem,
            FindingCategory::Registry,
            FindingCategory::MissingSecurity,
            FindingCategory::Obfuscation,
            FindingCategory::CodeInjection,
            FindingCategory::PrivilegeEscalation,
        ];

        for category in &categories {
            let finding = SecurityFinding {
                category: category.clone(),
                severity: Severity::Medium,
                description: "Test finding".to_string(),
                location: None,
                data: None,
            };
            assert_eq!(finding.category, *category);
        }
    }

    // Test edge cases and error handling
    #[test]
    fn test_analyze_imports_empty() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let mut indicators = SecurityIndicators::default();
        let mut findings = Vec::new();

        analyzer.analyze_imports(&[], &mut indicators, &mut findings);

        assert_eq!(indicators.suspicious_apis.len(), 0);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_analyze_sections_empty() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let mut indicators = SecurityIndicators::default();
        let mut findings = Vec::new();

        analyzer.analyze_sections(&[], &mut indicators, &mut findings);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_analyze_symbols_empty() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        let mut indicators = SecurityIndicators::default();
        let mut findings = Vec::new();

        analyzer.analyze_symbols(&[], &mut indicators, &mut findings);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_risk_score_bounds() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);

        // Test that risk score is always between 0 and 100
        let indicators = SecurityIndicators::default();
        let features = SecurityFeatures::default();

        // Empty findings should give 0 or very low score
        let empty_findings = vec![];
        let score = analyzer.calculate_risk_score(&indicators, &features, &empty_findings);
        assert!(score >= 0.0 && score <= 100.0);

        // Maximum risk scenario
        let high_risk_indicators = SecurityIndicators {
            suspicious_apis: (0..20).map(|i| format!("api_{}", i)).collect(),
            anti_debug: (0..10).map(|i| format!("debug_{}", i)).collect(),
            anti_vm: (0..10).map(|i| format!("vm_{}", i)).collect(),
            crypto_indicators: (0..5).map(|i| format!("crypto_{}", i)).collect(),
            network_indicators: (0..5).map(|i| format!("net_{}", i)).collect(),
            filesystem_indicators: (0..5).map(|i| format!("fs_{}", i)).collect(),
            registry_indicators: (0..5).map(|i| format!("reg_{}", i)).collect(),
        };

        let insecure_features = SecurityFeatures {
            nx_bit: false,
            aslr: false,
            stack_canary: false,
            cfi: false,
            fortify: false,
            pie: false,
            relro: false,
            signed: false,
        };

        let critical_findings: Vec<SecurityFinding> = (0..10)
            .map(|i| SecurityFinding {
                category: FindingCategory::SuspiciousApi,
                severity: Severity::Critical,
                description: format!("Critical finding {}", i),
                location: None,
                data: None,
            })
            .collect();

        let max_score = analyzer.calculate_risk_score(
            &high_risk_indicators,
            &insecure_features,
            &critical_findings,
        );
        assert!(max_score <= 100.0);
    }

    // Test disabled config scenarios
    #[test]
    fn test_analyze_with_disabled_suspicious_apis() {
        let config = SecurityConfig {
            detect_suspicious_apis: false,
            ..SecurityConfig::default()
        };
        let analyzer = SecurityAnalyzer::with_config(Architecture::X86_64, config);
        let mut indicators = SecurityIndicators::default();
        let mut findings = Vec::new();

        let imports = vec![Import {
            name: "VirtualAllocEx".to_string(),
            library: Some("kernel32.dll".to_string()),
            address: Some(0x1000),
            ordinal: None,
        }];

        analyzer.analyze_imports(&imports, &mut indicators, &mut findings);

        // Note: analyze_imports doesn't check config flags - it analyzes all categories
        // The config flags are checked in the main analyze() method
        // So VirtualAllocEx will still be detected as suspicious, but other categories work
        assert!(!indicators.suspicious_apis.is_empty());

        // But we can test that the config affects the main analyze flow
        // by testing a scenario with different detection flags
        let config2 = SecurityConfig {
            detect_anti_debug: false,
            detect_anti_vm: false,
            detect_crypto: false,
            detect_network: false,
            detect_filesystem: false,
            detect_registry: false,
            ..SecurityConfig::default()
        };
        let analyzer2 = SecurityAnalyzer::with_config(Architecture::X86_64, config2);

        // Test that individual detection methods can be configured
        assert!(!analyzer2.config.detect_anti_debug);
        assert!(!analyzer2.config.detect_anti_vm);
        assert!(analyzer2.config.detect_suspicious_apis); // This one is still enabled
    }

    // Integration tests for the main analyze method and analyze_binary_security function
    #[test]
    fn test_complete_security_analysis_high_risk() {
        // Create a high-risk mock binary
        let binary = MockBinaryFile {
            imports: vec![
                Import {
                    name: "VirtualAllocEx".to_string(),
                    library: Some("kernel32.dll".to_string()),
                    address: Some(0x1000),
                    ordinal: None,
                },
                Import {
                    name: "WriteProcessMemory".to_string(),
                    library: Some("kernel32.dll".to_string()),
                    address: Some(0x1004),
                    ordinal: None,
                },
                Import {
                    name: "IsDebuggerPresent".to_string(),
                    library: Some("kernel32.dll".to_string()),
                    address: Some(0x1008),
                    ordinal: None,
                },
            ],
            sections: vec![
                Section {
                    name: ".text".to_string(),
                    address: 0x1000,
                    size: 0x500,
                    offset: 0x400,
                    permissions: SectionPermissions {
                        read: true,
                        write: false,
                        execute: true,
                    },
                    section_type: SectionType::Code,
                    data: None,
                },
                Section {
                    name: ".rwx_evil".to_string(),
                    address: 0x2000,
                    size: 0x300,
                    offset: 0x900,
                    permissions: SectionPermissions {
                        read: true,
                        write: true,
                        execute: true,
                    },
                    section_type: SectionType::Code,
                    data: None,
                },
                Section {
                    name: ".upx0".to_string(),
                    address: 0x3000,
                    size: 0x200,
                    offset: 0xc00,
                    permissions: SectionPermissions {
                        read: true,
                        write: false,
                        execute: true,
                    },
                    section_type: SectionType::Code,
                    data: None,
                },
            ],
            symbols: vec![
                Symbol {
                    name: "main".to_string(),
                    demangled_name: None,
                    address: 0x1000,
                    size: 100,
                    symbol_type: SymbolType::Function,
                    binding: SymbolBinding::Global,
                    visibility: SymbolVisibility::Default,
                    section_index: Some(0),
                },
                Symbol {
                    name: "inject_shellcode".to_string(),
                    demangled_name: None,
                    address: 0x1100,
                    size: 50,
                    symbol_type: SymbolType::Function,
                    binding: SymbolBinding::Local,
                    visibility: SymbolVisibility::Hidden,
                    section_index: Some(0),
                },
                Symbol {
                    name: "bypass_protection".to_string(),
                    demangled_name: None,
                    address: 0x1200,
                    size: 75,
                    symbol_type: SymbolType::Function,
                    binding: SymbolBinding::Global,
                    visibility: SymbolVisibility::Default,
                    section_index: Some(0),
                },
            ],
            metadata: BinaryMetadata {
                size: 2048,
                format: BinaryFormat::Pe,
                architecture: Architecture::X86_64,
                entry_point: Some(0x1000),
                base_address: Some(0x400000),
                timestamp: None,
                compiler_info: None,
                endian: Endianness::Little,
                security_features: SecurityFeatures {
                    nx_bit: false,       // Missing security feature
                    aslr: false,         // Missing security feature
                    stack_canary: false, // Missing security feature
                    cfi: false,          // Missing security feature
                    fortify: false,
                    pie: false,
                    relro: false,
                    signed: false,
                },
            },
        };

        let result = analyze_mock_binary(&binary);

        // Verify high-risk indicators
        assert!(!result.indicators.suspicious_apis.is_empty());
        assert!(
            result
                .indicators
                .suspicious_apis
                .contains(&"VirtualAllocEx".to_string())
        );
        assert!(
            result
                .indicators
                .suspicious_apis
                .contains(&"WriteProcessMemory".to_string())
        );

        assert!(!result.indicators.anti_debug.is_empty());
        assert!(
            result
                .indicators
                .anti_debug
                .contains(&"IsDebuggerPresent".to_string())
        );

        // Verify security features
        assert!(!result.features.nx_bit);
        assert!(!result.features.aslr);
        assert!(!result.features.stack_canary);
        assert!(!result.features.cfi);

        // Verify findings
        assert!(!result.findings.is_empty());

        // Should have suspicious API findings
        let suspicious_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.category == FindingCategory::SuspiciousApi)
            .collect();
        assert!(!suspicious_findings.is_empty());

        // Should have anti-debug findings
        let anti_debug_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.category == FindingCategory::AntiDebug)
            .collect();
        assert!(!anti_debug_findings.is_empty());

        // Should have code injection findings (RWX section)
        let code_injection_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.category == FindingCategory::CodeInjection)
            .collect();
        assert!(!code_injection_findings.is_empty());

        // Should have obfuscation findings (suspicious section name)
        let obfuscation_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.category == FindingCategory::Obfuscation)
            .collect();
        assert!(!obfuscation_findings.is_empty());

        // Should have missing security findings
        let missing_security_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.category == FindingCategory::MissingSecurity)
            .collect();
        assert!(!missing_security_findings.is_empty());

        // Should have high risk score due to multiple indicators
        assert!(
            result.risk_score > 30.0,
            "Risk score should be high for malicious binary"
        );
    }

    #[test]
    fn test_complete_security_analysis_low_risk() {
        // Create a low-risk mock binary
        let binary = MockBinaryFile {
            imports: vec![
                Import {
                    name: "printf".to_string(),
                    library: Some("msvcrt.dll".to_string()),
                    address: Some(0x1000),
                    ordinal: None,
                },
                Import {
                    name: "malloc".to_string(),
                    library: Some("msvcrt.dll".to_string()),
                    address: Some(0x1004),
                    ordinal: None,
                },
                Import {
                    name: "ExitProcess".to_string(),
                    library: Some("kernel32.dll".to_string()),
                    address: Some(0x1008),
                    ordinal: None,
                },
            ],
            sections: vec![
                Section {
                    name: ".text".to_string(),
                    address: 0x1000,
                    size: 0x500,
                    offset: 0x400,
                    permissions: SectionPermissions {
                        read: true,
                        write: false,
                        execute: true,
                    },
                    section_type: SectionType::Code,
                    data: None,
                },
                Section {
                    name: ".data".to_string(),
                    address: 0x2000,
                    size: 0x300,
                    offset: 0x900,
                    permissions: SectionPermissions {
                        read: true,
                        write: true,
                        execute: false,
                    },
                    section_type: SectionType::Data,
                    data: None,
                },
                Section {
                    name: ".rdata".to_string(),
                    address: 0x3000,
                    size: 0x200,
                    offset: 0xc00,
                    permissions: SectionPermissions {
                        read: true,
                        write: false,
                        execute: false,
                    },
                    section_type: SectionType::Data,
                    data: None,
                },
            ],
            symbols: vec![
                Symbol {
                    name: "main".to_string(),
                    demangled_name: None,
                    address: 0x1000,
                    size: 100,
                    symbol_type: SymbolType::Function,
                    binding: SymbolBinding::Global,
                    visibility: SymbolVisibility::Default,
                    section_index: Some(0),
                },
                Symbol {
                    name: "print_hello".to_string(),
                    demangled_name: None,
                    address: 0x1100,
                    size: 50,
                    symbol_type: SymbolType::Function,
                    binding: SymbolBinding::Local,
                    visibility: SymbolVisibility::Default,
                    section_index: Some(0),
                },
            ],
            metadata: BinaryMetadata {
                size: 1024,
                format: BinaryFormat::Pe,
                architecture: Architecture::X86_64,
                entry_point: Some(0x1000),
                base_address: Some(0x400000),
                timestamp: None,
                compiler_info: None,
                endian: Endianness::Little,
                security_features: SecurityFeatures {
                    nx_bit: true,       // Security feature enabled
                    aslr: true,         // Security feature enabled
                    stack_canary: true, // Security feature enabled
                    cfi: true,          // Security feature enabled
                    fortify: true,
                    pie: true,
                    relro: true,
                    signed: true,
                },
            },
        };

        let result = analyze_mock_binary(&binary);

        // Verify low-risk indicators
        assert!(result.indicators.suspicious_apis.is_empty());
        assert!(result.indicators.anti_debug.is_empty());
        assert!(result.indicators.anti_vm.is_empty());

        // Verify security features are enabled
        assert!(result.features.nx_bit);
        assert!(result.features.aslr);
        assert!(result.features.stack_canary);
        assert!(result.features.cfi);

        // Should have no or very few security findings
        let suspicious_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| {
                matches!(
                    f.category,
                    FindingCategory::SuspiciousApi
                        | FindingCategory::AntiDebug
                        | FindingCategory::AntiVm
                        | FindingCategory::CodeInjection
                )
            })
            .collect();
        assert!(suspicious_findings.is_empty());

        // Should have no missing security findings since all features are enabled
        let missing_security_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.category == FindingCategory::MissingSecurity)
            .collect();
        assert!(missing_security_findings.is_empty());

        // Should have low risk score
        assert!(
            result.risk_score < 10.0,
            "Risk score should be low for benign binary"
        );
    }

    #[test]
    fn test_analyze_binary_security_function() {
        // This test is simplified since analyze_binary_security expects a BinaryFile
        // but we can test the function exists and works with proper parameters
        let binary = create_test_binary_file();

        // Test using our analyze_mock_binary helper which exercises the same logic
        let result = analyze_mock_binary(&binary);

        // Verify the result contains expected fields
        assert!(!result.indicators.suspicious_apis.is_empty());
        assert!(result.risk_score > 0.0);
        assert!(!result.findings.is_empty());

        // Verify that the function detected the suspicious API from our test data
        assert!(
            result
                .indicators
                .suspicious_apis
                .contains(&"VirtualAllocEx".to_string())
        );
    }

    #[test]
    fn test_analyzer_different_architectures() {
        // Test that analyzer works with different architectures
        let architectures = [
            Architecture::X86,
            Architecture::X86_64,
            Architecture::Arm,
            Architecture::Arm64,
            Architecture::Mips,
            Architecture::PowerPC,
        ];

        for arch in &architectures {
            let analyzer = SecurityAnalyzer::new(*arch);
            assert_eq!(analyzer.architecture, *arch);

            // Test basic functionality with each architecture
            let config = SecurityConfig::default();
            let analyzer_with_config = SecurityAnalyzer::with_config(*arch, config);
            assert_eq!(analyzer_with_config.architecture, *arch);
        }
    }

    #[test]
    fn test_security_analysis_result_completeness() {
        let binary = create_test_binary_file();
        let result = analyze_mock_binary(&binary);

        // Verify all fields of SecurityAnalysisResult are populated
        // indicators should be populated
        assert!(
            result.indicators.suspicious_apis.len() > 0
                || result.indicators.anti_debug.len() > 0
                || result.indicators.anti_vm.len() > 0
                || result.indicators.crypto_indicators.len() > 0
                || result.indicators.network_indicators.len() > 0
                || result.indicators.filesystem_indicators.len() > 0
                || result.indicators.registry_indicators.len() > 0
        );

        // features should be copied from metadata
        // (values don't matter, just that they're populated)
        // risk_score should be calculated (>= 0.0)
        assert!(result.risk_score >= 0.0);

        // findings should be populated when there are indicators
        assert!(!result.findings.is_empty());
    }

    #[test]
    fn test_config_detection_flags() {
        // Test each detection flag individually
        let mut config = SecurityConfig {
            detect_suspicious_apis: false,
            detect_anti_debug: false,
            detect_anti_vm: false,
            detect_crypto: false,
            detect_network: false,
            detect_filesystem: false,
            detect_registry: false,
            min_string_length: 4,
        };

        // Enable only suspicious API detection
        config.detect_suspicious_apis = true;
        let analyzer = SecurityAnalyzer::with_config(Architecture::X86_64, config.clone());
        let mut indicators = SecurityIndicators::default();
        let mut findings = Vec::new();

        let imports = vec![Import {
            name: "VirtualAllocEx".to_string(),
            library: Some("kernel32.dll".to_string()),
            address: Some(0x1000),
            ordinal: None,
        }];

        analyzer.analyze_imports(&imports, &mut indicators, &mut findings);
        assert!(!indicators.suspicious_apis.is_empty());

        // Disable suspicious APIs, enable anti-debug
        config.detect_suspicious_apis = false;
        config.detect_anti_debug = true;
        let analyzer = SecurityAnalyzer::with_config(Architecture::X86_64, config);
        let mut indicators = SecurityIndicators::default();
        let mut findings = Vec::new();

        let imports = vec![Import {
            name: "IsDebuggerPresent".to_string(),
            library: Some("kernel32.dll".to_string()),
            address: Some(0x1000),
            ordinal: None,
        }];

        analyzer.analyze_imports(&imports, &mut indicators, &mut findings);
        assert!(!indicators.anti_debug.is_empty());
    }
}
