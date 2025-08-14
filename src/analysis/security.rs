//! Security analysis for binary files
//!
//! This module provides comprehensive security analysis capabilities for binary files,
//! including vulnerability detection, malware indicators, and security feature analysis.

use crate::{
    types::{Architecture, Import, Section, SecurityFeatures, SecurityIndicators, Symbol},
    BinaryFile, Result,
};
use std::collections::HashSet;

/// Security analyzer for binary files
pub struct SecurityAnalyzer {
    /// Architecture being analyzed
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

    #[test]
    fn test_analyzer_creation() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        assert_eq!(analyzer.architecture, Architecture::X86_64);
    }

    #[test]
    fn test_security_config_default() {
        let config = SecurityConfig::default();
        assert!(config.detect_suspicious_apis);
        assert!(config.detect_anti_debug);
        assert!(config.detect_anti_vm);
        assert_eq!(config.min_string_length, 4);
    }

    #[test]
    fn test_suspicious_section_detection() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        assert!(analyzer.is_suspicious_section_name(".upx0"));
        assert!(analyzer.is_suspicious_section_name(".packed"));
        assert!(!analyzer.is_suspicious_section_name(".text"));
    }

    #[test]
    fn test_suspicious_symbol_detection() {
        let analyzer = SecurityAnalyzer::new(Architecture::X86_64);
        assert!(analyzer.is_suspicious_symbol_name("inject_code"));
        assert!(analyzer.is_suspicious_symbol_name("bypass_check"));
        assert!(!analyzer.is_suspicious_symbol_name("main"));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }
}
