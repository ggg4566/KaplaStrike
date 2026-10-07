#!/bin/bash

################################################################################
# EXE to Shellcode Converter
# 
# Usage: ./build_exe_shellcode.sh <exe_path> [command_line_args]
# 
# Example:
#   ./build_exe_shellcode.sh /path/to/app.exe "arg1 arg2 arg3"
#   ./build_exe_shellcode.sh C:\\tools\\test.exe "--verbose --output=result.txt"
# 
# Output:
#   bin/shellcode.bin  - Position-independent shellcode
#   bin/shellcode.hex  - Hex-encoded version for easy copy-paste
#
# Requirements:
#   - MinGW x86_64 toolchain
#   - Crystal Palace link tool (in repo root)
#   - Valid PE console EXE as input
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
LOADER_SPEC="spec/loader.spec"
LINK_TOOL="./link"
MAKE_CMD="make"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"
OUTPUT_DIR="${OUTPUT_DIR:-$BIN_DIR}"

# ────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ────────────────────────────────────────────────────────────────────────────

log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

usage() {
    echo "Usage: $0 <exe_path> [command_line_args]"
    echo ""
    echo "Examples:"
    echo "  $0 ./test.exe"
    echo "  $0 ./test.exe 'arg1 arg2 arg3'"
    echo "  $0 C:\\Windows\\System32\\cmd.exe '/c whoami'"
    exit 1
}

validate_pe_file() {
    local exe_file="$1"
    
    if [[ ! -f "$exe_file" ]]; then
        log_error "EXE file not found: $exe_file"
        exit 1
    fi
    
    # Check if it's a PE file (MZ header)
    if ! head -c 2 "$exe_file" | grep -q "MZ"; then
        log_error "Not a valid PE file: $exe_file"
        exit 1
    fi
    
    log_success "Valid PE file: $exe_file"
}

check_dependencies() {
    if [[ ! -f "$LINK_TOOL" ]]; then
        log_error "link tool not found at: $LINK_TOOL"
        log_info "This is the Crystal Palace PE linking tool from the repo root"
        exit 1
    fi
    
    if [[ ! -f "$LOADER_SPEC" ]]; then
        log_error "Loader spec not found at: $LOADER_SPEC"
        exit 1
    fi
    
    if ! command -v $MAKE_CMD &> /dev/null; then
        log_error "make not found in PATH"
        exit 1
    fi
}

compile_loader() {
    log_info "Compiling EXE loader..."
    cd "$SCRIPT_DIR"
    
    if ! $MAKE_CMD exe > /dev/null 2>&1; then
        log_error "Compilation failed. Run 'make exe' manually for details"
        exit 1
    fi
    
    log_success "Loader compiled successfully"
}

embed_exe_and_generate_shellcode() {
    local exe_file="$1"
    local cmdline="$2"
    local output_file="$3"
    
    log_info "Embedding EXE and generating shellcode..."
    log_info "  Input EXE: $exe_file"
    log_info "  Command line: '${cmdline:-<empty>}'"
    log_info "  Output: $output_file"
    
    # Generate the link spec with command line embedded
    # The link tool will:
    # 1. Read the loader.x64.o (compiled from loader.c)
    # 2. Embed the EXE binary into the cobalt_dll section
    # 3. Generate random XOR mask into cobalt_mask section
    # 4. Output position-independent shellcode blob
    
    if ! "$LINK_TOOL" "$LOADER_SPEC" "$exe_file" "$output_file" 2>/dev/null; then
        log_error "Failed to generate shellcode. Check that:"
        log_error "  1. EXE file is valid: $exe_file"
        log_error "  2. link tool is configured correctly"
        log_error "  3. Loader spec exists: $LOADER_SPEC"
        exit 1
    fi
    
    log_success "Shellcode generated: $output_file"
}

generate_hex_output() {
    local bin_file="$1"
    local hex_file="${bin_file%.bin}.hex"
    
    log_info "Generating hex-encoded output..."
    
    if command -v xxd &> /dev/null; then
        xxd -p "$bin_file" | tr -d '\n' > "$hex_file"
    elif command -v hexdump &> /dev/null; then
        hexdump -v -e '/1 "%02x"' "$bin_file" > "$hex_file"
    else
        log_warn "hexdump/xxd not found - skipping hex generation"
        return
    fi
    
    log_success "Hex output: $hex_file"
}

get_file_size() {
    if [[ -f "$1" ]]; then
        wc -c < "$1" | xargs
    fi
}

# ────────────────────────────────────────────────────────────────────────────
# Main Script
# ────────────────────────────────────────────────────────────────────────────

main() {
    # Validate arguments
    if [[ $# -lt 1 ]]; then
        usage
    fi
    
    local exe_path="$1"
    local cmdline="${2:-}"
    
    # Convert to absolute path
    exe_path="$(cd "$(dirname "$exe_path")" && pwd)/$(basename "$exe_path")"
    
    log_info "════════════════════════════════════════════════════════════"
    log_info "EXE to Shellcode Converter (Console Edition)"
    log_info "════════════════════════════════════════════════════════════"
    
    # Validate input
    validate_pe_file "$exe_path"
    
    # Check dependencies
    log_info "Checking dependencies..."
    check_dependencies
    log_success "All dependencies found"
    
    # Compile loader
    compile_loader
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Generate output filename
    local exe_basename=$(basename "$exe_path" .exe)
    local output_file="$OUTPUT_DIR/${exe_basename}_shellcode.bin"
    
    # Embed EXE and generate shellcode
    # Note: cmdline is passed but currently handled via EXE_CMDLINE macro at compile time
    # For runtime cmdline support, would need additional integration with link tool
    embed_exe_and_generate_shellcode "$exe_path" "$cmdline" "$output_file"
    
    # Generate hex output
    generate_hex_output "$output_file"
    
    # Print summary
    echo ""
    log_success "════════════════════════════════════════════════════════════"
    log_success "Shellcode generation complete!"
    log_info "Output file: $output_file"
    log_info "Size: $(get_file_size "$output_file") bytes"
    log_info ""
    log_info "Usage:"
    log_info "  - Execute with any shellcode runner"
    log_info "  - Ensure target system has WsmSvc.dll (Windows default)"
    log_info "  - x64 Windows only"
    log_success "════════════════════════════════════════════════════════════"
}

main "$@"
