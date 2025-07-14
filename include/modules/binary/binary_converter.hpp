#pragma once

#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <chrono>
#include <cstdint>

namespace converter::modules::binary {

enum class BinaryFormat {
    PE, ELF, MACHO, ARCHIVE, SHELLCODE, RAW, UNKNOWN
};

enum class Architecture {
    X86, X64, ARM, ARM64, MIPS, RISC_V, UNKNOWN
};

enum class VulnerabilityType {
    BUFFER_OVERFLOW, FORMAT_STRING, INTEGER_OVERFLOW, USE_AFTER_FREE, INJECTION, UNKNOWN
};

enum class VulnerabilitySeverity {
    LOW, MEDIUM, HIGH, CRITICAL
};

enum class AntiAnalysisType {
    DEBUGGER_DETECTION, VM_DETECTION, TIMING_CHECK, OBFUSCATION, PACKING
};

enum class ShellcodeType {
    REVERSE_SHELL, BIND_SHELL, METERPRETER, CUSTOM
};

enum class EncoderType {
    XOR, ALPHA_MIXED, SHIKATA_GA_NAI
};

struct BinarySection {
    char name[9];
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_offset;
    uint32_t raw_size;
    uint32_t characteristics;
    bool is_executable;
    bool is_readable;
    bool is_writable;
    double entropy;
};

struct ImportedLibrary {
    std::string name;
    std::vector<std::string> functions;
};

struct SuspiciousString {
    std::string content;
    std::string pattern;
    RiskLevel risk_level;
};

enum class RiskLevel {
    LOW, MEDIUM, HIGH, CRITICAL
};

struct ThreatIndicator {
    std::string rule_name;
    double confidence;
    std::string description;
};

struct Vulnerability {
    VulnerabilityType type;
    VulnerabilitySeverity severity;
    std::string description;
    double confidence;
    uint64_t address;
};

struct BinaryMetadata {
    uint64_t compilation_timestamp;
    std::string compiler_version;
    bool debug_info;
    bool code_signing;
    uint64_t entry_point;
    uint64_t base_address;
};

struct ProcessedBinary {
    std::vector<uint8_t> data;
    size_t size;
    std::string hash;
    BinaryFormat format;
    Architecture architecture;
    BinaryMetadata metadata;
    double entropy;
    bool is_packed;
    std::string packer_type;
    bool packer_detected;
    double packer_confidence;
    size_t unpacked_size;
    bool malware_detected;
    std::string malware_signature;
    double threat_score;
    std::vector<ThreatIndicator> threat_indicators;
    std::vector<std::string> strings;
    std::vector<SuspiciousString> suspicious_strings;
    std::vector<ImportedLibrary> imported_libraries;
    std::vector<std::string> exported_functions;
    std::vector<BinarySection> sections;
    std::vector<Vulnerability> vulnerabilities;
    bool has_suspicious_imports;
    bool has_anti_debug;
    bool has_anti_vm;
    std::vector<std::string> suspicious_api_calls;
};

struct Instruction {
    uint64_t address;
    std::string mnemonic;
    std::string operands;
    std::vector<uint8_t> bytes;
    size_t size;
    bool is_jump;
    bool is_call;
    bool is_ret;
    bool is_nop;
    bool reads_memory;
    bool writes_memory;
    size_t target_index;
};

enum class EdgeType {
    JUMP, CALL, FALLTHROUGH
};

struct ControlFlowEdge {
    size_t from;
    size_t to;
    EdgeType type;
};

struct AntiAnalysisTechnique {
    AntiAnalysisType type;
    uint64_t address;
    std::string description;
};

struct DisassemblyResult {
    std::vector<Instruction> instructions;
    std::vector<ControlFlowEdge> control_flow_edges;
    std::vector<AntiAnalysisTechnique> anti_analysis_techniques;
};

struct ShellcodeConfig {
    ShellcodeType type;
    std::string target_ip;
    uint16_t target_port;
    std::string assembly_code;
    bool encode;
    EncoderType encoder;
    bool obfuscate;
};

struct EmulatedInstruction {
    uint64_t address;
    uint32_t size;
};

struct MemoryAccess {
    uint64_t address;
    int size;
    int64_t value;
    bool is_read;
    bool is_write;
};

struct EmulationResult {
    bool success;
    std::vector<EmulatedInstruction> executed_instructions;
    std::vector<MemoryAccess> memory_accesses;
};

struct BinaryMetrics {
    uint64_t binaries_processed;
    uint64_t instructions_analyzed;
    uint64_t vulnerabilities_found;
    double threat_score_average;
    double throughput;
};

class BinaryConverter {
public:
    BinaryConverter();
    ~BinaryConverter();

    ProcessedBinary analyze_binary(const std::vector<uint8_t>& binary_data);
    
    DisassemblyResult disassemble_binary(const std::vector<uint8_t>& data, 
                                        uint64_t start_address = 0x400000, 
                                        size_t max_instructions = 1000);
    
    std::vector<uint8_t> generate_shellcode(const ShellcodeConfig& config);
    
    EmulationResult emulate_code(const std::vector<uint8_t>& code, 
                                uint64_t start_address = 0x400000, 
                                size_t max_instructions = 1000);
    
    BinaryMetrics get_metrics() const;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

} 