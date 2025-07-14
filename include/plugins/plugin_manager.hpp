#pragma once

#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <cstdint>
#include <thread>
#include <filesystem>

namespace converter::plugins {

constexpr uint32_t PLUGIN_API_VERSION = 1;
constexpr uint32_t CONVERTER_VERSION = 1;

enum class PluginStatus {
    UNKNOWN, LOADING, LOADED, RUNNING, IDLE, UNLOADING, UNLOADED, ERROR, CRASHED
};

struct PluginDependency {
    std::string plugin_id;
    std::string version_requirement;
    bool optional;
};

struct PluginManifest {
    std::string plugin_id;
    std::string name;
    std::string version;
    std::string description;
    std::string author;
    std::string license;
    uint32_t api_version;
    uint32_t min_converter_version;
    std::vector<std::string> capabilities;
    std::vector<PluginDependency> dependencies;
    std::string file_path;
    size_t file_size;
    std::filesystem::file_time_type modification_time;
    std::vector<uint8_t> signature;
    std::string checksum;
};

struct SecurityPolicy {
    std::unordered_set<std::string> allowed_permissions;
    std::unordered_set<std::string> blocked_syscalls;
    size_t max_memory_usage;
    std::chrono::seconds max_execution_time;
    bool allow_network_access;
    bool allow_file_system_access;
    std::vector<std::string> allowed_directories;
};

struct PluginConfig {
    std::vector<std::string> plugin_directories;
    SecurityPolicy security_policy;
    std::vector<uint8_t> trusted_public_key;
    bool enable_security;
    bool enable_hot_reload;
    bool enable_sandboxing;
    size_t max_concurrent_plugins;
    std::chrono::seconds plugin_timeout;
};

struct PluginSandbox {
    std::thread monitor_thread;
    pid_t process_id;
    std::string jail_directory;
    std::unordered_map<std::string, std::string> environment_variables;
    std::vector<int> allowed_file_descriptors;
};

struct PluginExecutionContext {
    std::string request_id;
    std::chrono::milliseconds max_execution_time;
    size_t max_memory_usage;
    std::unordered_set<std::string> required_permissions;
    std::unordered_map<std::string, std::string> environment;
    bool enable_profiling;
};

struct PluginExecutionResult {
    std::string instance_id;
    std::string function_name;
    bool success;
    std::vector<uint8_t> output_data;
    std::string error_message;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    std::chrono::milliseconds execution_time;
    size_t memory_used;
    std::unordered_map<std::string, std::string> profiling_data;
};

struct PluginInfo {
    std::string plugin_id;
    std::string name;
    std::string version;
    std::string description;
    std::vector<std::string> capabilities;
    bool is_available;
    bool is_loaded;
    PluginStatus status;
    std::chrono::steady_clock::time_point load_time;
    size_t reference_count;
    std::string error_message;
};

struct PluginMetrics {
    size_t total_plugins;
    size_t loaded_plugins;
    size_t active_plugins;
    size_t idle_plugins;
    size_t crashed_plugins;
    uint64_t function_calls_total;
    uint64_t function_calls_successful;
    uint64_t function_calls_failed;
    std::chrono::milliseconds average_execution_time;
    size_t plugins_loaded;
    size_t plugins_unloaded;
    size_t hot_reloads;
    size_t security_violations;
};

struct PluginContext {
    uint32_t api_version;
    bool security_enabled;
    bool sandbox_enabled;
    std::string converter_version;
    std::unordered_map<std::string, std::string> configuration;
};

class PluginInterface {
public:
    virtual ~PluginInterface() = default;
    
    virtual bool initialize(const PluginContext& context) = 0;
    virtual void shutdown() = 0;
    
    virtual std::vector<uint8_t> execute_function(const std::string& function_name,
                                                 const std::vector<uint8_t>& input_data,
                                                 const PluginExecutionContext& context) = 0;
    
    virtual std::vector<std::string> get_supported_functions() const = 0;
    virtual std::string get_function_description(const std::string& function_name) const = 0;
};

class PluginManager {
public:
    PluginManager();
    ~PluginManager();

    void initialize(const PluginConfig& config);
    
    std::string load_plugin(const std::string& plugin_id);
    void unload_plugin(const std::string& instance_id);
    
    PluginExecutionResult execute_plugin_function(const std::string& instance_id, 
                                                 const std::string& function_name, 
                                                 const std::vector<uint8_t>& input_data,
                                                 const PluginExecutionContext& context = {});
    
    std::vector<std::string> get_plugins_by_capability(const std::string& capability);
    
    PluginInfo get_plugin_info(const std::string& plugin_id);
    std::vector<PluginInfo> list_all_plugins();
    
    void reload_plugin(const std::string& plugin_id);
    
    PluginMetrics get_metrics() const;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

extern "C" {
    PluginManifest* get_plugin_manifest();
    PluginInterface* create_plugin();
    void destroy_plugin(PluginInterface* plugin);
}

} 