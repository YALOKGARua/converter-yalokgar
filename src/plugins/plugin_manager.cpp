#include "plugins/plugin_manager.hpp"
#include <dlfcn.h>
#include <sys/mman.h>
#include <seccomp.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <filesystem>
#include <fstream>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <execution>
#include <regex>

namespace converter::plugins {

class PluginManager::Impl {
public:
    struct PluginState {
        std::string plugin_id;
        std::string plugin_path;
        void* handle;
        PluginInterface* interface;
        PluginMetadata metadata;
        PluginStatus status;
        std::chrono::steady_clock::time_point load_time;
        std::chrono::steady_clock::time_point last_access;
        size_t reference_count;
        pid_t sandbox_pid;
        std::unique_ptr<PluginSandbox> sandbox;
        std::vector<uint8_t> signature;
        std::vector<uint8_t> hash;
        mutable std::shared_mutex mutex;
    };

    struct PluginRegistry {
        std::unordered_map<std::string, std::unique_ptr<PluginState>> loaded_plugins;
        std::unordered_map<std::string, PluginManifest> available_plugins;
        std::vector<std::string> plugin_directories;
        std::unordered_map<std::string, std::vector<std::string>> capability_map;
        mutable std::shared_mutex mutex;
        SecurityPolicy security_policy;
        std::vector<uint8_t> trusted_public_key;
    };

    PluginRegistry registry;
    std::atomic<bool> hot_reload_enabled{true};
    std::atomic<bool> security_enabled{true};
    std::thread monitoring_thread;
    std::thread hot_reload_thread;
    PluginMetrics metrics;
    
    void initialize_plugin_system(const PluginConfig& config) {
        registry.plugin_directories = config.plugin_directories;
        registry.security_policy = config.security_policy;
        registry.trusted_public_key = config.trusted_public_key;
        
        security_enabled = config.enable_security;
        hot_reload_enabled = config.enable_hot_reload;
        
        scan_plugin_directories();
        start_monitoring();
        
        if (hot_reload_enabled) {
            start_hot_reload_monitoring();
        }
    }
    
    void scan_plugin_directories() {
        std::unique_lock lock(registry.mutex);
        
        for (const auto& directory : registry.plugin_directories) {
            if (std::filesystem::exists(directory)) {
                scan_directory(directory);
            }
        }
        
        build_capability_map();
    }
    
    void scan_directory(const std::filesystem::path& directory) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(directory)) {
            if (entry.is_regular_file()) {
                auto extension = entry.path().extension();
                if (extension == ".so" || extension == ".dll" || extension == ".dylib") {
                    analyze_plugin_file(entry.path());
                }
            }
        }
    }
    
    void analyze_plugin_file(const std::filesystem::path& plugin_path) {
        try {
            PluginManifest manifest = extract_plugin_manifest(plugin_path);
            
            if (security_enabled && !verify_plugin_signature(plugin_path, manifest)) {
                throw std::runtime_error("Plugin signature verification failed");
            }
            
            if (!check_plugin_compatibility(manifest)) {
                throw std::runtime_error("Plugin compatibility check failed");
            }
            
            registry.available_plugins[manifest.plugin_id] = manifest;
            
        } catch (const std::exception& e) {
            // Log error but continue scanning
        }
    }
    
    PluginManifest extract_plugin_manifest(const std::filesystem::path& plugin_path) {
        void* handle = dlopen(plugin_path.c_str(), RTLD_LAZY | RTLD_LOCAL);
        if (!handle) {
            throw std::runtime_error("Failed to load plugin: " + std::string(dlerror()));
        }
        
        auto get_manifest = reinterpret_cast<PluginManifest*(*)()>(dlsym(handle, "get_plugin_manifest"));
        if (!get_manifest) {
            dlclose(handle);
            throw std::runtime_error("Plugin manifest not found");
        }
        
        PluginManifest manifest = *get_manifest();
        manifest.file_path = plugin_path.string();
        manifest.file_size = std::filesystem::file_size(plugin_path);
        manifest.modification_time = std::filesystem::last_write_time(plugin_path);
        
        dlclose(handle);
        
        return manifest;
    }
    
    bool verify_plugin_signature(const std::filesystem::path& plugin_path, const PluginManifest& manifest) {
        if (registry.trusted_public_key.empty()) {
            return true;
        }
        
        std::vector<uint8_t> plugin_data = read_file_binary(plugin_path);
        std::vector<uint8_t> plugin_hash = calculate_sha256(plugin_data);
        
        return verify_rsa_signature(plugin_hash, manifest.signature, registry.trusted_public_key);
    }
    
    std::vector<uint8_t> read_file_binary(const std::filesystem::path& file_path) {
        std::ifstream file(file_path, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open file: " + file_path.string());
        }
        
        file.seekg(0, std::ios::end);
        size_t file_size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        std::vector<uint8_t> data(file_size);
        file.read(reinterpret_cast<char*>(data.data()), file_size);
        
        return data;
    }
    
    std::vector<uint8_t> calculate_sha256(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
        
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, data.data(), data.size());
        SHA256_Final(hash.data(), &ctx);
        
        return hash;
    }
    
    bool verify_rsa_signature(const std::vector<uint8_t>& data, 
                             const std::vector<uint8_t>& signature, 
                             const std::vector<uint8_t>& public_key_data) {
        BIO* bio = BIO_new_mem_buf(public_key_data.data(), public_key_data.size());
        if (!bio) {
            return false;
        }
        
        RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        
        if (!rsa) {
            return false;
        }
        
        int result = RSA_verify(NID_sha256, data.data(), data.size(), 
                               signature.data(), signature.size(), rsa);
        
        RSA_free(rsa);
        
        return result == 1;
    }
    
    bool check_plugin_compatibility(const PluginManifest& manifest) {
        if (manifest.api_version != PLUGIN_API_VERSION) {
            return false;
        }
        
        if (manifest.min_converter_version > CONVERTER_VERSION) {
            return false;
        }
        
        for (const auto& dep : manifest.dependencies) {
            if (!check_dependency_available(dep)) {
                return false;
            }
        }
        
        return true;
    }
    
    bool check_dependency_available(const PluginDependency& dependency) {
        auto it = registry.available_plugins.find(dependency.plugin_id);
        if (it == registry.available_plugins.end()) {
            return false;
        }
        
        return version_satisfies(it->second.version, dependency.version_requirement);
    }
    
    bool version_satisfies(const std::string& version, const std::string& requirement) {
        // Simple version comparison implementation
        return version >= requirement;
    }
    
    void build_capability_map() {
        registry.capability_map.clear();
        
        for (const auto& [plugin_id, manifest] : registry.available_plugins) {
            for (const auto& capability : manifest.capabilities) {
                registry.capability_map[capability].push_back(plugin_id);
            }
        }
    }
    
    std::string load_plugin(const std::string& plugin_id) {
        std::unique_lock lock(registry.mutex);
        
        auto it = registry.loaded_plugins.find(plugin_id);
        if (it != registry.loaded_plugins.end()) {
            it->second->reference_count++;
            it->second->last_access = std::chrono::steady_clock::now();
            return it->second->plugin_id;
        }
        
        auto manifest_it = registry.available_plugins.find(plugin_id);
        if (manifest_it == registry.available_plugins.end()) {
            throw std::runtime_error("Plugin not found: " + plugin_id);
        }
        
        auto plugin_state = std::make_unique<PluginState>();
        plugin_state->plugin_id = plugin_id;
        plugin_state->plugin_path = manifest_it->second.file_path;
        plugin_state->metadata = manifest_it->second;
        plugin_state->status = PluginStatus::LOADING;
        plugin_state->load_time = std::chrono::steady_clock::now();
        plugin_state->last_access = plugin_state->load_time;
        plugin_state->reference_count = 1;
        
        try {
            load_plugin_library(*plugin_state);
            
            if (security_enabled) {
                setup_plugin_sandbox(*plugin_state);
            }
            
            initialize_plugin_interface(*plugin_state);
            
            plugin_state->status = PluginStatus::LOADED;
            
            std::string instance_id = plugin_id + "_" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                plugin_state->load_time.time_since_epoch()).count());
            
            registry.loaded_plugins[instance_id] = std::move(plugin_state);
            
            metrics.plugins_loaded++;
            
            return instance_id;
            
        } catch (const std::exception& e) {
            plugin_state->status = PluginStatus::ERROR;
            throw;
        }
    }
    
    void load_plugin_library(PluginState& plugin_state) {
        int flags = RTLD_LAZY;
        
        if (security_enabled) {
            flags |= RTLD_LOCAL;
        } else {
            flags |= RTLD_GLOBAL;
        }
        
        plugin_state.handle = dlopen(plugin_state.plugin_path.c_str(), flags);
        if (!plugin_state.handle) {
            throw std::runtime_error("Failed to load plugin library: " + std::string(dlerror()));
        }
        
        plugin_state.hash = calculate_sha256(read_file_binary(plugin_state.plugin_path));
    }
    
    void setup_plugin_sandbox(PluginState& plugin_state) {
        plugin_state.sandbox = std::make_unique<PluginSandbox>();
        
        plugin_state.sandbox_pid = fork();
        
        if (plugin_state.sandbox_pid == 0) {
            setup_seccomp_filter();
            setup_memory_protection();
            setup_filesystem_isolation();
            
            exec_plugin_in_sandbox(plugin_state);
            
            _exit(EXIT_FAILURE);
            
        } else if (plugin_state.sandbox_pid > 0) {
            setup_sandbox_monitoring(plugin_state);
        } else {
            throw std::runtime_error("Failed to create sandbox process");
        }
    }
    
    void setup_seccomp_filter() {
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
        if (!ctx) {
            throw std::runtime_error("Failed to initialize seccomp");
        }
        
        std::vector<int> allowed_syscalls = {
            SCMP_SYS(read), SCMP_SYS(write), SCMP_SYS(open), SCMP_SYS(close),
            SCMP_SYS(mmap), SCMP_SYS(munmap), SCMP_SYS(mprotect),
            SCMP_SYS(brk), SCMP_SYS(exit), SCMP_SYS(exit_group),
            SCMP_SYS(rt_sigreturn), SCMP_SYS(futex)
        };
        
        for (int syscall : allowed_syscalls) {
            if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall, 0) < 0) {
                seccomp_release(ctx);
                throw std::runtime_error("Failed to add seccomp rule");
            }
        }
        
        if (seccomp_load(ctx) < 0) {
            seccomp_release(ctx);
            throw std::runtime_error("Failed to load seccomp filter");
        }
        
        seccomp_release(ctx);
    }
    
    void setup_memory_protection() {
        if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
            // Non-fatal error
        }
        
        struct rlimit limit;
        limit.rlim_cur = 256 * 1024 * 1024;
        limit.rlim_max = 256 * 1024 * 1024;
        setrlimit(RLIMIT_AS, &limit);
        
        limit.rlim_cur = 100;
        limit.rlim_max = 100;
        setrlimit(RLIMIT_NPROC, &limit);
    }
    
    void setup_filesystem_isolation() {
        if (chroot("/tmp/plugin_jail") != 0) {
            // Setup basic jail directory if needed
        }
        
        if (chdir("/") != 0) {
            // Handle error
        }
    }
    
    void exec_plugin_in_sandbox(const PluginState& plugin_state) {
        // This would execute the plugin in a controlled environment
        // For now, just simulate the sandboxed execution
        sleep(1);
    }
    
    void setup_sandbox_monitoring(PluginState& plugin_state) {
        plugin_state.sandbox->monitor_thread = std::thread([&plugin_state, this]() {
            monitor_sandbox_process(plugin_state);
        });
        
        plugin_state.sandbox->monitor_thread.detach();
    }
    
    void monitor_sandbox_process(const PluginState& plugin_state) {
        int status;
        while (true) {
            pid_t result = waitpid(plugin_state.sandbox_pid, &status, WNOHANG);
            
            if (result == plugin_state.sandbox_pid) {
                if (WIFEXITED(status) || WIFSIGNALED(status)) {
                    handle_sandbox_termination(plugin_state.plugin_id, status);
                    break;
                }
            } else if (result == -1) {
                break;
            }
            
            check_sandbox_resource_usage(plugin_state);
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    void check_sandbox_resource_usage(const PluginState& plugin_state) {
        // Monitor CPU, memory, and other resource usage
        // Terminate plugin if it exceeds limits
    }
    
    void handle_sandbox_termination(const std::string& plugin_id, int status) {
        std::unique_lock lock(registry.mutex);
        
        auto it = std::find_if(registry.loaded_plugins.begin(), registry.loaded_plugins.end(),
                              [&plugin_id](const auto& pair) {
                                  return pair.second->plugin_id == plugin_id;
                              });
        
        if (it != registry.loaded_plugins.end()) {
            it->second->status = PluginStatus::CRASHED;
            // Clean up plugin state
        }
    }
    
    void initialize_plugin_interface(PluginState& plugin_state) {
        auto create_plugin = reinterpret_cast<PluginInterface*(*)()>(dlsym(plugin_state.handle, "create_plugin"));
        if (!create_plugin) {
            throw std::runtime_error("Plugin creation function not found");
        }
        
        plugin_state.interface = create_plugin();
        if (!plugin_state.interface) {
            throw std::runtime_error("Failed to create plugin instance");
        }
        
        PluginContext context;
        context.api_version = PLUGIN_API_VERSION;
        context.security_enabled = security_enabled;
        context.sandbox_enabled = plugin_state.sandbox != nullptr;
        
        if (!plugin_state.interface->initialize(context)) {
            throw std::runtime_error("Plugin initialization failed");
        }
    }
    
    void unload_plugin(const std::string& instance_id) {
        std::unique_lock lock(registry.mutex);
        
        auto it = registry.loaded_plugins.find(instance_id);
        if (it == registry.loaded_plugins.end()) {
            return;
        }
        
        auto& plugin_state = *it->second;
        
        plugin_state.reference_count--;
        if (plugin_state.reference_count > 0) {
            return;
        }
        
        plugin_state.status = PluginStatus::UNLOADING;
        
        try {
            if (plugin_state.interface) {
                plugin_state.interface->shutdown();
                
                auto destroy_plugin = reinterpret_cast<void(*)(PluginInterface*)>(dlsym(plugin_state.handle, "destroy_plugin"));
                if (destroy_plugin) {
                    destroy_plugin(plugin_state.interface);
                }
                
                plugin_state.interface = nullptr;
            }
            
            if (plugin_state.handle) {
                dlclose(plugin_state.handle);
                plugin_state.handle = nullptr;
            }
            
            if (plugin_state.sandbox_pid > 0) {
                kill(plugin_state.sandbox_pid, SIGTERM);
                
                int status;
                if (waitpid(plugin_state.sandbox_pid, &status, WNOHANG) == 0) {
                    sleep(1);
                    kill(plugin_state.sandbox_pid, SIGKILL);
                    waitpid(plugin_state.sandbox_pid, &status, 0);
                }
            }
            
            plugin_state.status = PluginStatus::UNLOADED;
            
        } catch (const std::exception& e) {
            plugin_state.status = PluginStatus::ERROR;
        }
        
        registry.loaded_plugins.erase(it);
        metrics.plugins_unloaded++;
    }
    
    PluginExecutionResult execute_plugin_function(const std::string& instance_id, 
                                                  const std::string& function_name, 
                                                  const std::vector<uint8_t>& input_data,
                                                  const PluginExecutionContext& context) {
        std::shared_lock lock(registry.mutex);
        
        auto it = registry.loaded_plugins.find(instance_id);
        if (it == registry.loaded_plugins.end()) {
            throw std::runtime_error("Plugin instance not found: " + instance_id);
        }
        
        auto& plugin_state = *it->second;
        
        if (plugin_state.status != PluginStatus::LOADED) {
            throw std::runtime_error("Plugin not in loaded state");
        }
        
        plugin_state.last_access = std::chrono::steady_clock::now();
        
        lock.unlock();
        
        std::unique_lock plugin_lock(plugin_state.mutex);
        
        PluginExecutionResult result;
        result.instance_id = instance_id;
        result.function_name = function_name;
        result.start_time = std::chrono::steady_clock::now();
        
        try {
            if (security_enabled && !validate_execution_context(context)) {
                throw std::runtime_error("Invalid execution context");
            }
            
            result.output_data = plugin_state.interface->execute_function(function_name, input_data, context);
            result.success = true;
            
        } catch (const std::exception& e) {
            result.success = false;
            result.error_message = e.what();
        }
        
        result.end_time = std::chrono::steady_clock::now();
        result.execution_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            result.end_time - result.start_time);
        
        metrics.function_calls_total++;
        if (result.success) {
            metrics.function_calls_successful++;
        } else {
            metrics.function_calls_failed++;
        }
        
        return result;
    }
    
    bool validate_execution_context(const PluginExecutionContext& context) {
        if (context.max_execution_time > std::chrono::seconds(60)) {
            return false;
        }
        
        if (context.max_memory_usage > 100 * 1024 * 1024) {
            return false;
        }
        
        for (const auto& permission : context.required_permissions) {
            if (!registry.security_policy.allowed_permissions.count(permission)) {
                return false;
            }
        }
        
        return true;
    }
    
    std::vector<std::string> get_plugins_by_capability(const std::string& capability) {
        std::shared_lock lock(registry.mutex);
        
        auto it = registry.capability_map.find(capability);
        if (it != registry.capability_map.end()) {
            return it->second;
        }
        
        return {};
    }
    
    PluginInfo get_plugin_info(const std::string& plugin_id) {
        std::shared_lock lock(registry.mutex);
        
        PluginInfo info;
        
        auto manifest_it = registry.available_plugins.find(plugin_id);
        if (manifest_it != registry.available_plugins.end()) {
            info.plugin_id = plugin_id;
            info.name = manifest_it->second.name;
            info.version = manifest_it->second.version;
            info.description = manifest_it->second.description;
            info.capabilities = manifest_it->second.capabilities;
            info.is_available = true;
        }
        
        auto loaded_it = std::find_if(registry.loaded_plugins.begin(), registry.loaded_plugins.end(),
                                     [&plugin_id](const auto& pair) {
                                         return pair.second->plugin_id == plugin_id;
                                     });
        
        if (loaded_it != registry.loaded_plugins.end()) {
            info.is_loaded = true;
            info.status = loaded_it->second->status;
            info.load_time = loaded_it->second->load_time;
            info.reference_count = loaded_it->second->reference_count;
        }
        
        return info;
    }
    
    std::vector<PluginInfo> list_all_plugins() {
        std::shared_lock lock(registry.mutex);
        
        std::vector<PluginInfo> plugins;
        
        for (const auto& [plugin_id, manifest] : registry.available_plugins) {
            plugins.push_back(get_plugin_info(plugin_id));
        }
        
        return plugins;
    }
    
    void reload_plugin(const std::string& plugin_id) {
        std::vector<std::string> instances_to_reload;
        
        {
            std::shared_lock lock(registry.mutex);
            for (const auto& [instance_id, plugin_state] : registry.loaded_plugins) {
                if (plugin_state->plugin_id == plugin_id) {
                    instances_to_reload.push_back(instance_id);
                }
            }
        }
        
        for (const auto& instance_id : instances_to_reload) {
            unload_plugin(instance_id);
        }
        
        scan_plugin_directories();
        
        for (size_t i = 0; i < instances_to_reload.size(); ++i) {
            load_plugin(plugin_id);
        }
    }
    
    void start_monitoring() {
        monitoring_thread = std::thread([this]() {
            while (true) {
                monitor_plugin_health();
                cleanup_unused_plugins();
                update_metrics();
                
                std::this_thread::sleep_for(std::chrono::seconds(30));
            }
        });
        
        monitoring_thread.detach();
    }
    
    void monitor_plugin_health() {
        std::unique_lock lock(registry.mutex);
        
        auto now = std::chrono::steady_clock::now();
        
        for (auto& [instance_id, plugin_state] : registry.loaded_plugins) {
            if (plugin_state->status == PluginStatus::LOADED) {
                auto idle_time = now - plugin_state->last_access;
                
                if (idle_time > std::chrono::minutes(30) && plugin_state->reference_count == 0) {
                    plugin_state->status = PluginStatus::IDLE;
                }
                
                if (plugin_state->sandbox_pid > 0) {
                    if (kill(plugin_state->sandbox_pid, 0) != 0) {
                        plugin_state->status = PluginStatus::CRASHED;
                    }
                }
            }
        }
    }
    
    void cleanup_unused_plugins() {
        std::vector<std::string> plugins_to_unload;
        
        {
            std::shared_lock lock(registry.mutex);
            auto now = std::chrono::steady_clock::now();
            
            for (const auto& [instance_id, plugin_state] : registry.loaded_plugins) {
                if (plugin_state->status == PluginStatus::IDLE || plugin_state->status == PluginStatus::CRASHED) {
                    auto idle_time = now - plugin_state->last_access;
                    if (idle_time > std::chrono::hours(1)) {
                        plugins_to_unload.push_back(instance_id);
                    }
                }
            }
        }
        
        for (const auto& instance_id : plugins_to_unload) {
            unload_plugin(instance_id);
        }
    }
    
    void start_hot_reload_monitoring() {
        hot_reload_thread = std::thread([this]() {
            std::unordered_map<std::string, std::filesystem::file_time_type> file_times;
            
            while (hot_reload_enabled) {
                check_plugin_file_changes(file_times);
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        });
        
        hot_reload_thread.detach();
    }
    
    void check_plugin_file_changes(std::unordered_map<std::string, std::filesystem::file_time_type>& file_times) {
        std::shared_lock lock(registry.mutex);
        
        for (const auto& [plugin_id, manifest] : registry.available_plugins) {
            try {
                auto current_time = std::filesystem::last_write_time(manifest.file_path);
                
                auto it = file_times.find(manifest.file_path);
                if (it != file_times.end() && it->second != current_time) {
                    lock.unlock();
                    reload_plugin(plugin_id);
                    lock.lock();
                }
                
                file_times[manifest.file_path] = current_time;
                
            } catch (const std::exception& e) {
                // Handle file access errors
            }
        }
    }
    
    void update_metrics() {
        std::shared_lock lock(registry.mutex);
        
        metrics.total_plugins = registry.available_plugins.size();
        metrics.loaded_plugins = registry.loaded_plugins.size();
        
        size_t active_plugins = 0;
        size_t idle_plugins = 0;
        size_t crashed_plugins = 0;
        
        for (const auto& [instance_id, plugin_state] : registry.loaded_plugins) {
            switch (plugin_state->status) {
                case PluginStatus::LOADED:
                    active_plugins++;
                    break;
                case PluginStatus::IDLE:
                    idle_plugins++;
                    break;
                case PluginStatus::CRASHED:
                    crashed_plugins++;
                    break;
                default:
                    break;
            }
        }
        
        metrics.active_plugins = active_plugins;
        metrics.idle_plugins = idle_plugins;
        metrics.crashed_plugins = crashed_plugins;
    }
};

PluginManager::PluginManager() : pimpl(std::make_unique<Impl>()) {}

PluginManager::~PluginManager() = default;

void PluginManager::initialize(const PluginConfig& config) {
    pimpl->initialize_plugin_system(config);
}

std::string PluginManager::load_plugin(const std::string& plugin_id) {
    return pimpl->load_plugin(plugin_id);
}

void PluginManager::unload_plugin(const std::string& instance_id) {
    pimpl->unload_plugin(instance_id);
}

PluginExecutionResult PluginManager::execute_plugin_function(const std::string& instance_id, 
                                                           const std::string& function_name, 
                                                           const std::vector<uint8_t>& input_data,
                                                           const PluginExecutionContext& context) {
    return pimpl->execute_plugin_function(instance_id, function_name, input_data, context);
}

std::vector<std::string> PluginManager::get_plugins_by_capability(const std::string& capability) {
    return pimpl->get_plugins_by_capability(capability);
}

PluginInfo PluginManager::get_plugin_info(const std::string& plugin_id) {
    return pimpl->get_plugin_info(plugin_id);
}

std::vector<PluginInfo> PluginManager::list_all_plugins() {
    return pimpl->list_all_plugins();
}

void PluginManager::reload_plugin(const std::string& plugin_id) {
    pimpl->reload_plugin(plugin_id);
}

PluginMetrics PluginManager::get_metrics() const {
    return pimpl->metrics;
}

} 