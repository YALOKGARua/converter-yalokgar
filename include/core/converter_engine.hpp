#pragma once

#include <memory>
#include <vector>
#include <unordered_map>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <future>
#include <chrono>
#include <span>
#include <concepts>
#include <coroutine>
#include <ranges>
#include <expected>
#include <variant>
#include <optional>

namespace converter::core {

template<typename T>
concept ConvertibleFormat = requires(T t) {
    typename T::input_type;
    typename T::output_type;
    { t.convert() } -> std::convertible_to<std::expected<typename T::output_type, std::error_code>>;
    { t.validate() } -> std::convertible_to<bool>;
    { t.get_format_name() } -> std::convertible_to<std::string>;
};

template<typename T>
concept AsyncConvertible = ConvertibleFormat<T> && requires(T t) {
    { t.convert_async() } -> std::convertible_to<std::future<std::expected<typename T::output_type, std::error_code>>>;
};

template<typename T>
concept StreamConvertible = ConvertibleFormat<T> && requires(T t) {
    { t.convert_stream() } -> std::convertible_to<std::generator<std::expected<typename T::output_type, std::error_code>>>;
};

enum class ConversionStatus : uint8_t {
    Idle,
    Preparing,
    Converting,
    Finalizing,
    Completed,
    Failed,
    Cancelled,
    Paused
};

enum class ConversionPriority : uint8_t {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3
};

enum class ConversionMode : uint8_t {
    Synchronous,
    Asynchronous,
    Streaming,
    BatchProcessing,
    Pipeline
};

struct ConversionMetadata {
    std::string source_format;
    std::string target_format;
    std::string source_path;
    std::string target_path;
    std::size_t source_size;
    std::size_t target_size;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    std::chrono::milliseconds duration;
    std::unordered_map<std::string, std::string> custom_properties;
    std::string checksum_source;
    std::string checksum_target;
    double compression_ratio;
    std::string error_message;
    std::vector<std::string> warnings;
};

struct ConversionOptions {
    ConversionMode mode = ConversionMode::Synchronous;
    ConversionPriority priority = ConversionPriority::Normal;
    std::size_t max_memory_usage = 1024 * 1024 * 1024;
    std::size_t thread_count = std::thread::hardware_concurrency();
    std::size_t chunk_size = 8192;
    bool enable_compression = true;
    bool enable_encryption = false;
    bool enable_checksums = true;
    bool enable_progress_tracking = true;
    bool enable_auto_recovery = true;
    bool enable_caching = true;
    std::string encryption_key;
    std::string compression_algorithm = "zstd";
    std::unordered_map<std::string, std::string> format_specific_options;
    std::function<void(float)> progress_callback;
    std::function<void(const std::string&)> log_callback;
    std::function<bool()> cancellation_token;
};

template<typename InputType, typename OutputType>
class ConversionTask {
public:
    using input_type = InputType;
    using output_type = OutputType;
    using result_type = std::expected<OutputType, std::error_code>;

    ConversionTask(InputType input, ConversionOptions options)
        : input_(std::move(input)), options_(std::move(options)), 
          status_(ConversionStatus::Idle), progress_(0.0f) {}

    virtual ~ConversionTask() = default;

    virtual result_type execute() = 0;
    virtual std::future<result_type> execute_async() = 0;
    virtual std::generator<result_type> execute_stream() = 0;

    virtual bool validate_input() const = 0;
    virtual bool can_convert() const = 0;
    virtual std::string get_format_info() const = 0;
    virtual std::size_t estimate_output_size() const = 0;
    virtual std::chrono::milliseconds estimate_duration() const = 0;

    ConversionStatus get_status() const { return status_.load(); }
    float get_progress() const { return progress_.load(); }
    const ConversionMetadata& get_metadata() const { return metadata_; }
    const ConversionOptions& get_options() const { return options_; }

    void cancel() { cancelled_.store(true); }
    bool is_cancelled() const { return cancelled_.load(); }

    void pause() { paused_.store(true); }
    void resume() { paused_.store(false); }
    bool is_paused() const { return paused_.load(); }

protected:
    void update_status(ConversionStatus status) { status_.store(status); }
    void update_progress(float progress) { progress_.store(progress); }
    void update_metadata(const ConversionMetadata& metadata) { metadata_ = metadata; }

    InputType input_;
    ConversionOptions options_;
    ConversionMetadata metadata_;
    std::atomic<ConversionStatus> status_;
    std::atomic<float> progress_;
    std::atomic<bool> cancelled_{false};
    std::atomic<bool> paused_{false};
};

class ConversionEngine {
public:
    ConversionEngine();
    ~ConversionEngine();

    template<ConvertibleFormat T>
    std::expected<std::unique_ptr<T>, std::error_code> create_converter(const std::string& format_name);

    template<typename InputType, typename OutputType>
    std::expected<OutputType, std::error_code> convert(
        InputType input, 
        const std::string& target_format,
        const ConversionOptions& options = {}
    );

    template<typename InputType, typename OutputType>
    std::future<std::expected<OutputType, std::error_code>> convert_async(
        InputType input,
        const std::string& target_format,
        const ConversionOptions& options = {}
    );

    template<typename InputType, typename OutputType>
    std::generator<std::expected<OutputType, std::error_code>> convert_stream(
        InputType input,
        const std::string& target_format,
        const ConversionOptions& options = {}
    );

    std::expected<std::vector<std::string>, std::error_code> batch_convert(
        const std::vector<std::string>& input_files,
        const std::string& target_format,
        const std::string& output_directory,
        const ConversionOptions& options = {}
    );

    std::expected<void, std::error_code> pipeline_convert(
        const std::vector<std::string>& conversion_chain,
        const std::string& input_file,
        const std::string& output_file,
        const ConversionOptions& options = {}
    );

    std::vector<std::string> get_supported_formats() const;
    std::vector<std::string> get_supported_conversions(const std::string& format) const;
    
    bool is_format_supported(const std::string& format) const;
    bool is_conversion_supported(const std::string& from, const std::string& to) const;
    
    std::expected<ConversionMetadata, std::error_code> get_conversion_info(
        const std::string& from, 
        const std::string& to,
        const std::string& input_file
    ) const;

    std::expected<void, std::error_code> register_format_converter(
        const std::string& format_name,
        std::function<std::unique_ptr<ConversionTask<std::vector<uint8_t>, std::vector<uint8_t>>>(
            std::vector<uint8_t>, ConversionOptions)> factory
    );

    std::expected<void, std::error_code> unregister_format_converter(const std::string& format_name);

    void set_thread_pool_size(std::size_t size);
    std::size_t get_thread_pool_size() const;

    void set_memory_limit(std::size_t bytes);
    std::size_t get_memory_limit() const;

    void enable_profiling(bool enable);
    bool is_profiling_enabled() const;

    std::expected<void, std::error_code> save_configuration(const std::string& config_file) const;
    std::expected<void, std::error_code> load_configuration(const std::string& config_file);

    std::expected<void, std::error_code> enable_plugin(const std::string& plugin_name);
    std::expected<void, std::error_code> disable_plugin(const std::string& plugin_name);
    std::vector<std::string> get_loaded_plugins() const;

    std::expected<void, std::error_code> clear_cache();
    std::expected<void, std::error_code> optimize_cache();
    std::size_t get_cache_size() const;

    std::expected<void, std::error_code> export_statistics(const std::string& output_file) const;
    std::expected<void, std::error_code> import_statistics(const std::string& input_file);

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

template<typename T>
class ConversionRegistry {
public:
    static ConversionRegistry& instance() {
        static ConversionRegistry instance;
        return instance;
    }

    template<ConvertibleFormat U>
    void register_converter(const std::string& name, std::function<std::unique_ptr<U>()> factory) {
        std::lock_guard<std::mutex> lock(mutex_);
        factories_[name] = [factory]() -> std::unique_ptr<T> {
            return std::unique_ptr<T>(factory());
        };
    }

    std::unique_ptr<T> create_converter(const std::string& name) {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        if (auto it = factories_.find(name); it != factories_.end()) {
            return it->second();
        }
        return nullptr;
    }

    std::vector<std::string> get_registered_converters() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        std::vector<std::string> names;
        names.reserve(factories_.size());
        for (const auto& [name, _] : factories_) {
            names.push_back(name);
        }
        return names;
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::function<std::unique_ptr<T>()>> factories_;
};

} 