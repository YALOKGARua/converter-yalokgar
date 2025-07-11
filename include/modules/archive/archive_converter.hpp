#pragma once

#include "../../core/converter_engine.hpp"
#include "../../core/format_types.hpp"
#include <memory>
#include <vector>
#include <string>
#include <unordered_map>
#include <expected>
#include <filesystem>

namespace converter::modules::archive {

enum class ArchiveFormat {
    ZIP, RAR, TAR, GZIP, BZIP2, XZ, LZMA, ZSTD, LZ4, 
    SEVEN_ZIP, CAB, ARJ, LHA, ACE, UUE, Z, COMPRESS,
    TAR_GZ, TAR_BZ2, TAR_XZ, TAR_LZMA, TAR_ZSTD,
    ISO, DMG, IMG, VHD, VMDK, QCOW2, VDI
};

enum class CompressionLevel {
    None = 0, Fastest = 1, Fast = 3, Normal = 5, 
    Good = 7, Best = 9, Ultra = 11
};

enum class CompressionMethod {
    Store, Deflate, Deflate64, BZIP2, LZMA, LZMA2, 
    PPMd, AES, ZStandard, LZ4, BROTLI, SNAPPY
};

struct ArchiveEntry {
    std::string path;
    std::string name;
    std::size_t size;
    std::size_t compressed_size;
    std::time_t modified_time;
    std::time_t created_time;
    std::time_t accessed_time;
    std::uint32_t attributes;
    std::uint32_t crc32;
    std::string checksum_md5;
    std::string checksum_sha1;
    std::string checksum_sha256;
    bool is_directory;
    bool is_encrypted;
    bool is_compressed;
    CompressionMethod compression_method;
    CompressionLevel compression_level;
    std::string comment;
    std::unordered_map<std::string, std::string> extended_attributes;
};

struct ArchiveMetadata {
    std::string archive_name;
    ArchiveFormat format;
    std::size_t total_size;
    std::size_t compressed_size;
    std::size_t entry_count;
    std::size_t directory_count;
    std::size_t file_count;
    double compression_ratio;
    std::time_t created_time;
    std::time_t modified_time;
    std::string comment;
    std::string creator;
    std::string version;
    bool is_encrypted;
    bool is_signed;
    bool is_solid;
    bool is_multivolume;
    std::uint32_t volume_count;
    std::vector<ArchiveEntry> entries;
    std::unordered_map<std::string, std::string> metadata_map;
};

struct ArchiveOptions {
    std::optional<CompressionLevel> compression_level;
    std::optional<CompressionMethod> compression_method;
    std::optional<std::string> password;
    std::optional<std::string> comment;
    std::optional<bool> create_solid_archive;
    std::optional<bool> encrypt_headers;
    std::optional<std::string> encryption_algorithm;
    std::optional<std::size_t> dictionary_size;
    std::optional<std::size_t> word_size;
    std::optional<std::size_t> block_size;
    std::optional<std::size_t> thread_count;
    std::optional<std::size_t> memory_limit;
    std::optional<bool> store_permissions;
    std::optional<bool> store_timestamps;
    std::optional<bool> store_extended_attributes;
    std::optional<bool> follow_symlinks;
    std::optional<std::vector<std::string>> exclude_patterns;
    std::optional<std::vector<std::string>> include_patterns;
    std::optional<std::size_t> volume_size;
    std::optional<std::string> volume_prefix;
    std::optional<bool> verify_integrity;
    std::optional<bool> test_archive;
    std::optional<bool> overwrite_existing;
    std::optional<bool> preserve_paths;
    std::optional<bool> flatten_directory_structure;
    std::optional<std::string> base_directory;
    std::optional<bool> compress_executables;
    std::optional<bool> compress_media_files;
    std::optional<bool> deduplicate_files;
    std::optional<bool> create_recovery_records;
    std::optional<double> recovery_record_percentage;
    std::optional<bool> create_sfx;
    std::optional<std::string> sfx_module;
    std::optional<std::string> sfx_config;
    std::optional<std::size_t> max_file_size;
    std::optional<std::size_t> min_file_size;
    std::optional<std::time_t> newer_than;
    std::optional<std::time_t> older_than;
    std::optional<bool> store_checksums;
    std::optional<std::vector<std::string>> checksum_algorithms;
    std::optional<bool> enable_progress_tracking;
    std::optional<bool> enable_logging;
    std::optional<std::string> log_file;
    std::optional<std::string> temp_directory;
    std::optional<bool> clean_temp_files;
};

class ArchiveBuffer {
public:
    ArchiveBuffer();
    ArchiveBuffer(const std::string& filename);
    ArchiveBuffer(std::vector<uint8_t> data, ArchiveFormat format);
    ~ArchiveBuffer();
    
    std::expected<void, std::error_code> load_from_file(const std::string& filename);
    std::expected<void, std::error_code> load_from_memory(std::span<const uint8_t> data, ArchiveFormat format);
    std::expected<void, std::error_code> save_to_file(const std::string& filename, const ArchiveOptions& options = {});
    std::expected<std::vector<uint8_t>, std::error_code> save_to_memory(ArchiveFormat format, const ArchiveOptions& options = {});
    
    const ArchiveMetadata& metadata() const { return metadata_; }
    ArchiveMetadata& metadata() { return metadata_; }
    
    std::expected<void, std::error_code> add_file(const std::string& file_path, const std::string& archive_path = "");
    std::expected<void, std::error_code> add_directory(const std::string& directory_path, const std::string& archive_path = "", bool recursive = true);
    std::expected<void, std::error_code> add_data(const std::string& archive_path, std::span<const uint8_t> data);
    std::expected<void, std::error_code> add_from_memory(const std::string& archive_path, const std::vector<uint8_t>& data);
    
    std::expected<void, std::error_code> remove_entry(const std::string& archive_path);
    std::expected<void, std::error_code> rename_entry(const std::string& old_path, const std::string& new_path);
    std::expected<void, std::error_code> update_entry(const std::string& archive_path, const std::string& file_path);
    
    std::expected<std::vector<uint8_t>, std::error_code> extract_entry(const std::string& archive_path);
    std::expected<void, std::error_code> extract_entry_to_file(const std::string& archive_path, const std::string& output_path);
    std::expected<void, std::error_code> extract_all(const std::string& output_directory);
    std::expected<void, std::error_code> extract_entries(const std::vector<std::string>& archive_paths, const std::string& output_directory);
    
    std::expected<bool, std::error_code> entry_exists(const std::string& archive_path);
    std::expected<ArchiveEntry, std::error_code> get_entry_info(const std::string& archive_path);
    std::expected<std::vector<ArchiveEntry>, std::error_code> list_entries(const std::string& path_prefix = "");
    std::expected<std::vector<std::string>, std::error_code> list_entry_names(const std::string& path_prefix = "");
    
    std::expected<void, std::error_code> set_password(const std::string& password);
    std::expected<void, std::error_code> remove_password();
    std::expected<void, std::error_code> change_password(const std::string& old_password, const std::string& new_password);
    
    std::expected<void, std::error_code> test_archive();
    std::expected<void, std::error_code> repair_archive();
    std::expected<void, std::error_code> optimize_archive();
    
    std::expected<void, std::error_code> create_sfx(const std::string& sfx_module, const std::string& config = "");
    std::expected<void, std::error_code> remove_sfx();
    
    std::expected<void, std::error_code> split_archive(std::size_t volume_size, const std::string& output_prefix);
    std::expected<void, std::error_code> merge_volumes(const std::vector<std::string>& volume_files);
    
    std::expected<void, std::error_code> compress_archive(CompressionLevel level = CompressionLevel::Normal);
    std::expected<void, std::error_code> decompress_archive();
    
    std::expected<void, std::error_code> convert_to_format(ArchiveFormat target_format, const ArchiveOptions& options = {});
    
    std::expected<void, std::error_code> create_backup(const std::string& source_directory, const ArchiveOptions& options = {});
    std::expected<void, std::error_code> restore_backup(const std::string& target_directory, const ArchiveOptions& options = {});
    
    std::expected<void, std::error_code> create_incremental_backup(const std::string& source_directory, const std::string& base_archive, const ArchiveOptions& options = {});
    std::expected<void, std::error_code> apply_incremental_backup(const std::string& base_archive, const std::string& target_directory);
    
    std::expected<void, std::error_code> create_differential_backup(const std::string& source_directory, const std::string& base_archive, const ArchiveOptions& options = {});
    std::expected<void, std::error_code> apply_differential_backup(const std::string& base_archive, const std::string& target_directory);
    
    std::expected<void, std::error_code> deduplicate_files();
    std::expected<void, std::error_code> verify_checksums();
    std::expected<void, std::error_code> update_checksums();
    
    std::expected<std::vector<std::string>, std::error_code> find_duplicates();
    std::expected<std::vector<std::string>, std::error_code> find_corrupted_entries();
    std::expected<std::vector<std::string>, std::error_code> find_empty_directories();
    std::expected<std::vector<std::string>, std::error_code> find_large_files(std::size_t size_threshold);
    
    std::expected<void, std::error_code> set_comment(const std::string& comment);
    std::expected<std::string, std::error_code> get_comment();
    
    std::expected<void, std::error_code> set_entry_comment(const std::string& archive_path, const std::string& comment);
    std::expected<std::string, std::error_code> get_entry_comment(const std::string& archive_path);
    
    bool is_valid() const { return !data_.empty(); }
    ArchiveFormat get_format() const { return format_; }
    std::size_t get_size() const { return data_.size(); }
    std::size_t get_entry_count() const { return metadata_.entry_count; }
    double get_compression_ratio() const { return metadata_.compression_ratio; }
    bool is_encrypted() const { return metadata_.is_encrypted; }
    bool is_multivolume() const { return metadata_.is_multivolume; }
    
private:
    std::vector<uint8_t> data_;
    ArchiveFormat format_;
    ArchiveMetadata metadata_;
    std::string password_;
    
    std::expected<void, std::error_code> detect_format();
    std::expected<void, std::error_code> parse_metadata();
    std::expected<void, std::error_code> initialize_archive_engine();
    
    class ArchiveEngine;
    std::unique_ptr<ArchiveEngine> engine_;
};

class ArchiveConverter : public converter::core::ConversionTask<ArchiveBuffer, ArchiveBuffer> {
public:
    ArchiveConverter(ArchiveBuffer input, converter::core::ConversionOptions options, ArchiveOptions processing_options = {});
    
    result_type execute() override;
    std::future<result_type> execute_async() override;
    std::generator<result_type> execute_stream() override;
    
    bool validate_input() const override;
    bool can_convert() const override;
    std::string get_format_info() const override;
    std::size_t estimate_output_size() const override;
    std::chrono::milliseconds estimate_duration() const override;
    
    void set_target_format(ArchiveFormat format) { target_format_ = format; }
    void set_processing_options(const ArchiveOptions& options) { processing_options_ = options; }
    
    static std::expected<ArchiveBuffer, std::error_code> load_from_file(const std::string& filename);
    static std::expected<void, std::error_code> save_to_file(const ArchiveBuffer& archive, const std::string& filename, const ArchiveOptions& options = {});
    
    static std::expected<std::vector<ArchiveBuffer>, std::error_code> batch_convert(
        const std::vector<std::string>& input_files,
        const std::string& output_directory,
        ArchiveFormat target_format,
        const ArchiveOptions& options = {}
    );
    
    static std::expected<ArchiveBuffer, std::error_code> create_archive(const std::string& source_directory, ArchiveFormat format, const ArchiveOptions& options = {});
    static std::expected<void, std::error_code> extract_archive(const std::string& archive_file, const std::string& output_directory, const ArchiveOptions& options = {});
    
    static std::expected<void, std::error_code> compress_directory(const std::string& directory_path, const std::string& output_file, CompressionLevel level = CompressionLevel::Normal);
    static std::expected<void, std::error_code> decompress_archive(const std::string& archive_file, const std::string& output_directory);
    
    static std::expected<void, std::error_code> create_backup_archive(const std::string& source_directory, const std::string& output_file, const ArchiveOptions& options = {});
    static std::expected<void, std::error_code> restore_from_backup(const std::string& backup_file, const std::string& target_directory, const ArchiveOptions& options = {});
    
    static std::expected<void, std::error_code> merge_archives(const std::vector<std::string>& archive_files, const std::string& output_file);
    static std::expected<void, std::error_code> split_archive(const std::string& archive_file, std::size_t volume_size, const std::string& output_prefix);
    
    static std::expected<void, std::error_code> create_encrypted_archive(const std::string& source_directory, const std::string& output_file, const std::string& password, const ArchiveOptions& options = {});
    static std::expected<void, std::error_code> decrypt_archive(const std::string& archive_file, const std::string& password, const std::string& output_file);
    
    static std::expected<void, std::error_code> test_archive_integrity(const std::string& archive_file);
    static std::expected<void, std::error_code> repair_corrupted_archive(const std::string& archive_file, const std::string& output_file);
    
    static std::expected<void, std::error_code> optimize_archive_size(const std::string& archive_file, const std::string& output_file);
    static std::expected<void, std::error_code> recompress_archive(const std::string& archive_file, const std::string& output_file, CompressionLevel level);
    
    static std::expected<void, std::error_code> create_incremental_archive(const std::string& source_directory, const std::string& base_archive, const std::string& output_file);
    static std::expected<void, std::error_code> apply_incremental_archive(const std::string& base_archive, const std::string& incremental_archive, const std::string& output_directory);
    
    static std::expected<void, std::error_code> create_differential_archive(const std::string& source_directory, const std::string& base_archive, const std::string& output_file);
    static std::expected<void, std::error_code> apply_differential_archive(const std::string& base_archive, const std::string& differential_archive, const std::string& output_directory);
    
    static std::expected<void, std::error_code> create_sync_archive(const std::string& source_directory, const std::string& target_directory, const std::string& output_file);
    static std::expected<void, std::error_code> apply_sync_archive(const std::string& sync_archive, const std::string& target_directory);
    
    static std::expected<void, std::error_code> create_disk_image(const std::string& source_directory, const std::string& output_file, const std::string& filesystem_type = "iso9660");
    static std::expected<void, std::error_code> mount_disk_image(const std::string& image_file, const std::string& mount_point);
    static std::expected<void, std::error_code> unmount_disk_image(const std::string& mount_point);
    
    static std::expected<void, std::error_code> create_virtual_drive(const std::string& source_directory, const std::string& output_file, std::size_t size_gb);
    static std::expected<void, std::error_code> convert_disk_image(const std::string& input_file, const std::string& output_file, const std::string& target_format);
    
    static std::expected<void, std::error_code> benchmark_compression(const std::string& test_directory, const std::string& output_file);
    static std::expected<void, std::error_code> analyze_compression_efficiency(const std::string& archive_file, const std::string& report_file);
    
    static std::vector<ArchiveFormat> get_supported_input_formats();
    static std::vector<ArchiveFormat> get_supported_output_formats();
    static std::vector<CompressionMethod> get_supported_compression_methods();
    static bool is_format_supported(ArchiveFormat format);
    static std::expected<ArchiveMetadata, std::error_code> get_archive_info(const std::string& filename);
    
private:
    ArchiveFormat target_format_ = ArchiveFormat::ZIP;
    ArchiveOptions processing_options_;
    
    std::expected<ArchiveBuffer, std::error_code> apply_processing(const ArchiveBuffer& input) const;
    std::expected<std::vector<uint8_t>, std::error_code> encode_archive(const ArchiveBuffer& archive) const;
    std::expected<ArchiveBuffer, std::error_code> decode_archive(std::span<const uint8_t> data) const;
    
    static std::unordered_map<ArchiveFormat, std::string> format_extensions_;
    static std::unordered_map<ArchiveFormat, std::vector<std::string>> format_mime_types_;
    static bool is_initialized_;
    static void initialize_archive_support();
};

} 