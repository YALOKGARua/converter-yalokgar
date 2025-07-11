#pragma once

#include "../../core/converter_engine.hpp"
#include "../../core/format_types.hpp"
#include <memory>
#include <vector>
#include <string>
#include <variant>
#include <unordered_map>
#include <expected>

namespace converter::modules::data {

enum class DataFormat {
    JSON, XML, CSV, YAML, TOML, INI, PROPERTIES, PLIST,
    AVRO, PARQUET, ORC, PROTOBUF, MSGPACK, BSON, CBOR,
    ARROW, FEATHER, HDF5, NETCDF, FITS, MATLAB, PICKLE,
    SQL, GRAPHQL, JSONL, NDJSON, TSV, PSV, FIXED_WIDTH,
    BINARY, HEX, BASE64, UUENCODE, QUOTED_PRINTABLE,
    SQLITE, MYSQL, POSTGRESQL, MONGODB, REDIS, INFLUXDB,
    ELASTICSEARCH, CASSANDRA, DYNAMODB, FIRESTORE,
    EXCEL, ODS, SPSS, SAS, STATA, R, JUPYTER, MARKDOWN_TABLE
};

enum class DataType {
    String, Integer, Float, Boolean, Date, DateTime, Time,
    Binary, Array, Object, Null, UUID, URI, Email, Phone,
    JSON_POINTER, REGEX, CURRENCY, PERCENTAGE, DURATION,
    COORDINATES, IPV4, IPV6, MAC_ADDRESS, CREDIT_CARD,
    SOCIAL_SECURITY, PASSPORT, DRIVER_LICENSE, BARCODE,
    QR_CODE, HASH, CHECKSUM, SIGNATURE, CERTIFICATE
};

struct DataSchema {
    std::string name;
    std::string description;
    std::string version;
    std::unordered_map<std::string, DataType> fields;
    std::unordered_map<std::string, std::string> field_descriptions;
    std::unordered_map<std::string, std::vector<std::string>> field_constraints;
    std::unordered_map<std::string, std::string> field_formats;
    std::unordered_map<std::string, bool> field_required;
    std::unordered_map<std::string, std::string> field_defaults;
    std::vector<std::string> primary_keys;
    std::vector<std::string> foreign_keys;
    std::vector<std::string> unique_constraints;
    std::vector<std::string> indexes;
    std::unordered_map<std::string, std::string> metadata;
};

struct DataMetadata {
    std::string source_name;
    std::string source_type;
    std::string source_version;
    std::string created_by;
    std::string created_at;
    std::string modified_by;
    std::string modified_at;
    std::string description;
    std::string license;
    std::string copyright;
    std::vector<std::string> tags;
    std::unordered_map<std::string, std::string> custom_properties;
    std::size_t record_count;
    std::size_t field_count;
    std::size_t size_bytes;
    std::string checksum_md5;
    std::string checksum_sha256;
    std::string encoding;
    std::string line_ending;
    std::string delimiter;
    std::string quote_char;
    std::string escape_char;
    std::string null_value;
    bool has_header;
    bool is_normalized;
    bool is_compressed;
    bool is_encrypted;
    DataSchema schema;
};

struct DataOptions {
    std::optional<std::string> encoding;
    std::optional<std::string> delimiter;
    std::optional<std::string> quote_char;
    std::optional<std::string> escape_char;
    std::optional<std::string> null_value;
    std::optional<std::string> line_ending;
    std::optional<bool> has_header;
    std::optional<bool> skip_empty_lines;
    std::optional<std::size_t> skip_rows;
    std::optional<std::size_t> max_rows;
    std::optional<std::vector<std::string>> column_names;
    std::optional<std::vector<DataType>> column_types;
    std::optional<std::vector<std::string>> select_columns;
    std::optional<std::vector<std::string>> exclude_columns;
    std::optional<std::unordered_map<std::string, std::string>> rename_columns;
    std::optional<std::unordered_map<std::string, std::string>> default_values;
    std::optional<std::string> date_format;
    std::optional<std::string> time_format;
    std::optional<std::string> datetime_format;
    std::optional<std::string> timezone;
    std::optional<std::string> locale;
    std::optional<std::string> decimal_separator;
    std::optional<std::string> thousand_separator;
    std::optional<std::string> currency_symbol;
    std::optional<bool> normalize_data;
    std::optional<bool> validate_data;
    std::optional<bool> clean_data;
    std::optional<bool> deduplicate_data;
    std::optional<bool> sort_data;
    std::optional<std::vector<std::string>> sort_columns;
    std::optional<bool> sort_ascending;
    std::optional<std::string> filter_expression;
    std::optional<std::string> group_by_column;
    std::optional<std::vector<std::string>> aggregate_functions;
    std::optional<std::unordered_map<std::string, std::string>> transformations;
    std::optional<std::string> pivot_column;
    std::optional<std::string> pivot_value_column;
    std::optional<std::string> unpivot_columns;
    std::optional<bool> transpose_data;
    std::optional<std::string> join_type;
    std::optional<std::string> join_column;
    std::optional<std::string> join_file;
    std::optional<bool> preserve_order;
    std::optional<bool> preserve_types;
    std::optional<bool> preserve_nulls;
    std::optional<bool> preserve_empty_strings;
    std::optional<bool> trim_whitespace;
    std::optional<bool> convert_case;
    std::optional<std::string> case_conversion;
    std::optional<bool> remove_duplicates;
    std::optional<bool> fill_missing_values;
    std::optional<std::string> missing_value_strategy;
    std::optional<bool> detect_outliers;
    std::optional<bool> remove_outliers;
    std::optional<double> outlier_threshold;
    std::optional<bool> anonymize_data;
    std::optional<std::vector<std::string>> anonymize_columns;
    std::optional<std::string> anonymization_method;
    std::optional<bool> encrypt_data;
    std::optional<std::string> encryption_key;
    std::optional<std::string> encryption_algorithm;
    std::optional<bool> compress_data;
    std::optional<std::string> compression_algorithm;
    std::optional<int> compression_level;
    std::optional<bool> create_index;
    std::optional<std::vector<std::string>> index_columns;
    std::optional<bool> create_backup;
    std::optional<std::string> backup_location;
    std::optional<bool> verify_integrity;
    std::optional<bool> generate_statistics;
    std::optional<bool> generate_report;
    std::optional<std::string> report_format;
    std::optional<std::string> output_schema;
    std::optional<std::string> output_template;
    std::optional<bool> pretty_print;
    std::optional<int> indent_size;
    std::optional<bool> sort_keys;
    std::optional<bool> escape_unicode;
    std::optional<bool> ensure_ascii;
    std::optional<std::string> float_precision;
    std::optional<bool> scientific_notation;
    std::optional<std::string> array_format;
    std::optional<std::string> object_format;
    std::optional<bool> inline_arrays;
    std::optional<bool> inline_objects;
    std::optional<std::string> root_element;
    std::optional<std::string> namespace_prefix;
    std::optional<std::unordered_map<std::string, std::string>> namespaces;
    std::optional<bool> include_declaration;
    std::optional<bool> include_schema;
    std::optional<std::string> schema_location;
    std::optional<bool> validate_schema;
    std::optional<bool> use_cdata;
    std::optional<bool> pretty_xml;
    std::optional<std::string> attribute_prefix;
    std::optional<std::string> text_key;
    std::optional<bool> force_list;
    std::optional<std::vector<std::string>> force_list_elements;
    std::optional<bool> strip_namespace;
    std::optional<bool> process_namespaces;
    std::optional<std::string> namespace_separator;
    std::optional<std::string> comment_prefix;
    std::optional<bool> allow_comments;
    std::optional<bool> allow_trailing_comma;
    std::optional<bool> allow_duplicate_keys;
    std::optional<bool> allow_nan_inf;
    std::optional<bool> strict_mode;
    std::optional<std::string> error_handling;
    std::optional<bool> log_errors;
    std::optional<std::string> log_file;
    std::optional<bool> continue_on_error;
    std::optional<std::size_t> max_errors;
    std::optional<bool> sample_data;
    std::optional<std::size_t> sample_size;
    std::optional<std::string> sample_method;
    std::optional<bool> profile_data;
    std::optional<bool> infer_schema;
    std::optional<std::size_t> schema_sample_size;
    std::optional<double> schema_threshold;
    std::optional<bool> auto_detect_types;
    std::optional<bool> auto_detect_encoding;
    std::optional<bool> auto_detect_delimiter;
    std::optional<std::vector<std::string>> try_delimiters;
    std::optional<bool> parallel_processing;
    std::optional<std::size_t> chunk_size;
    std::optional<std::size_t> buffer_size;
    std::optional<bool> streaming_mode;
    std::optional<std::size_t> memory_limit;
    std::optional<bool> use_memory_mapping;
    std::optional<std::string> temp_directory;
    std::optional<bool> clean_temp_files;
    std::optional<bool> cache_results;
    std::optional<std::string> cache_directory;
    std::optional<std::size_t> cache_size_limit;
    std::optional<std::chrono::seconds> cache_ttl;
    std::optional<bool> enable_metrics;
    std::optional<std::string> metrics_format;
    std::optional<std::string> metrics_output;
    std::optional<bool> enable_tracing;
    std::optional<std::string> trace_format;
    std::optional<std::string> trace_output;
};

using DataValue = std::variant<std::monostate, std::string, int64_t, double, bool, 
                               std::vector<uint8_t>, std::vector<DataValue>, 
                               std::unordered_map<std::string, DataValue>>;

class DataBuffer {
public:
    DataBuffer();
    DataBuffer(const std::string& filename);
    DataBuffer(std::vector<uint8_t> data, DataFormat format);
    DataBuffer(const std::vector<std::unordered_map<std::string, DataValue>>& records);
    ~DataBuffer();
    
    std::expected<void, std::error_code> load_from_file(const std::string& filename);
    std::expected<void, std::error_code> load_from_memory(std::span<const uint8_t> data, DataFormat format);
    std::expected<void, std::error_code> load_from_string(const std::string& data, DataFormat format);
    std::expected<void, std::error_code> save_to_file(const std::string& filename, const DataOptions& options = {});
    std::expected<std::vector<uint8_t>, std::error_code> save_to_memory(DataFormat format, const DataOptions& options = {});
    std::expected<std::string, std::error_code> save_to_string(DataFormat format, const DataOptions& options = {});
    
    const DataMetadata& metadata() const { return metadata_; }
    DataMetadata& metadata() { return metadata_; }
    
    const std::vector<std::unordered_map<std::string, DataValue>>& records() const { return records_; }
    std::vector<std::unordered_map<std::string, DataValue>>& records() { return records_; }
    
    std::expected<void, std::error_code> add_record(const std::unordered_map<std::string, DataValue>& record);
    std::expected<void, std::error_code> insert_record(std::size_t index, const std::unordered_map<std::string, DataValue>& record);
    std::expected<void, std::error_code> update_record(std::size_t index, const std::unordered_map<std::string, DataValue>& record);
    std::expected<void, std::error_code> remove_record(std::size_t index);
    std::expected<void, std::error_code> clear_records();
    
    std::expected<DataValue, std::error_code> get_value(std::size_t row, const std::string& column) const;
    std::expected<void, std::error_code> set_value(std::size_t row, const std::string& column, const DataValue& value);
    
    std::expected<std::vector<std::string>, std::error_code> get_column_names() const;
    std::expected<std::vector<DataValue>, std::error_code> get_column_values(const std::string& column) const;
    std::expected<void, std::error_code> set_column_values(const std::string& column, const std::vector<DataValue>& values);
    
    std::expected<void, std::error_code> add_column(const std::string& name, DataType type, const DataValue& default_value = {});
    std::expected<void, std::error_code> remove_column(const std::string& name);
    std::expected<void, std::error_code> rename_column(const std::string& old_name, const std::string& new_name);
    std::expected<void, std::error_code> change_column_type(const std::string& name, DataType new_type);
    
    std::expected<void, std::error_code> filter_records(const std::function<bool(const std::unordered_map<std::string, DataValue>&)>& predicate);
    std::expected<void, std::error_code> sort_records(const std::string& column, bool ascending = true);
    std::expected<void, std::error_code> sort_records(const std::vector<std::string>& columns, bool ascending = true);
    
    std::expected<void, std::error_code> group_by(const std::string& column);
    std::expected<void, std::error_code> aggregate(const std::string& column, const std::string& function);
    std::expected<void, std::error_code> pivot(const std::string& column, const std::string& value_column);
    std::expected<void, std::error_code> unpivot(const std::vector<std::string>& columns, const std::string& key_column, const std::string& value_column);
    
    std::expected<void, std::error_code> join(const DataBuffer& other, const std::string& join_column, const std::string& join_type = "inner");
    std::expected<void, std::error_code> merge(const DataBuffer& other);
    std::expected<void, std::error_code> append(const DataBuffer& other);
    
    std::expected<void, std::error_code> validate_data(const DataSchema& schema);
    std::expected<void, std::error_code> clean_data();
    std::expected<void, std::error_code> normalize_data();
    std::expected<void, std::error_code> deduplicate_data();
    
    std::expected<void, std::error_code> fill_missing_values(const std::string& strategy = "forward");
    std::expected<void, std::error_code> detect_outliers(const std::string& method = "iqr");
    std::expected<void, std::error_code> remove_outliers(double threshold = 1.5);
    
    std::expected<void, std::error_code> anonymize_data(const std::vector<std::string>& columns, const std::string& method = "hash");
    std::expected<void, std::error_code> encrypt_data(const std::string& key, const std::string& algorithm = "aes256");
    std::expected<void, std::error_code> decrypt_data(const std::string& key, const std::string& algorithm = "aes256");
    
    std::expected<void, std::error_code> transform_column(const std::string& column, const std::function<DataValue(const DataValue&)>& transformer);
    std::expected<void, std::error_code> apply_expression(const std::string& expression, const std::string& result_column);
    
    std::expected<DataBuffer, std::error_code> sample_data(std::size_t sample_size, const std::string& method = "random") const;
    std::expected<DataBuffer, std::error_code> select_columns(const std::vector<std::string>& columns) const;
    std::expected<DataBuffer, std::error_code> select_rows(std::size_t start, std::size_t count) const;
    
    std::expected<void, std::error_code> convert_to_format(DataFormat target_format, const DataOptions& options = {});
    
    std::expected<std::unordered_map<std::string, std::any>, std::error_code> get_statistics() const;
    std::expected<std::string, std::error_code> generate_report(const std::string& format = "html") const;
    std::expected<DataSchema, std::error_code> infer_schema() const;
    
    std::expected<void, std::error_code> export_to_database(const std::string& connection_string, const std::string& table_name, const DataOptions& options = {});
    std::expected<void, std::error_code> import_from_database(const std::string& connection_string, const std::string& query, const DataOptions& options = {});
    
    std::expected<void, std::error_code> export_to_api(const std::string& endpoint, const std::string& method = "POST", const DataOptions& options = {});
    std::expected<void, std::error_code> import_from_api(const std::string& endpoint, const std::string& method = "GET", const DataOptions& options = {});
    
    std::expected<void, std::error_code> stream_to_kafka(const std::string& broker, const std::string& topic, const DataOptions& options = {});
    std::expected<void, std::error_code> stream_from_kafka(const std::string& broker, const std::string& topic, const DataOptions& options = {});
    
    std::expected<void, std::error_code> create_index(const std::vector<std::string>& columns);
    std::expected<void, std::error_code> optimize_storage();
    std::expected<void, std::error_code> compress_data(const std::string& algorithm = "gzip");
    std::expected<void, std::error_code> decompress_data();
    
    bool is_valid() const { return !records_.empty(); }
    DataFormat get_format() const { return format_; }
    std::size_t get_record_count() const { return records_.size(); }
    std::size_t get_column_count() const { return records_.empty() ? 0 : records_[0].size(); }
    std::size_t get_size() const { return records_.size() * sizeof(std::unordered_map<std::string, DataValue>); }
    
private:
    std::vector<std::unordered_map<std::string, DataValue>> records_;
    DataFormat format_;
    DataMetadata metadata_;
    
    std::expected<void, std::error_code> detect_format(const std::string& filename);
    std::expected<void, std::error_code> parse_data(std::span<const uint8_t> data, DataFormat format);
    std::expected<void, std::error_code> serialize_data(DataFormat format, const DataOptions& options);
    std::expected<void, std::error_code> initialize_data_engine();
    
    class DataEngine;
    std::unique_ptr<DataEngine> engine_;
};

class DataConverter : public converter::core::ConversionTask<DataBuffer, DataBuffer> {
public:
    DataConverter(DataBuffer input, converter::core::ConversionOptions options, DataOptions processing_options = {});
    
    result_type execute() override;
    std::future<result_type> execute_async() override;
    std::generator<result_type> execute_stream() override;
    
    bool validate_input() const override;
    bool can_convert() const override;
    std::string get_format_info() const override;
    std::size_t estimate_output_size() const override;
    std::chrono::milliseconds estimate_duration() const override;
    
    void set_target_format(DataFormat format) { target_format_ = format; }
    void set_processing_options(const DataOptions& options) { processing_options_ = options; }
    
    static std::expected<DataBuffer, std::error_code> load_from_file(const std::string& filename);
    static std::expected<void, std::error_code> save_to_file(const DataBuffer& data, const std::string& filename, const DataOptions& options = {});
    
    static std::expected<std::vector<DataBuffer>, std::error_code> batch_convert(
        const std::vector<std::string>& input_files,
        const std::string& output_directory,
        DataFormat target_format,
        const DataOptions& options = {}
    );
    
    static std::expected<DataBuffer, std::error_code> merge_datasets(const std::vector<DataBuffer>& datasets);
    static std::expected<std::vector<DataBuffer>, std::error_code> split_dataset(const DataBuffer& dataset, std::size_t chunk_size);
    
    static std::expected<void, std::error_code> csv_to_json(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    static std::expected<void, std::error_code> json_to_csv(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    static std::expected<void, std::error_code> xml_to_json(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    static std::expected<void, std::error_code> json_to_xml(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    static std::expected<void, std::error_code> yaml_to_json(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    static std::expected<void, std::error_code> json_to_yaml(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    static std::expected<void, std::error_code> toml_to_json(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    static std::expected<void, std::error_code> json_to_toml(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    
    static std::expected<void, std::error_code> sql_to_json(const std::string& connection_string, const std::string& query, const std::string& output_file, const DataOptions& options = {});
    static std::expected<void, std::error_code> json_to_sql(const std::string& input_file, const std::string& connection_string, const std::string& table_name, const DataOptions& options = {});
    
    static std::expected<void, std::error_code> excel_to_json(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    static std::expected<void, std::error_code> json_to_excel(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    
    static std::expected<void, std::error_code> parquet_to_json(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    static std::expected<void, std::error_code> json_to_parquet(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    
    static std::expected<void, std::error_code> avro_to_json(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    static std::expected<void, std::error_code> json_to_avro(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    
    static std::expected<void, std::error_code> protobuf_to_json(const std::string& input_file, const std::string& output_file, const std::string& proto_file, const DataOptions& options = {});
    static std::expected<void, std::error_code> json_to_protobuf(const std::string& input_file, const std::string& output_file, const std::string& proto_file, const DataOptions& options = {});
    
    static std::expected<void, std::error_code> msgpack_to_json(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    static std::expected<void, std::error_code> json_to_msgpack(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    
    static std::expected<void, std::error_code> bson_to_json(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    static std::expected<void, std::error_code> json_to_bson(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    
    static std::expected<void, std::error_code> cbor_to_json(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    static std::expected<void, std::error_code> json_to_cbor(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    
    static std::expected<void, std::error_code> binary_to_hex(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    static std::expected<void, std::error_code> hex_to_binary(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    
    static std::expected<void, std::error_code> binary_to_base64(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    static std::expected<void, std::error_code> base64_to_binary(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    
    static std::expected<void, std::error_code> validate_data_quality(const std::string& input_file, const std::string& schema_file, const std::string& report_file);
    static std::expected<void, std::error_code> profile_dataset(const std::string& input_file, const std::string& profile_file);
    static std::expected<void, std::error_code> generate_schema(const std::string& input_file, const std::string& schema_file);
    static std::expected<void, std::error_code> infer_data_types(const std::string& input_file, const std::string& output_file);
    
    static std::expected<void, std::error_code> clean_dataset(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    static std::expected<void, std::error_code> normalize_dataset(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    static std::expected<void, std::error_code> deduplicate_dataset(const std::string& input_file, const std::string& output_file, const DataOptions& options = {});
    
    static std::expected<void, std::error_code> anonymize_dataset(const std::string& input_file, const std::string& output_file, const std::vector<std::string>& columns, const DataOptions& options = {});
    static std::expected<void, std::error_code> encrypt_dataset(const std::string& input_file, const std::string& output_file, const std::string& key, const DataOptions& options = {});
    static std::expected<void, std::error_code> decrypt_dataset(const std::string& input_file, const std::string& output_file, const std::string& key, const DataOptions& options = {});
    
    static std::expected<void, std::error_code> compress_dataset(const std::string& input_file, const std::string& output_file, const std::string& algorithm = "gzip");
    static std::expected<void, std::error_code> decompress_dataset(const std::string& input_file, const std::string& output_file, const std::string& algorithm = "gzip");
    
    static std::expected<void, std::error_code> split_dataset(const std::string& input_file, const std::string& output_directory, std::size_t chunk_size);
    static std::expected<void, std::error_code> merge_datasets(const std::vector<std::string>& input_files, const std::string& output_file);
    
    static std::expected<void, std::error_code> sample_dataset(const std::string& input_file, const std::string& output_file, std::size_t sample_size, const std::string& method = "random");
    static std::expected<void, std::error_code> filter_dataset(const std::string& input_file, const std::string& output_file, const std::string& filter_expression);
    
    static std::expected<void, std::error_code> sort_dataset(const std::string& input_file, const std::string& output_file, const std::vector<std::string>& columns, bool ascending = true);
    static std::expected<void, std::error_code> group_dataset(const std::string& input_file, const std::string& output_file, const std::string& group_column, const std::vector<std::string>& aggregate_functions);
    
    static std::expected<void, std::error_code> join_datasets(const std::string& left_file, const std::string& right_file, const std::string& output_file, const std::string& join_column, const std::string& join_type = "inner");
    static std::expected<void, std::error_code> union_datasets(const std::vector<std::string>& input_files, const std::string& output_file);
    
    static std::expected<void, std::error_code> pivot_dataset(const std::string& input_file, const std::string& output_file, const std::string& pivot_column, const std::string& value_column);
    static std::expected<void, std::error_code> unpivot_dataset(const std::string& input_file, const std::string& output_file, const std::vector<std::string>& columns, const std::string& key_column, const std::string& value_column);
    
    static std::expected<void, std::error_code> transpose_dataset(const std::string& input_file, const std::string& output_file);
    static std::expected<void, std::error_code> crosstab_dataset(const std::string& input_file, const std::string& output_file, const std::string& row_column, const std::string& column_column, const std::string& value_column);
    
    static std::expected<void, std::error_code> calculate_statistics(const std::string& input_file, const std::string& output_file);
    static std::expected<void, std::error_code> generate_report(const std::string& input_file, const std::string& output_file, const std::string& format = "html");
    
    static std::expected<void, std::error_code> create_data_dictionary(const std::string& input_file, const std::string& output_file);
    static std::expected<void, std::error_code> create_lineage_diagram(const std::vector<std::string>& input_files, const std::string& output_file);
    
    static std::expected<void, std::error_code> benchmark_formats(const std::string& input_file, const std::string& output_directory);
    static std::expected<void, std::error_code> compare_datasets(const std::string& left_file, const std::string& right_file, const std::string& output_file);
    
    static std::vector<DataFormat> get_supported_input_formats();
    static std::vector<DataFormat> get_supported_output_formats();
    static bool is_format_supported(DataFormat format);
    static std::expected<DataMetadata, std::error_code> get_data_info(const std::string& filename);
    
private:
    DataFormat target_format_ = DataFormat::JSON;
    DataOptions processing_options_;
    
    std::expected<DataBuffer, std::error_code> apply_processing(const DataBuffer& input) const;
    std::expected<std::vector<uint8_t>, std::error_code> encode_data(const DataBuffer& data) const;
    std::expected<DataBuffer, std::error_code> decode_data(std::span<const uint8_t> data) const;
    
    static std::unordered_map<DataFormat, std::string> format_extensions_;
    static std::unordered_map<DataFormat, std::vector<std::string>> format_mime_types_;
    static bool is_initialized_;
    static void initialize_data_support();
};

} 