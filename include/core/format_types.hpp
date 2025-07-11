#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <span>
#include <variant>
#include <optional>
#include <expected>

namespace converter::core {

enum class FormatCategory : uint16_t {
    Image = 0x0001,
    Video = 0x0002,
    Audio = 0x0004,
    Document = 0x0008,
    Archive = 0x0010,
    Data = 0x0020,
    Font = 0x0040,
    Mesh = 0x0080,
    Web = 0x0100,
    Crypto = 0x0200,
    Compression = 0x0400,
    Metadata = 0x0800,
    Vector = 0x1000,
    Raster = 0x2000,
    Markup = 0x4000,
    Binary = 0x8000
};

enum class FormatType : uint32_t {
    JPEG = 0x00010001,
    PNG = 0x00010002,
    GIF = 0x00010003,
    BMP = 0x00010004,
    TIFF = 0x00010005,
    WEBP = 0x00010006,
    HEIF = 0x00010007,
    AVIF = 0x00010008,
    RAW = 0x00010009,
    PSD = 0x0001000A,
    SVG = 0x0001000B,
    ICO = 0x0001000C,
    
    MP4 = 0x00020001,
    AVI = 0x00020002,
    MOV = 0x00020003,
    MKV = 0x00020004,
    WMV = 0x00020005,
    FLV = 0x00020006,
    WEBM = 0x00020007,
    OGV = 0x00020008,
    M4V = 0x00020009,
    TS = 0x0002000A,
    
    MP3 = 0x00040001,
    WAV = 0x00040002,
    FLAC = 0x00040003,
    OGG = 0x00040004,
    AAC = 0x00040005,
    M4A = 0x00040006,
    WMA = 0x00040007,
    OPUS = 0x00040008,
    APE = 0x00040009,
    AC3 = 0x0004000A,
    
    PDF = 0x00080001,
    DOCX = 0x00080002,
    DOC = 0x00080003,
    XLSX = 0x00080004,
    XLS = 0x00080005,
    PPTX = 0x00080006,
    PPT = 0x00080007,
    ODT = 0x00080008,
    ODS = 0x00080009,
    ODP = 0x0008000A,
    RTF = 0x0008000B,
    TXT = 0x0008000C,
    
    ZIP = 0x00100001,
    RAR = 0x00100002,
    GZIP = 0x00100003,
    TAR = 0x00100004,
    BZIP2 = 0x00100005,
    XZ = 0x00100006,
    LZMA = 0x00100007,
    ZSTD = 0x00100008,
    LZ4 = 0x00100009,
    
    JSON = 0x00200001,
    XML = 0x00200002,
    CSV = 0x00200003,
    YAML = 0x00200004,
    TOML = 0x00200005,
    INI = 0x00200006,
    SQL = 0x00200007,
    BINARY = 0x00200008,
    HEX = 0x00200009,
    BASE64 = 0x0020000A,
    
    TTF = 0x00400001,
    OTF = 0x00400002,
    WOFF = 0x00400003,
    WOFF2 = 0x00400004,
    EOT = 0x00400005,
    
    OBJ = 0x00800001,
    STL = 0x00800002,
    PLY = 0x00800003,
    FBX = 0x00800004,
    DAE = 0x00800005,
    X3D = 0x00800006,
    
    HTML = 0x01000001,
    CSS = 0x01000002,
    JS = 0x01000003,
    SCSS = 0x01000004,
    LESS = 0x01000005,
    TS = 0x01000006,
    
    UNKNOWN = 0xFFFFFFFF
};

struct FormatInfo {
    FormatType type;
    std::string name;
    std::string extension;
    std::string mime_type;
    std::vector<std::string> aliases;
    FormatCategory category;
    std::string description;
    std::vector<std::string> supported_features;
    std::unordered_map<std::string, std::string> metadata;
    bool is_lossy;
    bool supports_transparency;
    bool supports_animation;
    bool supports_metadata;
    bool supports_layers;
    bool supports_compression;
    bool supports_encryption;
    std::vector<std::string> conversion_targets;
    std::size_t max_file_size;
    std::size_t max_dimensions;
    std::string codec_info;
};

class FormatDetector {
public:
    static std::expected<FormatType, std::error_code> detect_from_header(std::span<const uint8_t> data);
    static std::expected<FormatType, std::error_code> detect_from_extension(const std::string& filename);
    static std::expected<FormatType, std::error_code> detect_from_mime_type(const std::string& mime_type);
    static std::expected<FormatType, std::error_code> detect_comprehensive(const std::string& filename, std::span<const uint8_t> data);
    
    static std::expected<FormatInfo, std::error_code> get_format_info(FormatType type);
    static std::vector<FormatType> get_supported_formats();
    static std::vector<FormatType> get_formats_by_category(FormatCategory category);
    
    static bool is_conversion_supported(FormatType from, FormatType to);
    static std::vector<FormatType> get_conversion_targets(FormatType from);
    static std::expected<double, std::error_code> estimate_conversion_quality(FormatType from, FormatType to);
    
private:
    static std::unordered_map<std::vector<uint8_t>, FormatType> header_signatures_;
    static std::unordered_map<std::string, FormatType> extension_map_;
    static std::unordered_map<std::string, FormatType> mime_type_map_;
    static std::unordered_map<FormatType, FormatInfo> format_info_map_;
    
    static void initialize_format_database();
    static bool is_initialized_;
};

template<typename T>
struct FormatTraits {
    static constexpr FormatType format_type = FormatType::UNKNOWN;
    static constexpr FormatCategory category = FormatCategory::Data;
    static constexpr bool is_lossy = false;
    static constexpr bool supports_transparency = false;
    static constexpr bool supports_animation = false;
    static constexpr bool supports_metadata = false;
    static constexpr bool supports_layers = false;
    static constexpr bool supports_compression = false;
    static constexpr bool supports_encryption = false;
    
    using native_type = T;
    using header_type = std::array<uint8_t, 16>;
    
    static std::expected<header_type, std::error_code> get_header(const T& data);
    static std::expected<bool, std::error_code> validate_format(const T& data);
    static std::expected<std::size_t, std::error_code> get_size(const T& data);
    static std::expected<std::string, std::error_code> get_version(const T& data);
};

} 