#pragma once

#include "../../core/converter_engine.hpp"
#include "../../core/format_types.hpp"
#include <opencv2/opencv.hpp>
#include <memory>
#include <vector>
#include <span>
#include <complex>
#include <concepts>

namespace converter::modules::image {

enum class ColorSpace : uint8_t {
    RGB, BGR, RGBA, BGRA, ARGB, ABGR,
    HSV, HSL, HLS, Lab, Luv, XYZ, YUV, YCbCr,
    CMYK, Gray, Indexed
};

enum class ImageQuality : uint8_t {
    Lowest = 1,
    Low = 25,
    Medium = 50,
    High = 75,
    Highest = 95,
    Lossless = 100
};

enum class ResizeAlgorithm : uint8_t {
    Nearest, Linear, Cubic, Lanczos3, Lanczos4,
    Area, SuperResolution, EdgePreserving
};

enum class FilterType : uint8_t {
    Blur, GaussianBlur, MedianBlur, BilateralFilter,
    Sharpen, UnsharpMask, EdgeDetection, Emboss,
    Noise, Denoise, Contrast, Brightness, Saturation,
    Hue, Gamma, Levels, Curves, Histogram
};

struct ImageMetadata {
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t channels = 0;
    uint32_t depth = 8;
    ColorSpace color_space = ColorSpace::RGB;
    double dpi_x = 72.0;
    double dpi_y = 72.0;
    std::string compression = "none";
    std::string color_profile;
    std::unordered_map<std::string, std::string> exif_data;
    std::unordered_map<std::string, std::string> iptc_data;
    std::unordered_map<std::string, std::string> xmp_data;
    std::vector<uint8_t> icc_profile;
    bool has_transparency = false;
    bool is_animated = false;
    uint32_t frame_count = 1;
    std::vector<uint32_t> frame_delays;
    std::string creation_time;
    std::string author;
    std::string copyright;
    std::string description;
    std::string software;
    std::string camera_make;
    std::string camera_model;
    std::optional<double> focal_length;
    std::optional<double> aperture;
    std::optional<double> shutter_speed;
    std::optional<int> iso_speed;
    std::optional<double> exposure_bias;
    std::optional<double> white_balance;
    std::optional<bool> flash_used;
    std::optional<double> gps_latitude;
    std::optional<double> gps_longitude;
    std::optional<double> gps_altitude;
};

struct ImageProcessingOptions {
    std::optional<std::pair<uint32_t, uint32_t>> target_size;
    std::optional<ResizeAlgorithm> resize_algorithm;
    std::optional<ColorSpace> target_color_space;
    std::optional<ImageQuality> quality;
    std::optional<uint32_t> target_depth;
    std::vector<FilterType> filters;
    std::unordered_map<std::string, double> filter_parameters;
    bool preserve_metadata = true;
    bool preserve_transparency = true;
    bool auto_orient = true;
    bool strip_metadata = false;
    std::optional<std::string> watermark_path;
    std::optional<std::pair<int, int>> watermark_position;
    std::optional<double> watermark_opacity;
    std::optional<std::pair<int, int, int, int>> crop_rectangle;
    std::optional<double> rotation_angle;
    std::optional<bool> flip_horizontal;
    std::optional<bool> flip_vertical;
    std::optional<std::string> output_icc_profile;
    std::optional<std::pair<double, double>> target_dpi;
    std::optional<std::string> compression_algorithm;
    std::optional<int> compression_level;
    bool progressive_encoding = false;
    bool optimize_for_web = false;
    bool remove_alpha_channel = false;
    std::optional<std::array<uint8_t, 3>> background_color;
    std::optional<std::pair<int, int>> tile_size;
    bool generate_thumbnails = false;
    std::vector<std::pair<uint32_t, uint32_t>> thumbnail_sizes;
    std::optional<std::string> output_format_options;
};

template<typename T>
concept ImageData = requires(T t) {
    { t.data() } -> std::convertible_to<const uint8_t*>;
    { t.size() } -> std::convertible_to<std::size_t>;
    { t.width() } -> std::convertible_to<uint32_t>;
    { t.height() } -> std::convertible_to<uint32_t>;
    { t.channels() } -> std::convertible_to<uint32_t>;
};

class ImageBuffer {
public:
    ImageBuffer() = default;
    ImageBuffer(uint32_t width, uint32_t height, uint32_t channels, uint32_t depth = 8);
    ImageBuffer(const cv::Mat& mat);
    ImageBuffer(std::vector<uint8_t> data, uint32_t width, uint32_t height, uint32_t channels, uint32_t depth = 8);
    
    ~ImageBuffer() = default;
    
    const uint8_t* data() const { return data_.data(); }
    uint8_t* data() { return data_.data(); }
    std::size_t size() const { return data_.size(); }
    
    uint32_t width() const { return width_; }
    uint32_t height() const { return height_; }
    uint32_t channels() const { return channels_; }
    uint32_t depth() const { return depth_; }
    
    ColorSpace color_space() const { return color_space_; }
    void set_color_space(ColorSpace cs) { color_space_ = cs; }
    
    const ImageMetadata& metadata() const { return metadata_; }
    ImageMetadata& metadata() { return metadata_; }
    
    cv::Mat to_mat() const;
    void from_mat(const cv::Mat& mat);
    
    std::expected<void, std::error_code> resize(uint32_t new_width, uint32_t new_height, ResizeAlgorithm algorithm = ResizeAlgorithm::Linear);
    std::expected<void, std::error_code> convert_color_space(ColorSpace target_space);
    std::expected<void, std::error_code> apply_filter(FilterType filter, const std::unordered_map<std::string, double>& parameters = {});
    std::expected<void, std::error_code> crop(int x, int y, int width, int height);
    std::expected<void, std::error_code> rotate(double angle);
    std::expected<void, std::error_code> flip(bool horizontal, bool vertical);
    std::expected<void, std::error_code> add_watermark(const ImageBuffer& watermark, int x, int y, double opacity = 1.0);
    
    std::expected<std::vector<uint8_t>, std::error_code> encode(core::FormatType format, const ImageProcessingOptions& options = {}) const;
    std::expected<void, std::error_code> decode(std::span<const uint8_t> data, core::FormatType format);
    
    std::expected<ImageBuffer, std::error_code> create_thumbnail(uint32_t max_width, uint32_t max_height) const;
    std::expected<std::vector<ImageBuffer>, std::error_code> create_thumbnails(const std::vector<std::pair<uint32_t, uint32_t>>& sizes) const;
    
    std::expected<std::vector<double>, std::error_code> compute_histogram() const;
    std::expected<double, std::error_code> compute_quality_score() const;
    std::expected<bool, std::error_code> detect_blur() const;
    std::expected<std::vector<cv::Rect>, std::error_code> detect_faces() const;
    std::expected<std::vector<cv::Point2f>, std::error_code> detect_corners() const;
    std::expected<std::vector<cv::KeyPoint>, std::error_code> detect_features() const;
    
    bool is_valid() const { return !data_.empty() && width_ > 0 && height_ > 0; }
    bool has_alpha() const { return channels_ == 2 || channels_ == 4; }
    std::size_t bytes_per_pixel() const { return channels_ * (depth_ / 8); }
    std::size_t stride() const { return width_ * bytes_per_pixel(); }
    
private:
    std::vector<uint8_t> data_;
    uint32_t width_ = 0;
    uint32_t height_ = 0;
    uint32_t channels_ = 0;
    uint32_t depth_ = 8;
    ColorSpace color_space_ = ColorSpace::RGB;
    ImageMetadata metadata_;
};

class ImageConverter : public core::ConversionTask<ImageBuffer, ImageBuffer> {
public:
    ImageConverter(ImageBuffer input, core::ConversionOptions options, ImageProcessingOptions processing_options = {});
    
    result_type execute() override;
    std::future<result_type> execute_async() override;
    std::generator<result_type> execute_stream() override;
    
    bool validate_input() const override;
    bool can_convert() const override;
    std::string get_format_info() const override;
    std::size_t estimate_output_size() const override;
    std::chrono::milliseconds estimate_duration() const override;
    
    void set_target_format(core::FormatType format) { target_format_ = format; }
    void set_processing_options(const ImageProcessingOptions& options) { processing_options_ = options; }
    
    static std::expected<ImageBuffer, std::error_code> load_from_file(const std::string& filename);
    static std::expected<void, std::error_code> save_to_file(const ImageBuffer& image, const std::string& filename, const ImageProcessingOptions& options = {});
    
    static std::expected<ImageBuffer, std::error_code> create_from_raw_data(
        std::span<const uint8_t> data,
        uint32_t width,
        uint32_t height,
        uint32_t channels,
        uint32_t depth = 8,
        ColorSpace color_space = ColorSpace::RGB
    );
    
    static std::expected<std::vector<ImageBuffer>, std::error_code> load_animated_image(const std::string& filename);
    static std::expected<void, std::error_code> save_animated_image(const std::vector<ImageBuffer>& frames, const std::string& filename, const std::vector<uint32_t>& delays = {});
    
    static std::expected<ImageBuffer, std::error_code> create_collage(
        const std::vector<ImageBuffer>& images,
        uint32_t columns,
        uint32_t rows,
        uint32_t spacing = 0,
        const std::array<uint8_t, 3>& background_color = {255, 255, 255}
    );
    
    static std::expected<ImageBuffer, std::error_code> create_panorama(const std::vector<ImageBuffer>& images);
    
    static std::expected<ImageBuffer, std::error_code> remove_background(const ImageBuffer& image, const std::array<uint8_t, 3>& background_color = {255, 255, 255});
    
    static std::expected<ImageBuffer, std::error_code> super_resolution(const ImageBuffer& image, uint32_t scale_factor = 2);
    
    static std::expected<ImageBuffer, std::error_code> style_transfer(const ImageBuffer& content, const ImageBuffer& style);
    
    static std::expected<ImageBuffer, std::error_code> noise_reduction(const ImageBuffer& image, double strength = 0.5);
    
    static std::expected<ImageBuffer, std::error_code> hdr_tone_mapping(const std::vector<ImageBuffer>& exposures);
    
    static std::expected<ImageBuffer, std::error_code> depth_of_field_simulation(const ImageBuffer& image, const ImageBuffer& depth_map, double blur_strength = 1.0);
    
    static std::expected<std::vector<ImageBuffer>, std::error_code> batch_process(
        const std::vector<std::string>& input_files,
        const std::string& output_directory,
        core::FormatType target_format,
        const ImageProcessingOptions& options = {}
    );
    
    static std::expected<void, std::error_code> create_contact_sheet(
        const std::vector<std::string>& input_files,
        const std::string& output_file,
        uint32_t columns = 4,
        uint32_t thumbnail_size = 200
    );
    
    static std::vector<core::FormatType> get_supported_input_formats();
    static std::vector<core::FormatType> get_supported_output_formats();
    static bool is_format_supported(core::FormatType format);
    static std::expected<ImageMetadata, std::error_code> get_image_info(const std::string& filename);
    
private:
    core::FormatType target_format_ = core::FormatType::JPEG;
    ImageProcessingOptions processing_options_;
    
    std::expected<ImageBuffer, std::error_code> apply_processing(const ImageBuffer& input) const;
    std::expected<std::vector<uint8_t>, std::error_code> encode_image(const ImageBuffer& image) const;
    std::expected<ImageBuffer, std::error_code> decode_image(std::span<const uint8_t> data) const;
    
    static cv::Mat apply_super_resolution_model(const cv::Mat& input, uint32_t scale_factor);
    static cv::Mat apply_style_transfer_model(const cv::Mat& content, const cv::Mat& style);
    static cv::Mat apply_noise_reduction_model(const cv::Mat& input, double strength);
    
    static std::unordered_map<core::FormatType, std::string> format_extensions_;
    static std::unordered_map<core::FormatType, std::vector<std::string>> format_mime_types_;
    static bool is_initialized_;
    static void initialize_format_support();
};

class RawImageProcessor {
public:
    struct RawProcessingOptions {
        double exposure = 0.0;
        double highlights = 0.0;
        double shadows = 0.0;
        double contrast = 0.0;
        double brightness = 0.0;
        double saturation = 0.0;
        double vibrance = 0.0;
        double temperature = 0.0;
        double tint = 0.0;
        double sharpness = 0.0;
        double noise_reduction = 0.0;
        double chromatic_aberration = 0.0;
        double vignetting = 0.0;
        bool auto_white_balance = false;
        bool auto_exposure = false;
        std::string color_profile = "sRGB";
        std::string demosaic_algorithm = "AHD";
        double gamma = 2.2;
        bool output_16bit = false;
    };
    
    static std::expected<ImageBuffer, std::error_code> process_raw_file(
        const std::string& filename,
        const RawProcessingOptions& options = {}
    );
    
    static std::expected<std::vector<std::string>, std::error_code> get_supported_raw_formats();
    static std::expected<RawProcessingOptions, std::error_code> get_auto_settings(const std::string& filename);
    static std::expected<ImageMetadata, std::error_code> get_raw_metadata(const std::string& filename);
    
private:
    static std::expected<ImageBuffer, std::error_code> process_with_libraw(
        const std::string& filename,
        const RawProcessingOptions& options
    );
};

} 