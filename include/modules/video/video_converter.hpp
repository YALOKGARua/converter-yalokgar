#pragma once

#include "../../core/converter_engine.hpp"
#include "../../core/format_types.hpp"
#include <memory>
#include <vector>
#include <span>
#include <concepts>
#include <chrono>

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libswscale/swscale.h>
#include <libavutil/avutil.h>
}

namespace converter::modules::video {

enum class VideoCodec : uint32_t {
    H264, H265, AV1, VP8, VP9, MPEG2, MPEG4,
    Xvid, DivX, Theora, ProRes, DNxHD, HAP,
    FFV1, HuffYUV, MJPEG, DV, DVCPRO, DVCPROHD,
    XDCAM, XAVC, AVCHD, WebM, FLV, WMV, RV40,
    Dirac, Schroedinger, VC1, Raw
};

enum class VideoQuality : uint8_t {
    Draft = 10,
    Low = 20,
    Medium = 30,
    High = 40,
    VeryHigh = 50,
    Ultra = 60,
    Lossless = 70
};

enum class VideoProfile : uint8_t {
    Baseline, Main, High, High10, High422, High444,
    Extended, ConstrainedBaseline, ConstrainedHigh,
    Progressive, Professional, Simple, Advanced
};

enum class VideoPreset : uint8_t {
    UltraFast, SuperFast, VeryFast, Faster, Fast,
    Medium, Slow, Slower, VerySlow, Placebo
};

enum class VideoFilter : uint32_t {
    Deinterlace = 0x001,
    Denoise = 0x002,
    Sharpen = 0x004,
    Blur = 0x008,
    Stabilize = 0x010,
    ColorCorrection = 0x020,
    Brightness = 0x040,
    Contrast = 0x080,
    Saturation = 0x100,
    Hue = 0x200,
    Gamma = 0x400,
    Levels = 0x800,
    Curves = 0x1000,
    Crop = 0x2000,
    Scale = 0x4000,
    Rotate = 0x8000,
    Flip = 0x10000,
    Watermark = 0x20000,
    Subtitle = 0x40000,
    AudioSync = 0x80000,
    FrameRate = 0x100000,
    SlowMotion = 0x200000,
    TimeWarp = 0x400000,
    Overlay = 0x800000,
    Transition = 0x1000000,
    Effect = 0x2000000
};

struct VideoMetadata {
    std::string format_name;
    std::string codec_name;
    std::string container_format;
    uint32_t width = 0;
    uint32_t height = 0;
    double fps = 0.0;
    uint64_t duration_ms = 0;
    uint64_t bitrate = 0;
    uint64_t file_size = 0;
    uint32_t frame_count = 0;
    std::string pixel_format;
    std::string color_space;
    std::string color_range;
    std::string color_primaries;
    std::string color_trc;
    double aspect_ratio = 0.0;
    bool has_b_frames = false;
    uint32_t gop_size = 0;
    uint32_t max_b_frames = 0;
    std::string profile;
    std::string level;
    std::string creation_time;
    std::string title;
    std::string author;
    std::string copyright;
    std::string description;
    std::string language;
    std::vector<std::string> tags;
    std::unordered_map<std::string, std::string> metadata_map;
    
    struct StreamInfo {
        int index;
        std::string codec;
        std::string type;
        uint64_t bitrate;
        std::string language;
        std::string title;
        std::unordered_map<std::string, std::string> metadata;
    };
    
    std::vector<StreamInfo> video_streams;
    std::vector<StreamInfo> audio_streams;
    std::vector<StreamInfo> subtitle_streams;
    std::vector<StreamInfo> data_streams;
    
    bool is_hdr = false;
    std::string hdr_format;
    std::string master_display;
    std::string content_light_level;
    
    std::optional<double> rotation_angle;
    std::optional<std::string> thumbnail_path;
    std::optional<std::vector<std::chrono::milliseconds>> chapter_times;
    std::optional<std::vector<std::string>> chapter_titles;
};

struct VideoProcessingOptions {
    std::optional<VideoCodec> target_codec;
    std::optional<std::pair<uint32_t, uint32_t>> target_resolution;
    std::optional<double> target_fps;
    std::optional<uint64_t> target_bitrate;
    std::optional<VideoQuality> quality;
    std::optional<VideoProfile> profile;
    std::optional<VideoPreset> preset;
    std::optional<std::string> pixel_format;
    std::optional<std::string> color_space;
    std::optional<uint32_t> gop_size;
    std::optional<uint32_t> max_b_frames;
    std::optional<int> qp_min;
    std::optional<int> qp_max;
    std::optional<double> crf;
    std::optional<std::pair<uint64_t, uint64_t>> time_range;
    std::optional<std::pair<int, int, int, int>> crop_area;
    std::optional<double> rotation_angle;
    std::optional<bool> flip_horizontal;
    std::optional<bool> flip_vertical;
    std::optional<std::string> watermark_path;
    std::optional<std::pair<int, int>> watermark_position;
    std::optional<double> watermark_opacity;
    std::optional<std::string> subtitle_path;
    std::optional<std::pair<int, int>> subtitle_position;
    std::optional<std::string> subtitle_font;
    std::optional<int> subtitle_size;
    std::optional<std::array<uint8_t, 3>> subtitle_color;
    
    uint32_t active_filters = 0;
    std::unordered_map<std::string, double> filter_parameters;
    std::vector<std::string> custom_filters;
    
    bool two_pass_encoding = false;
    bool hardware_acceleration = false;
    std::string hardware_device;
    bool preserve_metadata = true;
    bool preserve_chapters = true;
    bool preserve_subtitles = true;
    bool generate_thumbnails = false;
    std::vector<std::chrono::milliseconds> thumbnail_times;
    std::optional<std::string> output_format;
    std::optional<std::string> audio_codec;
    std::optional<uint32_t> audio_bitrate;
    std::optional<uint32_t> audio_sample_rate;
    std::optional<uint32_t> audio_channels;
    std::optional<std::string> audio_language;
    std::optional<std::string> subtitle_language;
    std::optional<std::string> container_format;
    std::optional<std::string> muxer_options;
    std::optional<int> thread_count;
    std::optional<std::string> log_level;
    
    struct StreamMapping {
        int input_stream_index;
        int output_stream_index;
        std::string codec;
        std::unordered_map<std::string, std::string> options;
    };
    
    std::vector<StreamMapping> stream_mappings;
    
    bool optimize_for_streaming = false;
    bool fast_start = false;
    bool fragment_mp4 = false;
    std::optional<uint32_t> segment_duration;
    std::optional<std::string> segment_format;
    std::optional<std::string> hls_playlist;
    std::optional<std::string> dash_manifest;
    
    struct HDROptions {
        bool preserve_hdr = true;
        std::string hdr_format;
        std::string color_primaries;
        std::string transfer_characteristics;
        std::string matrix_coefficients;
        std::optional<std::string> master_display;
        std::optional<std::string> content_light_level;
    };
    
    std::optional<HDROptions> hdr_options;
    
    struct AdvancedOptions {
        std::optional<std::string> motion_estimation;
        std::optional<std::string> motion_vector_precision;
        std::optional<int> lookahead_frames;
        std::optional<int> bframe_pyramid;
        std::optional<double> bframe_bias;
        std::optional<int> reference_frames;
        std::optional<std::string> entropy_coding;
        std::optional<bool> cabac;
        std::optional<int> slice_count;
        std::optional<std::string> rate_control;
        std::optional<double> buffer_size;
        std::optional<double> initial_buffer_occupancy;
        std::optional<bool> scene_change_detection;
        std::optional<double> noise_reduction;
        std::optional<bool> deblocking_filter;
        std::optional<int> deblocking_alpha;
        std::optional<int> deblocking_beta;
        std::optional<std::string> psychovisual_tuning;
        std::optional<double> psy_rd;
        std::optional<double> psy_trellis;
        std::optional<bool> mixed_refs;
        std::optional<bool> fast_pskip;
        std::optional<bool> dct_decimate;
        std::optional<int> trellis_quantization;
        std::optional<std::string> quantization_matrix;
    };
    
    std::optional<AdvancedOptions> advanced_options;
};

template<typename T>
concept VideoData = requires(T t) {
    { t.data() } -> std::convertible_to<const uint8_t*>;
    { t.size() } -> std::convertible_to<std::size_t>;
    { t.width() } -> std::convertible_to<uint32_t>;
    { t.height() } -> std::convertible_to<uint32_t>;
    { t.fps() } -> std::convertible_to<double>;
    { t.duration() } -> std::convertible_to<uint64_t>;
};

class VideoFrame {
public:
    VideoFrame() = default;
    VideoFrame(uint32_t width, uint32_t height, const std::string& pixel_format);
    VideoFrame(AVFrame* frame);
    
    ~VideoFrame();
    
    const uint8_t* data() const;
    uint8_t* data();
    std::size_t size() const;
    
    uint32_t width() const { return width_; }
    uint32_t height() const { return height_; }
    const std::string& pixel_format() const { return pixel_format_; }
    
    std::chrono::milliseconds timestamp() const { return timestamp_; }
    void set_timestamp(std::chrono::milliseconds ts) { timestamp_ = ts; }
    
    AVFrame* av_frame() const { return frame_; }
    
    std::expected<void, std::error_code> convert_pixel_format(const std::string& target_format);
    std::expected<void, std::error_code> resize(uint32_t new_width, uint32_t new_height);
    std::expected<void, std::error_code> crop(int x, int y, int width, int height);
    std::expected<void, std::error_code> rotate(double angle);
    std::expected<void, std::error_code> flip(bool horizontal, bool vertical);
    std::expected<void, std::error_code> apply_filter(const std::string& filter_name, const std::unordered_map<std::string, std::string>& parameters = {});
    
    bool is_valid() const { return frame_ != nullptr; }
    
private:
    AVFrame* frame_ = nullptr;
    uint32_t width_ = 0;
    uint32_t height_ = 0;
    std::string pixel_format_;
    std::chrono::milliseconds timestamp_{0};
    bool owns_frame_ = false;
};

class VideoBuffer {
public:
    VideoBuffer() = default;
    VideoBuffer(const std::string& filename);
    VideoBuffer(std::vector<uint8_t> data, const std::string& format);
    
    ~VideoBuffer();
    
    std::expected<void, std::error_code> load_from_file(const std::string& filename);
    std::expected<void, std::error_code> load_from_memory(std::span<const uint8_t> data, const std::string& format);
    std::expected<void, std::error_code> save_to_file(const std::string& filename, const VideoProcessingOptions& options = {});
    std::expected<std::vector<uint8_t>, std::error_code> save_to_memory(const std::string& format, const VideoProcessingOptions& options = {});
    
    const VideoMetadata& metadata() const { return metadata_; }
    VideoMetadata& metadata() { return metadata_; }
    
    std::expected<VideoFrame, std::error_code> get_frame(uint64_t frame_index);
    std::expected<VideoFrame, std::error_code> get_frame_at_time(std::chrono::milliseconds time);
    std::expected<std::vector<VideoFrame>, std::error_code> get_frames(uint64_t start_frame, uint64_t end_frame);
    std::expected<std::vector<VideoFrame>, std::error_code> get_frames_in_range(std::chrono::milliseconds start_time, std::chrono::milliseconds end_time);
    
    std::expected<void, std::error_code> seek_to_frame(uint64_t frame_index);
    std::expected<void, std::error_code> seek_to_time(std::chrono::milliseconds time);
    
    std::expected<VideoFrame, std::error_code> read_next_frame();
    
    std::expected<void, std::error_code> add_frame(const VideoFrame& frame);
    std::expected<void, std::error_code> insert_frame(uint64_t index, const VideoFrame& frame);
    std::expected<void, std::error_code> remove_frame(uint64_t index);
    std::expected<void, std::error_code> remove_frames(uint64_t start_index, uint64_t end_index);
    
    std::expected<void, std::error_code> trim(std::chrono::milliseconds start_time, std::chrono::milliseconds end_time);
    std::expected<void, std::error_code> concatenate(const VideoBuffer& other);
    
    std::expected<std::vector<uint8_t>, std::error_code> extract_thumbnail(std::chrono::milliseconds time = std::chrono::milliseconds(0));
    std::expected<std::vector<std::vector<uint8_t>>, std::error_code> extract_thumbnails(const std::vector<std::chrono::milliseconds>& times);
    
    std::expected<void, std::error_code> apply_filter(VideoFilter filter, const std::unordered_map<std::string, double>& parameters = {});
    std::expected<void, std::error_code> apply_custom_filter(const std::string& filter_graph);
    
    std::expected<void, std::error_code> change_speed(double speed_factor);
    std::expected<void, std::error_code> reverse();
    std::expected<void, std::error_code> loop(uint32_t loop_count);
    
    std::expected<void, std::error_code> add_watermark(const std::string& image_path, int x, int y, double opacity = 1.0);
    std::expected<void, std::error_code> add_text_overlay(const std::string& text, int x, int y, const std::string& font = "Arial", int size = 20, const std::array<uint8_t, 3>& color = {255, 255, 255});
    std::expected<void, std::error_code> add_subtitle_file(const std::string& subtitle_path, const std::string& language = "en");
    
    std::expected<void, std::error_code> stabilize();
    std::expected<void, std::error_code> denoise(double strength = 0.5);
    std::expected<void, std::error_code> deinterlace();
    std::expected<void, std::error_code> sharpen(double strength = 0.5);
    std::expected<void, std::error_code> auto_color_correction();
    
    std::expected<void, std::error_code> convert_to_format(const std::string& format, const VideoProcessingOptions& options = {});
    std::expected<void, std::error_code> change_resolution(uint32_t width, uint32_t height);
    std::expected<void, std::error_code> change_framerate(double fps);
    std::expected<void, std::error_code> change_bitrate(uint64_t bitrate);
    
    std::expected<void, std::error_code> extract_audio(const std::string& output_file);
    std::expected<void, std::error_code> replace_audio(const std::string& audio_file);
    std::expected<void, std::error_code> mix_audio(const std::string& audio_file, double volume = 1.0);
    
    std::expected<std::vector<std::chrono::milliseconds>, std::error_code> detect_scene_changes(double threshold = 0.3);
    std::expected<std::vector<std::pair<std::chrono::milliseconds, std::chrono::milliseconds>>, std::error_code> detect_silence(double threshold = -40.0);
    std::expected<std::vector<std::chrono::milliseconds>, std::error_code> detect_motion(double threshold = 0.1);
    
    std::expected<void, std::error_code> create_chapters(const std::vector<std::chrono::milliseconds>& times, const std::vector<std::string>& titles = {});
    std::expected<void, std::error_code> remove_chapters();
    
    std::expected<void, std::error_code> optimize_for_web();
    std::expected<void, std::error_code> create_adaptive_stream(const std::vector<std::pair<uint32_t, uint64_t>>& quality_levels, const std::string& output_dir);
    std::expected<void, std::error_code> create_hls_stream(const std::string& output_dir, uint32_t segment_duration = 10);
    std::expected<void, std::error_code> create_dash_stream(const std::string& output_dir, uint32_t segment_duration = 10);
    
    bool is_valid() const { return format_context_ != nullptr; }
    uint64_t frame_count() const { return metadata_.frame_count; }
    std::chrono::milliseconds duration() const { return std::chrono::milliseconds(metadata_.duration_ms); }
    double fps() const { return metadata_.fps; }
    uint32_t width() const { return metadata_.width; }
    uint32_t height() const { return metadata_.height; }
    
private:
    AVFormatContext* format_context_ = nullptr;
    AVCodecContext* codec_context_ = nullptr;
    AVCodec* codec_ = nullptr;
    SwsContext* sws_context_ = nullptr;
    int video_stream_index_ = -1;
    VideoMetadata metadata_;
    
    std::expected<void, std::error_code> initialize_decoder();
    std::expected<void, std::error_code> initialize_encoder(const VideoProcessingOptions& options);
    void cleanup();
};

class VideoConverter : public core::ConversionTask<VideoBuffer, VideoBuffer> {
public:
    VideoConverter(VideoBuffer input, core::ConversionOptions options, VideoProcessingOptions processing_options = {});
    
    result_type execute() override;
    std::future<result_type> execute_async() override;
    std::generator<result_type> execute_stream() override;
    
    bool validate_input() const override;
    bool can_convert() const override;
    std::string get_format_info() const override;
    std::size_t estimate_output_size() const override;
    std::chrono::milliseconds estimate_duration() const override;
    
    void set_target_format(const std::string& format) { target_format_ = format; }
    void set_processing_options(const VideoProcessingOptions& options) { processing_options_ = options; }
    
    static std::expected<VideoBuffer, std::error_code> load_from_file(const std::string& filename);
    static std::expected<void, std::error_code> save_to_file(const VideoBuffer& video, const std::string& filename, const VideoProcessingOptions& options = {});
    
    static std::expected<std::vector<VideoBuffer>, std::error_code> batch_convert(
        const std::vector<std::string>& input_files,
        const std::string& output_directory,
        const std::string& target_format,
        const VideoProcessingOptions& options = {}
    );
    
    static std::expected<VideoBuffer, std::error_code> concatenate_videos(const std::vector<VideoBuffer>& videos);
    static std::expected<VideoBuffer, std::error_code> create_slideshow(const std::vector<std::string>& image_files, double duration_per_image = 3.0, const std::string& transition = "fade");
    static std::expected<VideoBuffer, std::error_code> create_timelapse(const std::vector<std::string>& image_files, double fps = 30.0);
    
    static std::expected<void, std::error_code> extract_frames(const std::string& video_file, const std::string& output_dir, const std::string& format = "png");
    static std::expected<void, std::error_code> create_gif(const std::string& video_file, const std::string& output_file, std::chrono::milliseconds start_time = std::chrono::milliseconds(0), std::chrono::milliseconds duration = std::chrono::milliseconds(5000));
    
    static std::expected<void, std::error_code> live_stream(const std::string& input_source, const std::string& output_url, const VideoProcessingOptions& options = {});
    static std::expected<void, std::error_code> record_screen(const std::string& output_file, int x = 0, int y = 0, int width = 0, int height = 0);
    static std::expected<void, std::error_code> record_webcam(const std::string& output_file, int device_index = 0);
    
    static std::vector<std::string> get_supported_input_formats();
    static std::vector<std::string> get_supported_output_formats();
    static std::vector<std::string> get_supported_codecs();
    static std::vector<std::string> get_hardware_devices();
    static bool is_format_supported(const std::string& format);
    static bool is_codec_supported(const std::string& codec);
    static bool is_hardware_acceleration_available();
    
    static std::expected<VideoMetadata, std::error_code> get_video_info(const std::string& filename);
    static std::expected<std::vector<uint8_t>, std::error_code> get_video_thumbnail(const std::string& filename, std::chrono::milliseconds time = std::chrono::milliseconds(0));
    
private:
    std::string target_format_;
    VideoProcessingOptions processing_options_;
    
    std::expected<VideoBuffer, std::error_code> apply_processing(const VideoBuffer& input) const;
    std::expected<void, std::error_code> setup_encoder(AVCodecContext* codec_context, const VideoProcessingOptions& options) const;
    std::expected<void, std::error_code> setup_filter_graph(AVFilterGraph* filter_graph, const VideoProcessingOptions& options) const;
    
    static std::unordered_map<std::string, AVCodecID> codec_map_;
    static std::unordered_map<std::string, AVPixelFormat> pixel_format_map_;
    static bool is_initialized_;
    static void initialize_ffmpeg();
};

} 