#pragma once

#include "../../core/converter_engine.hpp"
#include "../../core/format_types.hpp"
#include <memory>
#include <vector>
#include <span>
#include <concepts>
#include <complex>
#include <chrono>

namespace converter::modules::audio {

enum class AudioCodec : uint32_t {
    PCM, MP3, AAC, FLAC, OGG, OPUS, WMA, AC3, DTS,
    ALAC, APE, WavPack, TrueHD, DolbyDigital, AMR,
    GSM, Speex, Vorbis, G711, G722, G729, iLBC,
    Silk, CELT, Musepack, Monkey, TAK, OptimFROG,
    ATRAC, RealAudio, QDesign, Nellymoser, ADPCM,
    PCM_S16LE, PCM_S16BE, PCM_S24LE, PCM_S24BE,
    PCM_S32LE, PCM_S32BE, PCM_F32LE, PCM_F32BE,
    PCM_F64LE, PCM_F64BE, PCM_MULAW, PCM_ALAW
};

enum class AudioQuality : uint8_t {
    Telephone = 8,
    Radio = 16,
    Standard = 32,
    High = 64,
    Studio = 96,
    Mastering = 128,
    Lossless = 255
};

enum class AudioProfile : uint8_t {
    Main, Low, SSR, LTP, HE_AAC, HE_AACv2,
    LD, ELD, xHE_AAC, USAC, Extended
};

enum class AudioEffect : uint32_t {
    Normalize = 0x001,
    Amplify = 0x002,
    Compressor = 0x004,
    Limiter = 0x008,
    Gate = 0x010,
    Expander = 0x020,
    EQ = 0x040,
    Filter = 0x080,
    Reverb = 0x100,
    Delay = 0x200,
    Chorus = 0x400,
    Flanger = 0x800,
    Phaser = 0x1000,
    Distortion = 0x2000,
    Overdrive = 0x4000,
    Bitcrusher = 0x8000,
    Tremolo = 0x10000,
    Vibrato = 0x20000,
    AutoTune = 0x40000,
    VoiceChanger = 0x80000,
    NoiseReduction = 0x100000,
    DeEsser = 0x200000,
    Exciter = 0x400000,
    Enhancer = 0x800000,
    Spatializer = 0x1000000,
    Crossfade = 0x2000000,
    Fade = 0x4000000,
    Trim = 0x8000000,
    Silence = 0x10000000,
    Pitch = 0x20000000,
    TimeStretch = 0x40000000,
    Convolution = 0x80000000
};

enum class ChannelLayout : uint32_t {
    Mono = 0x01,
    Stereo = 0x02,
    Surround_2_1 = 0x04,
    Surround_3_0 = 0x08,
    Surround_4_0 = 0x10,
    Surround_5_0 = 0x20,
    Surround_5_1 = 0x40,
    Surround_7_1 = 0x80,
    Surround_7_1_Wide = 0x100,
    Surround_9_1 = 0x200,
    Surround_11_1 = 0x400,
    Surround_22_2 = 0x800,
    Binaural = 0x1000,
    Quadraphonic = 0x2000,
    Ambisonic_First = 0x4000,
    Ambisonic_Second = 0x8000,
    Ambisonic_Third = 0x10000,
    Custom = 0x80000000
};

struct AudioMetadata {
    std::string format_name;
    std::string codec_name;
    uint32_t sample_rate = 0;
    uint32_t channels = 0;
    uint32_t bits_per_sample = 0;
    uint64_t duration_ms = 0;
    uint64_t bitrate = 0;
    uint64_t file_size = 0;
    uint64_t sample_count = 0;
    ChannelLayout channel_layout = ChannelLayout::Stereo;
    std::string container_format;
    std::string endianness;
    bool is_signed = true;
    bool is_float = false;
    bool is_planar = false;
    bool is_lossless = false;
    bool has_drm = false;
    
    std::string title;
    std::string artist;
    std::string album;
    std::string album_artist;
    std::string composer;
    std::string genre;
    std::string date;
    std::string year;
    std::string track_number;
    std::string disc_number;
    std::string total_tracks;
    std::string total_discs;
    std::string comment;
    std::string lyrics;
    std::string language;
    std::string publisher;
    std::string copyright;
    std::string encoded_by;
    std::string encoder;
    std::string isrc;
    std::string musicbrainz_artist_id;
    std::string musicbrainz_album_id;
    std::string musicbrainz_track_id;
    std::string acoustid_id;
    std::string bpm;
    std::string key;
    std::string mood;
    std::string rating;
    std::string replay_gain_track;
    std::string replay_gain_album;
    std::string replay_gain_reference;
    std::string dynamic_range;
    std::string peak_level;
    std::string rms_level;
    std::string loudness_range;
    std::string integrated_loudness;
    std::string true_peak;
    std::string cue_sheet;
    std::vector<uint8_t> album_art;
    std::string album_art_mime_type;
    std::unordered_map<std::string, std::string> custom_tags;
    
    struct ChapterInfo {
        uint64_t start_time_ms;
        uint64_t end_time_ms;
        std::string title;
        std::unordered_map<std::string, std::string> metadata;
    };
    
    std::vector<ChapterInfo> chapters;
    
    struct StreamInfo {
        int index;
        std::string codec;
        uint32_t sample_rate;
        uint32_t channels;
        uint64_t bitrate;
        std::string language;
        std::string title;
        std::unordered_map<std::string, std::string> metadata;
    };
    
    std::vector<StreamInfo> streams;
    
    double signal_to_noise_ratio = 0.0;
    double total_harmonic_distortion = 0.0;
    double dynamic_range_db = 0.0;
    double frequency_response_min = 0.0;
    double frequency_response_max = 0.0;
    bool is_mono_compatible = false;
    bool has_dc_offset = false;
    bool has_clipping = false;
    double crest_factor = 0.0;
    double zero_crossing_rate = 0.0;
    double spectral_centroid = 0.0;
    double spectral_rolloff = 0.0;
    double spectral_bandwidth = 0.0;
    std::vector<double> mfcc_coefficients;
    std::vector<double> chromagram;
    double tempo = 0.0;
    std::vector<double> beat_times;
    std::vector<double> onset_times;
    std::string key_signature;
    std::string time_signature;
};

struct AudioProcessingOptions {
    std::optional<AudioCodec> target_codec;
    std::optional<uint32_t> target_sample_rate;
    std::optional<uint32_t> target_channels;
    std::optional<uint32_t> target_bits_per_sample;
    std::optional<uint64_t> target_bitrate;
    std::optional<AudioQuality> quality;
    std::optional<AudioProfile> profile;
    std::optional<ChannelLayout> channel_layout;
    std::optional<std::string> container_format;
    std::optional<std::pair<uint64_t, uint64_t>> time_range;
    std::optional<double> volume_adjustment;
    std::optional<double> fade_in_duration;
    std::optional<double> fade_out_duration;
    std::optional<double> crossfade_duration;
    std::optional<double> pitch_shift;
    std::optional<double> tempo_change;
    std::optional<bool> preserve_pitch;
    std::optional<double> speed_factor;
    
    uint32_t active_effects = 0;
    std::unordered_map<std::string, double> effect_parameters;
    std::vector<std::string> custom_effects;
    
    struct EqualizerBand {
        double frequency;
        double gain;
        double q_factor;
        std::string type;
    };
    
    std::vector<EqualizerBand> equalizer_bands;
    
    struct CompressorSettings {
        double threshold = -20.0;
        double ratio = 4.0;
        double attack = 10.0;
        double release = 100.0;
        double knee = 2.0;
        double makeup_gain = 0.0;
        bool auto_makeup = false;
        bool lookahead = false;
    };
    
    std::optional<CompressorSettings> compressor;
    
    struct LimiterSettings {
        double threshold = -0.1;
        double release = 50.0;
        bool isr = true;
        double ceiling = -0.1;
    };
    
    std::optional<LimiterSettings> limiter;
    
    struct GateSettings {
        double threshold = -40.0;
        double ratio = 10.0;
        double attack = 1.0;
        double hold = 10.0;
        double release = 100.0;
        double knee = 2.0;
        double hysteresis = 3.0;
    };
    
    std::optional<GateSettings> gate;
    
    struct ReverbSettings {
        double room_size = 0.5;
        double damping = 0.5;
        double wet_level = 0.3;
        double dry_level = 0.7;
        double width = 1.0;
        double pre_delay = 0.0;
        std::string reverb_type = "hall";
    };
    
    std::optional<ReverbSettings> reverb;
    
    struct DelaySettings {
        double delay_time = 500.0;
        double feedback = 0.3;
        double wet_level = 0.3;
        double dry_level = 0.7;
        bool ping_pong = false;
        double damping = 0.0;
    };
    
    std::optional<DelaySettings> delay;
    
    struct ChorusSettings {
        double rate = 1.0;
        double depth = 0.5;
        double feedback = 0.3;
        double wet_level = 0.3;
        double dry_level = 0.7;
        double delay = 10.0;
        int voices = 3;
    };
    
    std::optional<ChorusSettings> chorus;
    
    struct DistortionSettings {
        double drive = 0.5;
        double tone = 0.5;
        double level = 0.5;
        std::string type = "overdrive";
        double pre_gain = 0.0;
        double post_gain = 0.0;
    };
    
    std::optional<DistortionSettings> distortion;
    
    struct NoiseReductionSettings {
        double sensitivity = 0.5;
        double strength = 0.5;
        double frequency_smoothing = 0.0;
        double temporal_smoothing = 0.0;
        bool spectral_subtraction = false;
        bool wiener_filter = false;
    };
    
    std::optional<NoiseReductionSettings> noise_reduction;
    
    struct AutoTuneSettings {
        std::string key = "C";
        std::string scale = "major";
        double correction_strength = 0.8;
        double pitch_shift_rate = 1.0;
        double formant_correction = 0.0;
        double natural_vibrato = 0.0;
    };
    
    std::optional<AutoTuneSettings> auto_tune;
    
    struct SpectralProcessingSettings {
        int fft_size = 2048;
        int hop_size = 512;
        std::string window_type = "hann";
        double overlap = 0.75;
        bool zero_padding = false;
        std::string magnitude_processing;
        std::string phase_processing;
    };
    
    std::optional<SpectralProcessingSettings> spectral_processing;
    
    bool preserve_metadata = true;
    bool normalize_audio = false;
    bool remove_silence = false;
    bool auto_gain_control = false;
    bool dither = false;
    bool noise_shaping = false;
    std::string dither_type = "triangular";
    std::string resampling_algorithm = "sinc";
    std::string channel_mixing_algorithm = "default";
    bool phase_inversion = false;
    bool channel_swap = false;
    bool mono_to_stereo = false;
    bool stereo_to_mono = false;
    std::string mono_mix_mode = "average";
    bool karaoke_mode = false;
    bool vocal_isolation = false;
    bool center_channel_extraction = false;
    bool surround_upmix = false;
    bool surround_downmix = false;
    std::string surround_decoder = "prologic";
    
    struct ConvolutionSettings {
        std::string impulse_response_file;
        double wet_level = 0.5;
        double dry_level = 0.5;
        bool normalize_ir = true;
        int fft_size = 8192;
        double latency_compensation = 0.0;
    };
    
    std::optional<ConvolutionSettings> convolution;
    
    struct AnalysisSettings {
        bool compute_loudness = false;
        bool compute_dynamic_range = false;
        bool compute_spectrum = false;
        bool compute_beats = false;
        bool compute_pitch = false;
        bool compute_onsets = false;
        bool compute_key = false;
        bool compute_tempo = false;
        bool compute_mfcc = false;
        bool compute_chromagram = false;
        bool detect_silence = false;
        bool detect_clipping = false;
        bool detect_dc_offset = false;
        double silence_threshold = -40.0;
        double clipping_threshold = -0.1;
        double dc_offset_threshold = 0.01;
    };
    
    std::optional<AnalysisSettings> analysis;
    
    struct OutputSettings {
        std::string output_format;
        std::string output_extension;
        std::string output_quality;
        std::string output_profile;
        std::unordered_map<std::string, std::string> format_options;
        std::unordered_map<std::string, std::string> codec_options;
        std::unordered_map<std::string, std::string> muxer_options;
        bool optimize_for_streaming = false;
        bool create_cue_sheet = false;
        bool embed_cue_sheet = false;
        bool create_playlist = false;
        std::string playlist_format = "m3u";
        bool split_by_chapters = false;
        bool split_by_silence = false;
        bool split_by_duration = false;
        double split_duration = 600.0;
        std::string split_naming_pattern = "{track:02d} - {title}";
        bool verify_output = false;
        bool calculate_checksums = false;
        std::vector<std::string> checksum_algorithms = {"md5", "sha1", "sha256"};
    };
    
    std::optional<OutputSettings> output;
};

template<typename T>
concept AudioData = requires(T t) {
    { t.data() } -> std::convertible_to<const float*>;
    { t.size() } -> std::convertible_to<std::size_t>;
    { t.sample_rate() } -> std::convertible_to<uint32_t>;
    { t.channels() } -> std::convertible_to<uint32_t>;
    { t.duration() } -> std::convertible_to<uint64_t>;
};

class AudioBuffer {
public:
    AudioBuffer() = default;
    AudioBuffer(uint32_t sample_rate, uint32_t channels, uint64_t sample_count);
    AudioBuffer(std::vector<float> data, uint32_t sample_rate, uint32_t channels);
    AudioBuffer(std::vector<std::vector<float>> channel_data, uint32_t sample_rate);
    
    ~AudioBuffer() = default;
    
    const float* data() const;
    float* data();
    const float* channel_data(uint32_t channel) const;
    float* channel_data(uint32_t channel);
    std::size_t size() const;
    std::size_t channel_size() const;
    
    uint32_t sample_rate() const { return sample_rate_; }
    uint32_t channels() const { return channels_; }
    uint64_t sample_count() const { return sample_count_; }
    uint64_t duration() const { return sample_count_ * 1000 / sample_rate_; }
    
    const AudioMetadata& metadata() const { return metadata_; }
    AudioMetadata& metadata() { return metadata_; }
    
    std::expected<void, std::error_code> resample(uint32_t new_sample_rate);
    std::expected<void, std::error_code> convert_channels(uint32_t new_channels, ChannelLayout layout = ChannelLayout::Stereo);
    std::expected<void, std::error_code> convert_format(uint32_t bits_per_sample, bool is_float = false, bool is_signed = true);
    
    std::expected<void, std::error_code> apply_gain(double gain_db);
    std::expected<void, std::error_code> normalize(double target_db = -3.0);
    std::expected<void, std::error_code> fade_in(double duration_ms);
    std::expected<void, std::error_code> fade_out(double duration_ms);
    std::expected<void, std::error_code> crossfade(const AudioBuffer& other, double duration_ms);
    
    std::expected<void, std::error_code> trim(uint64_t start_sample, uint64_t end_sample);
    std::expected<void, std::error_code> pad(uint64_t start_samples, uint64_t end_samples);
    std::expected<void, std::error_code> reverse();
    std::expected<void, std::error_code> loop(uint32_t loop_count);
    
    std::expected<void, std::error_code> apply_effect(AudioEffect effect, const std::unordered_map<std::string, double>& parameters = {});
    std::expected<void, std::error_code> apply_equalizer(const std::vector<AudioProcessingOptions::EqualizerBand>& bands);
    std::expected<void, std::error_code> apply_compressor(const AudioProcessingOptions::CompressorSettings& settings);
    std::expected<void, std::error_code> apply_limiter(const AudioProcessingOptions::LimiterSettings& settings);
    std::expected<void, std::error_code> apply_gate(const AudioProcessingOptions::GateSettings& settings);
    std::expected<void, std::error_code> apply_reverb(const AudioProcessingOptions::ReverbSettings& settings);
    std::expected<void, std::error_code> apply_delay(const AudioProcessingOptions::DelaySettings& settings);
    std::expected<void, std::error_code> apply_chorus(const AudioProcessingOptions::ChorusSettings& settings);
    std::expected<void, std::error_code> apply_distortion(const AudioProcessingOptions::DistortionSettings& settings);
    std::expected<void, std::error_code> apply_noise_reduction(const AudioProcessingOptions::NoiseReductionSettings& settings);
    std::expected<void, std::error_code> apply_auto_tune(const AudioProcessingOptions::AutoTuneSettings& settings);
    std::expected<void, std::error_code> apply_convolution(const AudioProcessingOptions::ConvolutionSettings& settings);
    
    std::expected<void, std::error_code> change_pitch(double semitones, bool preserve_tempo = true);
    std::expected<void, std::error_code> change_tempo(double factor, bool preserve_pitch = true);
    std::expected<void, std::error_code> change_speed(double factor);
    
    std::expected<void, std::error_code> mix(const AudioBuffer& other, double other_gain = 1.0, double self_gain = 1.0);
    std::expected<void, std::error_code> append(const AudioBuffer& other);
    std::expected<void, std::error_code> prepend(const AudioBuffer& other);
    std::expected<void, std::error_code> insert(uint64_t position, const AudioBuffer& other);
    
    std::expected<std::vector<uint8_t>, std::error_code> encode(AudioCodec codec, const AudioProcessingOptions& options = {}) const;
    std::expected<void, std::error_code> decode(std::span<const uint8_t> data, AudioCodec codec);
    
    std::expected<std::vector<float>, std::error_code> compute_spectrum(uint64_t start_sample = 0, uint64_t window_size = 2048) const;
    std::expected<std::vector<std::vector<float>>, std::error_code> compute_spectrogram(uint64_t window_size = 2048, uint64_t hop_size = 512) const;
    std::expected<std::vector<float>, std::error_code> compute_mel_spectrogram(uint32_t n_mels = 128, uint64_t window_size = 2048, uint64_t hop_size = 512) const;
    std::expected<std::vector<std::vector<float>>, std::error_code> compute_mfcc(uint32_t n_mfcc = 13, uint32_t n_mels = 128, uint64_t window_size = 2048, uint64_t hop_size = 512) const;
    std::expected<std::vector<std::vector<float>>, std::error_code> compute_chromagram(uint32_t n_chroma = 12, uint64_t window_size = 2048, uint64_t hop_size = 512) const;
    
    std::expected<double, std::error_code> compute_rms() const;
    std::expected<double, std::error_code> compute_peak() const;
    std::expected<double, std::error_code> compute_lufs() const;
    std::expected<double, std::error_code> compute_dynamic_range() const;
    std::expected<double, std::error_code> compute_crest_factor() const;
    std::expected<double, std::error_code> compute_zero_crossing_rate() const;
    std::expected<double, std::error_code> compute_spectral_centroid() const;
    std::expected<double, std::error_code> compute_spectral_rolloff() const;
    std::expected<double, std::error_code> compute_spectral_bandwidth() const;
    std::expected<double, std::error_code> compute_spectral_flatness() const;
    std::expected<double, std::error_code> compute_spectral_flux() const;
    std::expected<double, std::error_code> compute_tempo() const;
    std::expected<std::vector<double>, std::error_code> detect_beats() const;
    std::expected<std::vector<double>, std::error_code> detect_onsets() const;
    std::expected<std::string, std::error_code> detect_key() const;
    std::expected<std::vector<double>, std::error_code> detect_pitch() const;
    std::expected<std::vector<std::pair<uint64_t, uint64_t>>, std::error_code> detect_silence(double threshold_db = -40.0) const;
    std::expected<std::vector<uint64_t>, std::error_code> detect_clipping(double threshold = 0.99) const;
    std::expected<double, std::error_code> detect_dc_offset() const;
    
    std::expected<void, std::error_code> remove_silence(double threshold_db = -40.0, uint64_t min_duration_ms = 100);
    std::expected<void, std::error_code> remove_dc_offset();
    std::expected<void, std::error_code> remove_clicks();
    std::expected<void, std::error_code> repair_clipping();
    
    std::expected<AudioBuffer, std::error_code> extract_channel(uint32_t channel) const;
    std::expected<AudioBuffer, std::error_code> extract_range(uint64_t start_sample, uint64_t end_sample) const;
    std::expected<AudioBuffer, std::error_code> extract_silence_between(uint64_t start_sample, uint64_t end_sample) const;
    
    std::expected<void, std::error_code> analyze_audio(const AudioProcessingOptions::AnalysisSettings& settings);
    
    bool is_valid() const { return !data_.empty() && sample_rate_ > 0 && channels_ > 0; }
    bool is_silent(double threshold_db = -60.0) const;
    bool has_clipping(double threshold = 0.99) const;
    bool has_dc_offset(double threshold = 0.01) const;
    
private:
    std::vector<std::vector<float>> data_;
    uint32_t sample_rate_ = 0;
    uint32_t channels_ = 0;
    uint64_t sample_count_ = 0;
    AudioMetadata metadata_;
    
    void interleave_channels();
    void deinterleave_channels();
    std::expected<void, std::error_code> apply_window(std::vector<float>& data, const std::string& window_type) const;
    std::expected<std::vector<std::complex<float>>, std::error_code> compute_fft(const std::vector<float>& data) const;
    std::expected<std::vector<float>, std::error_code> compute_ifft(const std::vector<std::complex<float>>& data) const;
};

class AudioConverter : public core::ConversionTask<AudioBuffer, AudioBuffer> {
public:
    AudioConverter(AudioBuffer input, core::ConversionOptions options, AudioProcessingOptions processing_options = {});
    
    result_type execute() override;
    std::future<result_type> execute_async() override;
    std::generator<result_type> execute_stream() override;
    
    bool validate_input() const override;
    bool can_convert() const override;
    std::string get_format_info() const override;
    std::size_t estimate_output_size() const override;
    std::chrono::milliseconds estimate_duration() const override;
    
    void set_target_codec(AudioCodec codec) { target_codec_ = codec; }
    void set_processing_options(const AudioProcessingOptions& options) { processing_options_ = options; }
    
    static std::expected<AudioBuffer, std::error_code> load_from_file(const std::string& filename);
    static std::expected<void, std::error_code> save_to_file(const AudioBuffer& audio, const std::string& filename, const AudioProcessingOptions& options = {});
    
    static std::expected<std::vector<AudioBuffer>, std::error_code> batch_convert(
        const std::vector<std::string>& input_files,
        const std::string& output_directory,
        AudioCodec target_codec,
        const AudioProcessingOptions& options = {}
    );
    
    static std::expected<AudioBuffer, std::error_code> mix_multiple(const std::vector<AudioBuffer>& tracks, const std::vector<double>& gains = {});
    static std::expected<AudioBuffer, std::error_code> concatenate_multiple(const std::vector<AudioBuffer>& tracks, double crossfade_duration = 0.0);
    
    static std::expected<void, std::error_code> create_multitrack_session(const std::vector<AudioBuffer>& tracks, const std::string& output_file);
    static std::expected<std::vector<AudioBuffer>, std::error_code> split_by_chapters(const AudioBuffer& audio);
    static std::expected<std::vector<AudioBuffer>, std::error_code> split_by_silence(const AudioBuffer& audio, double threshold_db = -40.0);
    static std::expected<std::vector<AudioBuffer>, std::error_code> split_by_duration(const AudioBuffer& audio, double duration_seconds = 600.0);
    
    static std::expected<void, std::error_code> extract_vocals(const AudioBuffer& audio, const std::string& output_file);
    static std::expected<void, std::error_code> extract_instruments(const AudioBuffer& audio, const std::string& output_file);
    static std::expected<void, std::error_code> create_karaoke_version(const AudioBuffer& audio, const std::string& output_file);
    
    static std::expected<void, std::error_code> master_audio(const AudioBuffer& audio, const std::string& output_file, const AudioProcessingOptions& options = {});
    static std::expected<void, std::error_code> create_stems(const AudioBuffer& audio, const std::string& output_directory);
    
    static std::expected<void, std::error_code> sync_audio_to_video(const std::string& audio_file, const std::string& video_file, const std::string& output_file);
    static std::expected<void, std::error_code> generate_silence(double duration_seconds, uint32_t sample_rate, uint32_t channels, const std::string& output_file);
    static std::expected<void, std::error_code> generate_tone(double frequency, double duration_seconds, uint32_t sample_rate, const std::string& output_file);
    static std::expected<void, std::error_code> generate_noise(const std::string& noise_type, double duration_seconds, uint32_t sample_rate, const std::string& output_file);
    static std::expected<void, std::error_code> generate_sweep(double start_frequency, double end_frequency, double duration_seconds, uint32_t sample_rate, const std::string& output_file);
    
    static std::expected<void, std::error_code> create_podcast_intro(const std::vector<std::string>& audio_files, const std::string& output_file);
    static std::expected<void, std::error_code> create_radio_jingle(const std::vector<std::string>& audio_files, const std::string& output_file);
    static std::expected<void, std::error_code> create_audiobook_chapter(const std::vector<std::string>& audio_files, const std::string& output_file);
    
    static std::expected<void, std::error_code> live_stream_audio(const std::string& input_source, const std::string& output_url, const AudioProcessingOptions& options = {});
    static std::expected<void, std::error_code> record_microphone(const std::string& output_file, int device_index = 0, double duration_seconds = 0.0);
    static std::expected<void, std::error_code> record_system_audio(const std::string& output_file, double duration_seconds = 0.0);
    
    static std::vector<AudioCodec> get_supported_input_codecs();
    static std::vector<AudioCodec> get_supported_output_codecs();
    static std::vector<std::string> get_supported_formats();
    static std::vector<std::string> get_audio_devices();
    static bool is_codec_supported(AudioCodec codec);
    static bool is_format_supported(const std::string& format);
    
    static std::expected<AudioMetadata, std::error_code> get_audio_info(const std::string& filename);
    static std::expected<std::vector<uint8_t>, std::error_code> get_album_art(const std::string& filename);
    static std::expected<void, std::error_code> set_album_art(const std::string& filename, const std::vector<uint8_t>& image_data, const std::string& mime_type = "image/jpeg");
    
    static std::expected<void, std::error_code> create_cue_sheet(const std::vector<std::string>& audio_files, const std::string& output_file);
    static std::expected<void, std::error_code> create_playlist(const std::vector<std::string>& audio_files, const std::string& output_file, const std::string& format = "m3u");
    
    static std::expected<void, std::error_code> verify_audio_integrity(const std::string& filename);
    static std::expected<std::string, std::error_code> calculate_audio_fingerprint(const std::string& filename);
    static std::expected<void, std::error_code> compare_audio_files(const std::string& file1, const std::string& file2);
    
private:
    AudioCodec target_codec_ = AudioCodec::FLAC;
    AudioProcessingOptions processing_options_;
    
    std::expected<AudioBuffer, std::error_code> apply_processing(const AudioBuffer& input) const;
    std::expected<std::vector<uint8_t>, std::error_code> encode_audio(const AudioBuffer& audio) const;
    std::expected<AudioBuffer, std::error_code> decode_audio(std::span<const uint8_t> data) const;
    
    static std::unordered_map<AudioCodec, std::string> codec_extensions_;
    static std::unordered_map<AudioCodec, std::vector<std::string>> codec_mime_types_;
    static bool is_initialized_;
    static void initialize_codec_support();
};

} 