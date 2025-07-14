#pragma once

#include "../../core/converter_engine.hpp"
#include "../../core/format_types.hpp"
#include <memory>
#include <vector>
#include <string>
#include <unordered_map>
#include <expected>
#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_OUTLINE_H
#include FT_GLYPH_H
#include FT_BITMAP_H

namespace converter::modules::font {

enum class FontFormat {
    TTF, OTF, WOFF, WOFF2, EOT, SVG_FONT,
    TYPE1, PFB, PFA, AFM, PFM, CFF, CID,
    BITMAP_BDF, BITMAP_PCF, BITMAP_FNT, BITMAP_FON,
    VECTOR_PS, VECTOR_EPS, VECTOR_PDF, VECTOR_SVG,
    WEB_WOFF, WEB_WOFF2, WEB_EOT, WEB_CSS,
    MOBILE_AAR, MOBILE_IOS, MOBILE_ANDROID,
    GAME_BMF, GAME_FNT, GAME_ANGEL_CODE,
    PRINT_PFB, PRINT_AFM, PRINT_METRICS,
    SYSTEM_LINUX, SYSTEM_WINDOWS, SYSTEM_MAC,
    EMBEDDED_C_ARRAY, EMBEDDED_BINARY, EMBEDDED_BASE64
};

enum class FontType {
    TrueType, OpenType, PostScript, Bitmap,
    Variable, Color, Emoji, Symbol, Icon,
    Display, Text, Monospace, Script, Decorative,
    Sans_Serif, Serif, Handwriting, Condensed, Extended
};

enum class RenderingMode {
    Bitmap, Vector, SDF, MSDF, Outline, Filled,
    Antialiased, Subpixel, Grayscale, Monochrome,
    ClearType, LCD, Hinted, Unhinted
};

enum class HintingMode {
    None, Slight, Medium, Full, Auto, Custom,
    Vertical, Horizontal, Both, TrueType, PostScript
};

struct FontMetrics {
    float ascender;
    float descender;
    float line_height;
    float max_advance_width;
    float max_advance_height;
    float underline_position;
    float underline_thickness;
    float strikethrough_position;
    float strikethrough_thickness;
    float x_height;
    float cap_height;
    float em_size;
    std::array<float, 4> bounding_box;
};

struct GlyphMetrics {
    uint32_t codepoint;
    uint32_t glyph_index;
    float advance_width;
    float advance_height;
    float left_side_bearing;
    float right_side_bearing;
    float top_side_bearing;
    float bottom_side_bearing;
    std::array<float, 4> bounding_box;
    std::vector<std::array<float, 2>> contour_points;
    std::vector<uint8_t> contour_tags;
    std::vector<uint16_t> contour_ends;
    std::vector<uint8_t> bitmap_data;
    uint32_t bitmap_width;
    uint32_t bitmap_height;
    int32_t bitmap_left;
    int32_t bitmap_top;
    uint32_t bitmap_pitch;
    std::string svg_path;
    std::vector<uint8_t> sdf_data;
    uint32_t sdf_width;
    uint32_t sdf_height;
    float sdf_range;
};

struct KerningPair {
    uint32_t left_glyph;
    uint32_t right_glyph;
    float kerning_value;
};

struct FontFeature {
    std::string tag;
    std::string name;
    std::string description;
    bool enabled;
    std::vector<std::pair<uint32_t, uint32_t>> substitutions;
    std::vector<std::pair<std::vector<uint32_t>, uint32_t>> ligatures;
    std::vector<std::pair<uint32_t, std::array<float, 2>>> positioning;
};

struct FontVariation {
    std::string tag;
    std::string name;
    float min_value;
    float default_value;
    float max_value;
    float current_value;
    std::string unit;
    std::string description;
};

struct ColorLayer {
    uint32_t glyph_id;
    uint32_t color_id;
    std::array<uint8_t, 4> color_rgba;
    float opacity;
    std::string blend_mode;
};

struct ColorPalette {
    std::string name;
    std::vector<std::array<uint8_t, 4>> colors;
    bool is_dark_theme;
    bool is_light_theme;
    std::unordered_map<std::string, std::string> metadata;
};

struct FontMetadata {
    std::string family_name;
    std::string subfamily_name;
    std::string full_name;
    std::string postscript_name;
    std::string version;
    std::string copyright;
    std::string trademark;
    std::string manufacturer;
    std::string designer;
    std::string description;
    std::string vendor_url;
    std::string designer_url;
    std::string license;
    std::string license_url;
    std::string sample_text;
    std::string style_name;
    std::string weight_name;
    std::string width_name;
    std::string slope_name;
    FontType font_type;
    FontFormat format;
    uint32_t glyph_count;
    uint32_t character_count;
    uint32_t language_count;
    uint32_t feature_count;
    uint32_t variation_count;
    uint32_t palette_count;
    std::vector<std::string> supported_languages;
    std::vector<std::string> supported_scripts;
    std::vector<std::pair<uint32_t, uint32_t>> unicode_ranges;
    std::vector<std::string> opentype_features;
    std::vector<std::string> variation_axes;
    bool has_kerning;
    bool has_ligatures;
    bool has_alternates;
    bool has_small_caps;
    bool has_old_style_figures;
    bool has_tabular_figures;
    bool has_fractions;
    bool has_superscript;
    bool has_subscript;
    bool is_monospace;
    bool is_variable;
    bool is_color;
    bool is_bitmap;
    bool is_scalable;
    bool is_bold;
    bool is_italic;
    bool is_condensed;
    bool is_extended;
    bool is_outline;
    bool is_embeddable;
    bool is_subsettable;
    uint16_t weight;
    uint16_t width;
    int16_t slope;
    uint16_t optical_size;
    float units_per_em;
    FontMetrics metrics;
    std::unordered_map<std::string, std::string> custom_properties;
    std::string creation_date;
    std::string modification_date;
    std::string checksum;
    std::size_t file_size;
};

struct FontOptions {
    std::optional<std::vector<uint32_t>> subset_codepoints;
    std::optional<std::vector<std::string>> subset_characters;
    std::optional<std::vector<std::string>> subset_languages;
    std::optional<std::vector<std::string>> subset_features;
    std::optional<bool> remove_unused_glyphs;
    std::optional<bool> remove_hinting;
    std::optional<bool> optimize_tables;
    std::optional<bool> compress_tables;
    std::optional<std::string> compression_algorithm;
    std::optional<int> compression_level;
    std::optional<bool> decompile_bytecode;
    std::optional<bool> remove_overlaps;
    std::optional<bool> simplify_curves;
    std::optional<float> simplification_tolerance;
    std::optional<bool> normalize_glyphs;
    std::optional<bool> optimize_outlines;
    std::optional<bool> round_coordinates;
    std::optional<float> coordinate_precision;
    std::optional<bool> drop_empty_glyphs;
    std::optional<bool> recalculate_bounds;
    std::optional<bool> recalculate_metrics;
    std::optional<bool> update_checksums;
    std::optional<std::string> new_family_name;
    std::optional<std::string> new_style_name;
    std::optional<std::string> new_version;
    std::optional<std::string> new_copyright;
    std::optional<std::string> new_vendor;
    std::optional<std::string> new_designer;
    std::optional<std::string> new_license;
    std::optional<bool> embed_bitmap;
    std::optional<std::vector<uint32_t>> bitmap_sizes;
    std::optional<RenderingMode> bitmap_rendering;
    std::optional<HintingMode> bitmap_hinting;
    std::optional<bool> generate_sdf;
    std::optional<uint32_t> sdf_size;
    std::optional<float> sdf_range;
    std::optional<uint32_t> sdf_padding;
    std::optional<bool> generate_msdf;
    std::optional<uint32_t> msdf_size;
    std::optional<float> msdf_range;
    std::optional<uint32_t> msdf_padding;
    std::optional<bool> generate_atlas;
    std::optional<uint32_t> atlas_width;
    std::optional<uint32_t> atlas_height;
    std::optional<uint32_t> atlas_padding;
    std::optional<std::string> atlas_format;
    std::optional<bool> pack_glyphs;
    std::optional<std::string> packing_algorithm;
    std::optional<bool> merge_duplicates;
    std::optional<bool> sort_glyphs;
    std::optional<std::string> sort_order;
    std::optional<bool> add_fallback_glyphs;
    std::optional<std::vector<uint32_t>> fallback_codepoints;
    std::optional<bool> generate_web_fonts;
    std::optional<std::vector<FontFormat>> web_formats;
    std::optional<bool> generate_css;
    std::optional<std::string> css_font_family;
    std::optional<std::string> css_font_display;
    std::optional<std::vector<std::string>> css_unicode_ranges;
    std::optional<bool> preload_hint;
    std::optional<bool> font_feature_settings;
    std::optional<std::vector<std::string>> enabled_features;
    std::optional<bool> variable_font_instance;
    std::optional<std::unordered_map<std::string, float>> variation_settings;
    std::optional<bool> optimize_variable_font;
    std::optional<bool> split_variable_axes;
    std::optional<std::vector<std::string>> axes_to_split;
    std::optional<bool> color_font_conversion;
    std::optional<std::string> color_format;
    std::optional<std::vector<uint32_t>> palette_indices;
    std::optional<bool> svg_to_outlines;
    std::optional<float> svg_precision;
    std::optional<bool> bitmap_to_outlines;
    std::optional<std::string> tracing_algorithm;
    std::optional<float> tracing_threshold;
    std::optional<bool> autohint;
    std::optional<std::string> hinting_engine;
    std::optional<HintingMode> hinting_mode;
    std::optional<bool> grid_fitting;
    std::optional<bool> cleartype_hinting;
    std::optional<bool> stem_darkening;
    std::optional<float> stem_darkening_amount;
    std::optional<bool> embolden;
    std::optional<float> embolden_strength;
    std::optional<bool> oblique;
    std::optional<float> oblique_angle;
    std::optional<bool> expand;
    std::optional<float> expand_amount;
    std::optional<bool> condense;
    std::optional<float> condense_amount;
    std::optional<bool> add_outline;
    std::optional<float> outline_width;
    std::optional<std::array<uint8_t, 4>> outline_color;
    std::optional<bool> add_shadow;
    std::optional<std::array<float, 2>> shadow_offset;
    std::optional<float> shadow_blur;
    std::optional<std::array<uint8_t, 4>> shadow_color;
    std::optional<bool> add_glow;
    std::optional<float> glow_radius;
    std::optional<std::array<uint8_t, 4>> glow_color;
    std::optional<bool> transform_glyphs;
    std::optional<std::array<float, 6>> transformation_matrix;
    std::optional<bool> mirror_horizontal;
    std::optional<bool> mirror_vertical;
    std::optional<float> rotation_angle;
    std::optional<std::array<float, 2>> scale_factors;
    std::optional<std::array<float, 2>> translation;
    std::optional<bool> perspective_transform;
    std::optional<std::array<float, 8>> perspective_matrix;
    std::optional<bool> validate_font;
    std::optional<bool> repair_font;
    std::optional<bool> sanitize_font;
    std::optional<bool> verify_checksums;
    std::optional<bool> fix_metrics;
    std::optional<bool> fix_encoding;
    std::optional<bool> fix_names;
    std::optional<bool> fix_kerning;
    std::optional<bool> fix_features;
    std::optional<std::string> target_platform;
    std::optional<std::string> target_application;
    std::optional<std::vector<std::string>> compatibility_modes;
    std::optional<bool> legacy_support;
    std::optional<bool> modern_features;
    std::optional<std::string> output_encoding;
    std::optional<std::string> output_format_version;
    std::optional<bool> binary_format;
    std::optional<bool> ascii_format;
    std::optional<bool> xml_format;
    std::optional<bool> json_format;
    std::optional<bool> pretty_print;
    std::optional<std::size_t> indent_size;
    std::optional<bool> include_metadata;
    std::optional<bool> include_metrics;
    std::optional<bool> include_kerning;
    std::optional<bool> include_features;
    std::optional<bool> include_variations;
    std::optional<bool> include_palettes;
    std::optional<std::vector<std::string>> tables_to_include;
    std::optional<std::vector<std::string>> tables_to_exclude;
    std::optional<std::unordered_map<std::string, std::string>> custom_parameters;
};

class FontBuffer {
public:
    FontBuffer();
    FontBuffer(const std::string& filename);
    FontBuffer(std::vector<uint8_t> data, FontFormat format);
    ~FontBuffer();
    
    std::expected<void, std::error_code> load_from_file(const std::string& filename);
    std::expected<void, std::error_code> load_from_memory(std::span<const uint8_t> data, FontFormat format);
    std::expected<void, std::error_code> save_to_file(const std::string& filename, const FontOptions& options = {});
    std::expected<std::vector<uint8_t>, std::error_code> save_to_memory(FontFormat format, const FontOptions& options = {});
    
    const FontMetadata& metadata() const { return metadata_; }
    FontMetadata& metadata() { return metadata_; }
    
    const std::vector<GlyphMetrics>& glyphs() const { return glyphs_; }
    std::vector<GlyphMetrics>& glyphs() { return glyphs_; }
    
    const std::vector<KerningPair>& kerning_pairs() const { return kerning_pairs_; }
    std::vector<KerningPair>& kerning_pairs() { return kerning_pairs_; }
    
    const std::vector<FontFeature>& features() const { return features_; }
    std::vector<FontFeature>& features() { return features_; }
    
    const std::vector<FontVariation>& variations() const { return variations_; }
    std::vector<FontVariation>& variations() { return variations_; }
    
    const std::vector<ColorPalette>& palettes() const { return palettes_; }
    std::vector<ColorPalette>& palettes() { return palettes_; }
    
    std::expected<uint32_t, std::error_code> get_glyph_index(uint32_t codepoint);
    std::expected<GlyphMetrics, std::error_code> get_glyph_metrics(uint32_t glyph_index);
    std::expected<std::vector<uint8_t>, std::error_code> render_glyph(uint32_t glyph_index, uint32_t size, RenderingMode mode = RenderingMode::Antialiased);
    std::expected<std::vector<uint8_t>, std::error_code> render_text(const std::string& text, uint32_t size, RenderingMode mode = RenderingMode::Antialiased);
    
    std::expected<void, std::error_code> subset_font(const std::vector<uint32_t>& codepoints);
    std::expected<void, std::error_code> subset_by_language(const std::string& language);
    std::expected<void, std::error_code> subset_by_text(const std::string& text);
    std::expected<void, std::error_code> subset_by_frequency(const std::unordered_map<uint32_t, float>& frequencies, float threshold = 0.01f);
    
    std::expected<void, std::error_code> optimize_font();
    std::expected<void, std::error_code> remove_unused_glyphs();
    std::expected<void, std::error_code> remove_hinting();
    std::expected<void, std::error_code> optimize_tables();
    std::expected<void, std::error_code> compress_font();
    std::expected<void, std::error_code> decompress_font();
    
    std::expected<void, std::error_code> merge_fonts(const std::vector<FontBuffer>& other_fonts);
    std::expected<std::vector<FontBuffer>, std::error_code> split_font(const std::string& split_method = "language");
    std::expected<void, std::error_code> extract_subset(const std::vector<uint32_t>& codepoints, FontBuffer& subset);
    
    std::expected<void, std::error_code> convert_format(FontFormat target_format, const FontOptions& options = {});
    std::expected<void, std::error_code> convert_to_web_fonts(const std::vector<FontFormat>& formats, const std::string& output_directory, const FontOptions& options = {});
    std::expected<void, std::error_code> generate_css(const std::string& css_file, const FontOptions& options = {});
    
    std::expected<void, std::error_code> generate_bitmap_fonts(const std::vector<uint32_t>& sizes, const std::string& output_directory, const FontOptions& options = {});
    std::expected<void, std::error_code> generate_sdf_font(uint32_t size, float range, const std::string& output_file, const FontOptions& options = {});
    std::expected<void, std::error_code> generate_msdf_font(uint32_t size, float range, const std::string& output_file, const FontOptions& options = {});
    std::expected<void, std::error_code> generate_atlas(uint32_t width, uint32_t height, const std::string& output_file, const FontOptions& options = {});
    
    std::expected<void, std::error_code> apply_variation_settings(const std::unordered_map<std::string, float>& settings);
    std::expected<FontBuffer, std::error_code> create_instance(const std::unordered_map<std::string, float>& settings);
    std::expected<void, std::error_code> interpolate_instances(const std::vector<std::pair<FontBuffer, float>>& instances);
    
    std::expected<void, std::error_code> enable_features(const std::vector<std::string>& feature_tags);
    std::expected<void, std::error_code> disable_features(const std::vector<std::string>& feature_tags);
    std::expected<void, std::error_code> apply_feature_settings(const std::unordered_map<std::string, bool>& settings);
    
    std::expected<void, std::error_code> add_kerning_pair(uint32_t left_glyph, uint32_t right_glyph, float kerning_value);
    std::expected<void, std::error_code> remove_kerning_pair(uint32_t left_glyph, uint32_t right_glyph);
    std::expected<void, std::error_code> optimize_kerning();
    std::expected<void, std::error_code> auto_kern();
    
    std::expected<void, std::error_code> add_glyph(const GlyphMetrics& glyph);
    std::expected<void, std::error_code> remove_glyph(uint32_t glyph_index);
    std::expected<void, std::error_code> modify_glyph(uint32_t glyph_index, const GlyphMetrics& new_glyph);
    std::expected<void, std::error_code> duplicate_glyph(uint32_t source_index, uint32_t target_codepoint);
    
    std::expected<void, std::error_code> simplify_outlines(float tolerance = 1.0f);
    std::expected<void, std::error_code> remove_overlaps();
    std::expected<void, std::error_code> normalize_glyphs();
    std::expected<void, std::error_code> round_coordinates();
    std::expected<void, std::error_code> scale_glyphs(float scale_factor);
    
    std::expected<void, std::error_code> embolden_font(float strength = 0.5f);
    std::expected<void, std::error_code> oblique_font(float angle = 15.0f);
    std::expected<void, std::error_code> condense_font(float factor = 0.8f);
    std::expected<void, std::error_code> expand_font(float factor = 1.2f);
    
    std::expected<void, std::error_code> add_outline(float width, const std::array<uint8_t, 4>& color = {0, 0, 0, 255});
    std::expected<void, std::error_code> add_shadow(const std::array<float, 2>& offset, float blur = 2.0f, const std::array<uint8_t, 4>& color = {0, 0, 0, 128});
    std::expected<void, std::error_code> add_glow(float radius = 3.0f, const std::array<uint8_t, 4>& color = {255, 255, 255, 128});
    
    std::expected<void, std::error_code> transform_glyphs(const std::array<float, 6>& matrix);
    std::expected<void, std::error_code> rotate_glyphs(float angle);
    std::expected<void, std::error_code> skew_glyphs(float x_angle, float y_angle = 0.0f);
    std::expected<void, std::error_code> perspective_transform(const std::array<float, 8>& matrix);
    
    std::expected<void, std::error_code> auto_hint();
    std::expected<void, std::error_code> apply_hinting(HintingMode mode);
    std::expected<void, std::error_code> remove_hinting_instructions();
    std::expected<void, std::error_code> optimize_hinting();
    
    std::expected<void, std::error_code> update_metrics();
    std::expected<void, std::error_code> recalculate_bounds();
    std::expected<void, std::error_code> fix_metrics();
    std::expected<void, std::error_code> normalize_metrics();
    
    std::expected<void, std::error_code> validate_font(std::vector<std::string>& errors, std::vector<std::string>& warnings);
    std::expected<void, std::error_code> repair_font();
    std::expected<void, std::error_code> sanitize_font();
    std::expected<void, std::error_code> verify_checksums();
    
    std::expected<void, std::error_code> analyze_coverage(std::unordered_map<std::string, float>& coverage_stats);
    std::expected<void, std::error_code> analyze_quality(std::unordered_map<std::string, float>& quality_metrics);
    std::expected<void, std::error_code> detect_duplicates(std::vector<std::pair<uint32_t, uint32_t>>& duplicates);
    
    std::expected<void, std::error_code> create_color_font(const std::vector<ColorLayer>& layers, const std::vector<ColorPalette>& palettes);
    std::expected<void, std::error_code> extract_color_layers(std::vector<ColorLayer>& layers);
    std::expected<void, std::error_code> modify_color_palette(uint32_t palette_index, const ColorPalette& new_palette);
    
    std::expected<void, std::error_code> svg_to_outlines();
    std::expected<void, std::error_code> bitmap_to_outlines(const std::string& tracing_algorithm = "potrace");
    std::expected<void, std::error_code> outlines_to_bitmap(uint32_t size, RenderingMode mode = RenderingMode::Antialiased);
    
    std::expected<void, std::error_code> create_variable_font(const std::vector<FontBuffer>& masters, const std::vector<FontVariation>& axes);
    std::expected<std::vector<FontBuffer>, std::error_code> extract_variable_instances();
    std::expected<void, std::error_code> optimize_variable_data();
    
    std::expected<void, std::error_code> add_ligatures(const std::vector<std::vector<uint32_t>>& character_sequences, const std::vector<uint32_t>& ligature_glyphs);
    std::expected<void, std::error_code> remove_ligatures();
    std::expected<void, std::error_code> auto_generate_ligatures();
    
    std::expected<void, std::error_code> add_alternates(uint32_t base_glyph, const std::vector<uint32_t>& alternate_glyphs);
    std::expected<void, std::error_code> remove_alternates(uint32_t base_glyph);
    std::expected<void, std::error_code> randomize_alternates();
    
    std::expected<void, std::error_code> create_small_caps(float scale_factor = 0.75f);
    std::expected<void, std::error_code> create_old_style_figures();
    std::expected<void, std::error_code> create_tabular_figures();
    std::expected<void, std::error_code> create_fractions();
    std::expected<void, std::error_code> create_superscript();
    std::expected<void, std::error_code> create_subscript();
    
    std::expected<void, std::error_code> generate_missing_glyphs(const std::vector<uint32_t>& codepoints);
    std::expected<void, std::error_code> interpolate_missing_weights(const std::vector<FontBuffer>& reference_fonts);
    std::expected<void, std::error_code> extrapolate_weights(const FontBuffer& light_font, const FontBuffer& bold_font);
    
    std::expected<void, std::error_code> match_metrics_to_font(const FontBuffer& reference_font);
    std::expected<void, std::error_code> harmonize_with_family(const std::vector<FontBuffer>& family_fonts);
    std::expected<void, std::error_code> optimize_for_platform(const std::string& platform);
    
    std::expected<void, std::error_code> embed_metadata(const std::unordered_map<std::string, std::string>& metadata);
    std::expected<void, std::error_code> strip_metadata();
    std::expected<void, std::error_code> update_names(const std::unordered_map<std::string, std::string>& new_names);
    
    std::expected<void, std::error_code> create_preview_images(const std::vector<std::string>& sample_texts, const std::string& output_directory, const FontOptions& options = {});
    std::expected<void, std::error_code> generate_character_map(const std::string& output_file, const FontOptions& options = {});
    std::expected<void, std::error_code> create_specimen_sheet(const std::string& output_file, const FontOptions& options = {});
    
    bool is_valid() const { return !glyphs_.empty(); }
    FontFormat get_format() const { return format_; }
    std::size_t get_glyph_count() const { return glyphs_.size(); }
    std::size_t get_character_count() const;
    bool has_kerning() const { return !kerning_pairs_.empty(); }
    bool has_ligatures() const;
    bool has_features() const { return !features_.empty(); }
    bool is_variable() const { return !variations_.empty(); }
    bool is_color() const { return !palettes_.empty(); }
    bool is_monospace() const { return metadata_.is_monospace; }
    
private:
    std::vector<GlyphMetrics> glyphs_;
    std::vector<KerningPair> kerning_pairs_;
    std::vector<FontFeature> features_;
    std::vector<FontVariation> variations_;
    std::vector<ColorPalette> palettes_;
    std::vector<ColorLayer> color_layers_;
    FontFormat format_;
    FontMetadata metadata_;
    
    FT_Library ft_library_;
    FT_Face ft_face_;
    
    std::expected<void, std::error_code> detect_format(const std::string& filename);
    std::expected<void, std::error_code> parse_font_data();
    std::expected<void, std::error_code> initialize_freetype();
    std::expected<void, std::error_code> cleanup_freetype();
    
    class FontEngine;
    std::unique_ptr<FontEngine> engine_;
};

class FontConverter : public converter::core::ConversionTask<FontBuffer, FontBuffer> {
public:
    FontConverter(FontBuffer input, converter::core::ConversionOptions options, FontOptions processing_options = {});
    
    result_type execute() override;
    std::future<result_type> execute_async() override;
    std::generator<result_type> execute_stream() override;
    
    bool validate_input() const override;
    bool can_convert() const override;
    std::string get_format_info() const override;
    std::size_t estimate_output_size() const override;
    std::chrono::milliseconds estimate_duration() const override;
    
    void set_target_format(FontFormat format) { target_format_ = format; }
    void set_processing_options(const FontOptions& options) { processing_options_ = options; }
    
    static std::expected<FontBuffer, std::error_code> load_from_file(const std::string& filename);
    static std::expected<void, std::error_code> save_to_file(const FontBuffer& font, const std::string& filename, const FontOptions& options = {});
    
    static std::expected<std::vector<FontBuffer>, std::error_code> batch_convert(
        const std::vector<std::string>& input_files,
        const std::string& output_directory,
        FontFormat target_format,
        const FontOptions& options = {}
    );
    
    static std::expected<void, std::error_code> ttf_to_woff(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    static std::expected<void, std::error_code> ttf_to_woff2(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    static std::expected<void, std::error_code> otf_to_ttf(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    static std::expected<void, std::error_code> ttf_to_otf(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    static std::expected<void, std::error_code> ttf_to_eot(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    
    static std::expected<void, std::error_code> create_web_font_kit(const std::string& input_file, const std::string& output_directory, const FontOptions& options = {});
    static std::expected<void, std::error_code> generate_font_css(const std::string& font_file, const std::string& css_file, const FontOptions& options = {});
    static std::expected<void, std::error_code> optimize_web_fonts(const std::vector<std::string>& font_files, const std::string& output_directory, const FontOptions& options = {});
    
    static std::expected<void, std::error_code> subset_font_for_text(const std::string& input_file, const std::string& output_file, const std::string& text, const FontOptions& options = {});
    static std::expected<void, std::error_code> subset_font_for_language(const std::string& input_file, const std::string& output_file, const std::string& language, const FontOptions& options = {});
    static std::expected<void, std::error_code> create_font_subsets(const std::string& input_file, const std::string& output_directory, const std::vector<std::string>& languages, const FontOptions& options = {});
    
    static std::expected<void, std::error_code> merge_font_families(const std::vector<std::string>& font_files, const std::string& output_file, const FontOptions& options = {});
    static std::expected<void, std::error_code> split_font_by_scripts(const std::string& input_file, const std::string& output_directory, const FontOptions& options = {});
    static std::expected<void, std::error_code> extract_font_subset(const std::string& input_file, const std::string& output_file, const std::vector<uint32_t>& codepoints, const FontOptions& options = {});
    
    static std::expected<void, std::error_code> convert_bitmap_to_vector(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    static std::expected<void, std::error_code> convert_vector_to_bitmap(const std::string& input_file, const std::string& output_file, const std::vector<uint32_t>& sizes, const FontOptions& options = {});
    static std::expected<void, std::error_code> vectorize_bitmap_font(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    
    static std::expected<void, std::error_code> generate_sdf_atlas(const std::string& input_file, const std::string& output_file, uint32_t size = 512, float range = 4.0f, const FontOptions& options = {});
    static std::expected<void, std::error_code> generate_msdf_atlas(const std::string& input_file, const std::string& output_file, uint32_t size = 512, float range = 4.0f, const FontOptions& options = {});
    static std::expected<void, std::error_code> create_bitmap_atlas(const std::string& input_file, const std::string& output_file, uint32_t size = 1024, const FontOptions& options = {});
    
    static std::expected<void, std::error_code> create_variable_font(const std::vector<std::string>& master_files, const std::string& output_file, const std::vector<FontVariation>& axes, const FontOptions& options = {});
    static std::expected<void, std::error_code> extract_variable_instances(const std::string& input_file, const std::string& output_directory, const std::vector<std::unordered_map<std::string, float>>& instances, const FontOptions& options = {});
    static std::expected<void, std::error_code> optimize_variable_font(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    
    static std::expected<void, std::error_code> add_color_layers(const std::string& input_file, const std::string& output_file, const std::vector<ColorLayer>& layers, const FontOptions& options = {});
    static std::expected<void, std::error_code> extract_color_fonts(const std::string& input_file, const std::string& output_directory, const FontOptions& options = {});
    static std::expected<void, std::error_code> convert_emoji_font(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    
    static std::expected<void, std::error_code> auto_hint_font(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    static std::expected<void, std::error_code> remove_font_hinting(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    static std::expected<void, std::error_code> optimize_font_hinting(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    
    static std::expected<void, std::error_code> add_kerning_pairs(const std::string& input_file, const std::string& output_file, const std::vector<KerningPair>& pairs, const FontOptions& options = {});
    static std::expected<void, std::error_code> optimize_kerning_table(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    static std::expected<void, std::error_code> auto_kern_font(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    
    static std::expected<void, std::error_code> add_opentype_features(const std::string& input_file, const std::string& output_file, const std::vector<FontFeature>& features, const FontOptions& options = {});
    static std::expected<void, std::error_code> remove_opentype_features(const std::string& input_file, const std::string& output_file, const std::vector<std::string>& feature_tags, const FontOptions& options = {});
    static std::expected<void, std::error_code> optimize_opentype_features(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    
    static std::expected<void, std::error_code> repair_corrupted_font(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    static std::expected<void, std::error_code> validate_font_file(const std::string& input_file, const std::string& report_file);
    static std::expected<void, std::error_code> sanitize_font_file(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    
    static std::expected<void, std::error_code> optimize_font_size(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    static std::expected<void, std::error_code> compress_font_tables(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    static std::expected<void, std::error_code> remove_unused_glyphs(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    
    static std::expected<void, std::error_code> create_font_preview(const std::string& input_file, const std::string& output_file, const std::string& sample_text, const FontOptions& options = {});
    static std::expected<void, std::error_code> generate_character_map(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    static std::expected<void, std::error_code> create_font_specimen(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    
    static std::expected<void, std::error_code> analyze_font_coverage(const std::string& input_file, const std::string& report_file, const std::vector<std::string>& languages = {});
    static std::expected<void, std::error_code> compare_font_metrics(const std::string& font1_file, const std::string& font2_file, const std::string& report_file);
    static std::expected<void, std::error_code> font_quality_analysis(const std::string& input_file, const std::string& report_file);
    
    static std::expected<void, std::error_code> convert_legacy_encoding(const std::string& input_file, const std::string& output_file, const std::string& source_encoding, const FontOptions& options = {});
    static std::expected<void, std::error_code> modernize_font_features(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    static std::expected<void, std::error_code> backport_font_features(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    
    static std::expected<void, std::error_code> create_icon_font(const std::vector<std::string>& svg_files, const std::string& output_file, const FontOptions& options = {});
    static std::expected<void, std::error_code> extract_icons_from_font(const std::string& input_file, const std::string& output_directory, const FontOptions& options = {});
    static std::expected<void, std::error_code> optimize_icon_font(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    
    static std::expected<void, std::error_code> create_monospace_variant(const std::string& input_file, const std::string& output_file, const FontOptions& options = {});
    static std::expected<void, std::error_code> create_condensed_variant(const std::string& input_file, const std::string& output_file, float factor = 0.8f, const FontOptions& options = {});
    static std::expected<void, std::error_code> create_extended_variant(const std::string& input_file, const std::string& output_file, float factor = 1.2f, const FontOptions& options = {});
    
    static std::expected<void, std::error_code> match_font_to_sample(const std::string& sample_image, const std::string& output_file, const std::vector<std::string>& candidate_fonts = {});
    static std::expected<void, std::error_code> interpolate_font_weights(const std::string& light_font, const std::string& bold_font, const std::string& output_file, float weight_factor = 0.5f);
    static std::expected<void, std::error_code> extrapolate_font_weight(const std::string& regular_font, const std::string& bold_font, const std::string& output_file, float weight_factor = 1.5f);
    
    static std::vector<FontFormat> get_supported_input_formats();
    static std::vector<FontFormat> get_supported_output_formats();
    static bool is_format_supported(FontFormat format);
    static bool is_web_font_format(FontFormat format);
    static bool is_bitmap_format(FontFormat format);
    static bool supports_variable_fonts(FontFormat format);
    static bool supports_color_fonts(FontFormat format);
    static std::expected<FontMetadata, std::error_code> get_font_info(const std::string& filename);
    
private:
    FontFormat target_format_ = FontFormat::WOFF2;
    FontOptions processing_options_;
    
    std::expected<FontBuffer, std::error_code> apply_processing(const FontBuffer& input) const;
    std::expected<std::vector<uint8_t>, std::error_code> encode_font(const FontBuffer& font) const;
    std::expected<FontBuffer, std::error_code> decode_font(std::span<const uint8_t> data) const;
    
    static std::unordered_map<FontFormat, std::string> format_extensions_;
    static std::unordered_map<FontFormat, std::vector<std::string>> format_mime_types_;
    static bool is_initialized_;
    static void initialize_font_support();
};

} 