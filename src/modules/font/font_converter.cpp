#include "modules/font/font_converter.hpp"
#include <freetype/freetype.h>
#include <freetype/ftglyph.h>
#include <freetype/ftoutln.h>
#include <freetype/fttrigon.h>
#include <freetype/ftbitmap.h>
#include <freetype/ftmodapi.h>
#include <harfbuzz/hb.h>
#include <harfbuzz/hb-ft.h>
#include <harfbuzz/hb-ot.h>
#include <skia/include/core/SkTypeface.h>
#include <skia/include/core/SkFont.h>
#include <skia/include/core/SkCanvas.h>
#include <skia/include/core/SkSurface.h>
#include <skia/include/core/SkPath.h>
#include <fontconfig/fontconfig.h>
#include <msdfgen/msdfgen.h>
#include <execution>
#include <numeric>
#include <fstream>
#include <codecvt>
#include <locale>

namespace converter::modules::font {

class FontConverter::Impl {
public:
    struct FontState {
        FT_Library ft_library;
        std::unordered_map<std::string, FT_Face> font_faces;
        std::unordered_map<std::string, hb_font_t*> hb_fonts;
        std::unordered_map<std::string, sk_sp<SkTypeface>> sk_typefaces;
        std::unordered_map<std::string, ProcessedFont> font_cache;
        mutable std::shared_mutex mutex;
        FontMetrics metrics;
        FcConfig* fc_config;
    };

    std::unordered_map<std::thread::id, std::unique_ptr<FontState>> thread_states;
    std::shared_mutex states_mutex;
    std::atomic<uint64_t> fonts_processed{0};
    std::atomic<uint64_t> glyphs_processed{0};
    std::atomic<uint64_t> characters_processed{0};
    
    FontState& get_thread_state() {
        std::thread::id tid = std::this_thread::get_id();
        std::shared_lock lock(states_mutex);
        
        if (auto it = thread_states.find(tid); it != thread_states.end()) {
            return *it->second;
        }
        
        lock.unlock();
        std::unique_lock ulock(states_mutex);
        
        auto state = std::make_unique<FontState>();
        
        if (FT_Init_FreeType(&state->ft_library)) {
            throw std::runtime_error("Failed to initialize FreeType library");
        }
        
        state->fc_config = FcInitLoadConfigAndFonts();
        if (!state->fc_config) {
            throw std::runtime_error("Failed to initialize FontConfig");
        }
        
        auto& ref = *state;
        thread_states[tid] = std::move(state);
        return ref;
    }
    
    ProcessedFont load_font(const std::string& font_path) {
        auto& state = get_thread_state();
        
        std::string cache_key = font_path + "_" + std::to_string(std::hash<std::string>{}(font_path));
        
        {
            std::shared_lock lock(state.mutex);
            if (auto it = state.font_cache.find(cache_key); it != state.font_cache.end()) {
                return it->second;
            }
        }
        
        FT_Face face;
        if (FT_New_Face(state.ft_library, font_path.c_str(), 0, &face)) {
            throw std::runtime_error("Failed to load font: " + font_path);
        }
        
        state.font_faces[cache_key] = face;
        
        hb_font_t* hb_font = hb_ft_font_create(face, nullptr);
        state.hb_fonts[cache_key] = hb_font;
        
        auto sk_typeface = SkTypeface::MakeFromFile(font_path.c_str());
        if (!sk_typeface) {
            throw std::runtime_error("Failed to create Skia typeface: " + font_path);
        }
        state.sk_typefaces[cache_key] = sk_typeface;
        
        ProcessedFont processed_font;
        processed_font.family_name = std::string(face->family_name);
        processed_font.style_name = std::string(face->style_name);
        processed_font.num_glyphs = face->num_glyphs;
        processed_font.is_scalable = FT_IS_SCALABLE(face);
        processed_font.is_bold = (face->style_flags & FT_STYLE_FLAG_BOLD) != 0;
        processed_font.is_italic = (face->style_flags & FT_STYLE_FLAG_ITALIC) != 0;
        
        if (face->bbox.xMin != 0 || face->bbox.yMin != 0 || face->bbox.xMax != 0 || face->bbox.yMax != 0) {
            processed_font.bounding_box = {
                static_cast<float>(face->bbox.xMin) / face->units_per_EM,
                static_cast<float>(face->bbox.yMin) / face->units_per_EM,
                static_cast<float>(face->bbox.xMax) / face->units_per_EM,
                static_cast<float>(face->bbox.yMax) / face->units_per_EM
            };
        }
        
        processed_font.units_per_em = face->units_per_EM;
        processed_font.ascender = static_cast<float>(face->ascender) / face->units_per_EM;
        processed_font.descender = static_cast<float>(face->descender) / face->units_per_EM;
        processed_font.height = static_cast<float>(face->height) / face->units_per_EM;
        
        extract_font_metadata(face, processed_font);
        extract_variable_font_axes(face, processed_font);
        
        {
            std::unique_lock lock(state.mutex);
            state.font_cache[cache_key] = processed_font;
        }
        
        return processed_font;
    }
    
    void extract_font_metadata(FT_Face face, ProcessedFont& font) {
        font.metadata.version = get_name_string(face, TT_NAME_ID_VERSION_STRING);
        font.metadata.copyright = get_name_string(face, TT_NAME_ID_COPYRIGHT);
        font.metadata.trademark = get_name_string(face, TT_NAME_ID_TRADEMARK);
        font.metadata.manufacturer = get_name_string(face, TT_NAME_ID_MANUFACTURER);
        font.metadata.designer = get_name_string(face, TT_NAME_ID_DESIGNER);
        font.metadata.description = get_name_string(face, TT_NAME_ID_DESCRIPTION);
        font.metadata.license = get_name_string(face, TT_NAME_ID_LICENSE);
        font.metadata.license_url = get_name_string(face, TT_NAME_ID_LICENSE_URL);
        
        if (FT_IS_SFNT(face)) {
            TT_OS2* os2 = static_cast<TT_OS2*>(FT_Get_Sfnt_Table(face, FT_SFNT_OS2));
            if (os2) {
                font.metadata.weight = os2->usWeightClass;
                font.metadata.width = os2->usWidthClass;
                font.metadata.fsType = os2->fsType;
            }
            
            TT_Header* header = static_cast<TT_Header*>(FT_Get_Sfnt_Table(face, FT_SFNT_HEAD));
            if (header) {
                font.metadata.created = header->Created;
                font.metadata.modified = header->Modified;
            }
        }
    }
    
    void extract_variable_font_axes(FT_Face face, ProcessedFont& font) {
        if (!FT_HAS_MULTIPLE_MASTERS(face)) {
            return;
        }
        
        FT_MM_Var* mm_var = nullptr;
        if (FT_Get_MM_Var(face, &mm_var) == 0) {
            font.variable_axes.reserve(mm_var->num_axis);
            
            for (FT_UInt i = 0; i < mm_var->num_axis; i++) {
                VariableAxis axis;
                axis.tag = mm_var->axis[i].tag;
                axis.name = get_axis_name(axis.tag);
                axis.min_value = mm_var->axis[i].minimum / 65536.0f;
                axis.default_value = mm_var->axis[i].def / 65536.0f;
                axis.max_value = mm_var->axis[i].maximum / 65536.0f;
                
                font.variable_axes.push_back(axis);
            }
            
            FT_Done_MM_Var(face->glyph->library, mm_var);
        }
    }
    
    std::string get_name_string(FT_Face face, FT_UInt name_id) {
        FT_UInt count = FT_Get_Sfnt_Name_Count(face);
        
        for (FT_UInt i = 0; i < count; i++) {
            FT_SfntName name;
            if (FT_Get_Sfnt_Name(face, i, &name) == 0) {
                if (name.name_id == name_id && name.language_id == 0x0409) {
                    std::string result;
                    if (name.encoding_id == 1) {
                        std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
                        result = converter.to_bytes(reinterpret_cast<const char16_t*>(name.string), 
                                                   reinterpret_cast<const char16_t*>(name.string + name.string_len));
                    } else {
                        result = std::string(reinterpret_cast<const char*>(name.string), name.string_len);
                    }
                    return result;
                }
            }
        }
        
        return "";
    }
    
    std::string get_axis_name(FT_ULong tag) {
        switch (tag) {
            case FT_MAKE_TAG('w', 'g', 'h', 't'): return "Weight";
            case FT_MAKE_TAG('w', 'd', 't', 'h'): return "Width";
            case FT_MAKE_TAG('s', 'l', 'n', 't'): return "Slant";
            case FT_MAKE_TAG('i', 't', 'a', 'l'): return "Italic";
            case FT_MAKE_TAG('o', 'p', 's', 'z'): return "Optical Size";
            default: {
                std::string result;
                result.push_back(static_cast<char>((tag >> 24) & 0xFF));
                result.push_back(static_cast<char>((tag >> 16) & 0xFF));
                result.push_back(static_cast<char>((tag >> 8) & 0xFF));
                result.push_back(static_cast<char>(tag & 0xFF));
                return result;
            }
        }
    }
    
    GlyphAtlas generate_glyph_atlas(const ProcessedFont& font, 
                                   const std::string& font_path,
                                   const std::vector<uint32_t>& codepoints,
                                   const AtlasSettings& settings) {
        auto& state = get_thread_state();
        
        std::string cache_key = font_path + "_" + std::to_string(std::hash<std::string>{}(font_path));
        FT_Face face = state.font_faces[cache_key];
        
        if (FT_Set_Pixel_Sizes(face, 0, settings.font_size)) {
            throw std::runtime_error("Failed to set font size");
        }
        
        std::vector<GlyphInfo> glyphs;
        glyphs.reserve(codepoints.size());
        
        int atlas_width = 0;
        int atlas_height = 0;
        
        for (uint32_t codepoint : codepoints) {
            FT_UInt glyph_index = FT_Get_Char_Index(face, codepoint);
            if (glyph_index == 0) continue;
            
            if (FT_Load_Glyph(face, glyph_index, FT_LOAD_DEFAULT)) {
                continue;
            }
            
            if (FT_Render_Glyph(face->glyph, FT_RENDER_MODE_NORMAL)) {
                continue;
            }
            
            FT_GlyphSlot slot = face->glyph;
            
            GlyphInfo glyph;
            glyph.codepoint = codepoint;
            glyph.glyph_index = glyph_index;
            glyph.advance_x = slot->advance.x >> 6;
            glyph.advance_y = slot->advance.y >> 6;
            glyph.bitmap_left = slot->bitmap_left;
            glyph.bitmap_top = slot->bitmap_top;
            glyph.width = slot->bitmap.width;
            glyph.height = slot->bitmap.rows;
            
            if (glyph.width > 0 && glyph.height > 0) {
                glyph.bitmap_data.resize(glyph.width * glyph.height);
                std::memcpy(glyph.bitmap_data.data(), slot->bitmap.buffer, glyph.bitmap_data.size());
            }
            
            glyphs.push_back(glyph);
            
            atlas_width = std::max(atlas_width, static_cast<int>(glyph.width));
            atlas_height += glyph.height + settings.padding;
        }
        
        atlas_width = next_power_of_two(atlas_width + settings.padding * 2);
        atlas_height = next_power_of_two(atlas_height + settings.padding * 2);
        
        GlyphAtlas atlas;
        atlas.width = atlas_width;
        atlas.height = atlas_height;
        atlas.font_size = settings.font_size;
        atlas.padding = settings.padding;
        atlas.texture_data.resize(atlas_width * atlas_height, 0);
        
        int current_x = settings.padding;
        int current_y = settings.padding;
        int row_height = 0;
        
        for (auto& glyph : glyphs) {
            if (current_x + glyph.width + settings.padding > atlas_width) {
                current_x = settings.padding;
                current_y += row_height + settings.padding;
                row_height = 0;
            }
            
            if (current_y + glyph.height + settings.padding > atlas_height) {
                break;
            }
            
            glyph.atlas_x = current_x;
            glyph.atlas_y = current_y;
            glyph.atlas_u = static_cast<float>(current_x) / atlas_width;
            glyph.atlas_v = static_cast<float>(current_y) / atlas_height;
            glyph.atlas_u2 = static_cast<float>(current_x + glyph.width) / atlas_width;
            glyph.atlas_v2 = static_cast<float>(current_y + glyph.height) / atlas_height;
            
            if (!glyph.bitmap_data.empty()) {
                for (int y = 0; y < glyph.height; y++) {
                    for (int x = 0; x < glyph.width; x++) {
                        int atlas_idx = (current_y + y) * atlas_width + (current_x + x);
                        int glyph_idx = y * glyph.width + x;
                        atlas.texture_data[atlas_idx] = glyph.bitmap_data[glyph_idx];
                    }
                }
            }
            
            current_x += glyph.width + settings.padding;
            row_height = std::max(row_height, static_cast<int>(glyph.height));
        }
        
        atlas.glyphs = std::move(glyphs);
        
        return atlas;
    }
    
    GlyphAtlas generate_sdf_atlas(const ProcessedFont& font,
                                 const std::string& font_path,
                                 const std::vector<uint32_t>& codepoints,
                                 const SDFSettings& settings) {
        auto& state = get_thread_state();
        
        std::string cache_key = font_path + "_" + std::to_string(std::hash<std::string>{}(font_path));
        FT_Face face = state.font_faces[cache_key];
        
        if (FT_Set_Pixel_Sizes(face, 0, settings.font_size)) {
            throw std::runtime_error("Failed to set font size");
        }
        
        std::vector<GlyphInfo> glyphs;
        glyphs.reserve(codepoints.size());
        
        int atlas_width = 0;
        int atlas_height = 0;
        
        for (uint32_t codepoint : codepoints) {
            FT_UInt glyph_index = FT_Get_Char_Index(face, codepoint);
            if (glyph_index == 0) continue;
            
            if (FT_Load_Glyph(face, glyph_index, FT_LOAD_NO_BITMAP)) {
                continue;
            }
            
            if (face->glyph->format != FT_GLYPH_FORMAT_OUTLINE) {
                continue;
            }
            
            msdfgen::Shape shape;
            msdfgen::Contour* contour = nullptr;
            
            FT_Outline_Funcs outline_funcs;
            outline_funcs.move_to = move_to_func;
            outline_funcs.line_to = line_to_func;
            outline_funcs.conic_to = conic_to_func;
            outline_funcs.cubic_to = cubic_to_func;
            outline_funcs.shift = 0;
            outline_funcs.delta = 0;
            
            OutlineContext context{&shape, &contour};
            
            if (FT_Outline_Decompose(&face->glyph->outline, &outline_funcs, &context)) {
                continue;
            }
            
            shape.normalize();
            msdfgen::edgeColoringSimple(shape, 3.0);
            
            int sdf_width = settings.font_size + 2 * settings.padding;
            int sdf_height = settings.font_size + 2 * settings.padding;
            
            msdfgen::Bitmap<float, 3> msdf(sdf_width, sdf_height);
            msdfgen::generateMSDF(msdf, shape, settings.range, msdfgen::Vector2(1.0, 1.0), 
                                 msdfgen::Vector2(settings.padding, settings.padding));
            
            GlyphInfo glyph;
            glyph.codepoint = codepoint;
            glyph.glyph_index = glyph_index;
            glyph.advance_x = face->glyph->advance.x >> 6;
            glyph.advance_y = face->glyph->advance.y >> 6;
            glyph.bitmap_left = face->glyph->bitmap_left;
            glyph.bitmap_top = face->glyph->bitmap_top;
            glyph.width = sdf_width;
            glyph.height = sdf_height;
            
            glyph.bitmap_data.resize(sdf_width * sdf_height * 3);
            for (int y = 0; y < sdf_height; y++) {
                for (int x = 0; x < sdf_width; x++) {
                    int idx = (y * sdf_width + x) * 3;
                    msdfgen::FloatRGB pixel = msdf(x, y);
                    glyph.bitmap_data[idx] = static_cast<uint8_t>(std::clamp(pixel.r * 255.0f, 0.0f, 255.0f));
                    glyph.bitmap_data[idx + 1] = static_cast<uint8_t>(std::clamp(pixel.g * 255.0f, 0.0f, 255.0f));
                    glyph.bitmap_data[idx + 2] = static_cast<uint8_t>(std::clamp(pixel.b * 255.0f, 0.0f, 255.0f));
                }
            }
            
            glyphs.push_back(glyph);
            
            atlas_width = std::max(atlas_width, sdf_width);
            atlas_height += sdf_height + settings.padding;
        }
        
        atlas_width = next_power_of_two(atlas_width + settings.padding * 2);
        atlas_height = next_power_of_two(atlas_height + settings.padding * 2);
        
        GlyphAtlas atlas;
        atlas.width = atlas_width;
        atlas.height = atlas_height;
        atlas.font_size = settings.font_size;
        atlas.padding = settings.padding;
        atlas.texture_data.resize(atlas_width * atlas_height * 3, 0);
        
        int current_x = settings.padding;
        int current_y = settings.padding;
        int row_height = 0;
        
        for (auto& glyph : glyphs) {
            if (current_x + glyph.width + settings.padding > atlas_width) {
                current_x = settings.padding;
                current_y += row_height + settings.padding;
                row_height = 0;
            }
            
            if (current_y + glyph.height + settings.padding > atlas_height) {
                break;
            }
            
            glyph.atlas_x = current_x;
            glyph.atlas_y = current_y;
            glyph.atlas_u = static_cast<float>(current_x) / atlas_width;
            glyph.atlas_v = static_cast<float>(current_y) / atlas_height;
            glyph.atlas_u2 = static_cast<float>(current_x + glyph.width) / atlas_width;
            glyph.atlas_v2 = static_cast<float>(current_y + glyph.height) / atlas_height;
            
            for (int y = 0; y < glyph.height; y++) {
                for (int x = 0; x < glyph.width; x++) {
                    int atlas_idx = ((current_y + y) * atlas_width + (current_x + x)) * 3;
                    int glyph_idx = (y * glyph.width + x) * 3;
                    atlas.texture_data[atlas_idx] = glyph.bitmap_data[glyph_idx];
                    atlas.texture_data[atlas_idx + 1] = glyph.bitmap_data[glyph_idx + 1];
                    atlas.texture_data[atlas_idx + 2] = glyph.bitmap_data[glyph_idx + 2];
                }
            }
            
            current_x += glyph.width + settings.padding;
            row_height = std::max(row_height, static_cast<int>(glyph.height));
        }
        
        atlas.glyphs = std::move(glyphs);
        
        return atlas;
    }
    
    std::vector<ShapedGlyph> shape_text(const std::string& text,
                                       const std::string& font_path,
                                       const ShapingSettings& settings) {
        auto& state = get_thread_state();
        
        std::string cache_key = font_path + "_" + std::to_string(std::hash<std::string>{}(font_path));
        hb_font_t* hb_font = state.hb_fonts[cache_key];
        
        hb_buffer_t* buffer = hb_buffer_create();
        hb_buffer_add_utf8(buffer, text.c_str(), -1, 0, -1);
        hb_buffer_set_direction(buffer, settings.direction);
        hb_buffer_set_script(buffer, settings.script);
        hb_buffer_set_language(buffer, hb_language_from_string(settings.language.c_str(), -1));
        
        hb_shape(hb_font, buffer, nullptr, 0);
        
        unsigned int glyph_count = 0;
        hb_glyph_info_t* glyph_info = hb_buffer_get_glyph_infos(buffer, &glyph_count);
        hb_glyph_position_t* glyph_pos = hb_buffer_get_glyph_positions(buffer, &glyph_count);
        
        std::vector<ShapedGlyph> shaped_glyphs;
        shaped_glyphs.reserve(glyph_count);
        
        for (unsigned int i = 0; i < glyph_count; i++) {
            ShapedGlyph shaped;
            shaped.glyph_index = glyph_info[i].codepoint;
            shaped.cluster = glyph_info[i].cluster;
            shaped.x_advance = glyph_pos[i].x_advance / 64.0f;
            shaped.y_advance = glyph_pos[i].y_advance / 64.0f;
            shaped.x_offset = glyph_pos[i].x_offset / 64.0f;
            shaped.y_offset = glyph_pos[i].y_offset / 64.0f;
            
            shaped_glyphs.push_back(shaped);
        }
        
        hb_buffer_destroy(buffer);
        
        return shaped_glyphs;
    }
    
    std::vector<uint8_t> subset_font(const std::string& font_path,
                                    const std::vector<uint32_t>& codepoints,
                                    const SubsetSettings& settings) {
        auto& state = get_thread_state();
        
        std::string cache_key = font_path + "_" + std::to_string(std::hash<std::string>{}(font_path));
        hb_font_t* hb_font = state.hb_fonts[cache_key];
        
        hb_face_t* face = hb_font_get_face(hb_font);
        
        hb_subset_input_t* input = hb_subset_input_create_or_fail();
        if (!input) {
            throw std::runtime_error("Failed to create subset input");
        }
        
        hb_set_t* codepoint_set = hb_subset_input_unicode_set(input);
        for (uint32_t codepoint : codepoints) {
            hb_set_add(codepoint_set, codepoint);
        }
        
        if (settings.retain_gids) {
            hb_subset_input_set_retain_gids(input, true);
        }
        
        if (settings.desubroutinize) {
            hb_subset_input_set_desubroutinize(input, true);
        }
        
        if (settings.name_legacy) {
            hb_subset_input_set_name_legacy(input, true);
        }
        
        if (settings.overlaps_flag) {
            hb_subset_input_set_overlaps_flag(input, true);
        }
        
        if (settings.notdef_outline) {
            hb_subset_input_set_notdef_outline(input, true);
        }
        
        if (settings.no_prune_unicode_ranges) {
            hb_subset_input_set_no_prune_unicode_ranges(input, true);
        }
        
        hb_face_t* subset_face = hb_subset_or_fail(face, input);
        hb_subset_input_destroy(input);
        
        if (!subset_face) {
            throw std::runtime_error("Font subsetting failed");
        }
        
        hb_blob_t* blob = hb_face_reference_blob(subset_face);
        
        unsigned int length = 0;
        const char* data = hb_blob_get_data(blob, &length);
        
        std::vector<uint8_t> subset_data(data, data + length);
        
        hb_blob_destroy(blob);
        hb_face_destroy(subset_face);
        
        return subset_data;
    }
    
    std::vector<uint8_t> convert_to_woff2(const std::vector<uint8_t>& font_data) {
        std::vector<uint8_t> woff2_data;
        
        size_t compressed_size = font_data.size() * 2;
        woff2_data.resize(compressed_size);
        
        bool success = woff2::ConvertTTFToWOFF2(
            font_data.data(), font_data.size(),
            woff2_data.data(), &compressed_size
        );
        
        if (!success) {
            throw std::runtime_error("WOFF2 conversion failed");
        }
        
        woff2_data.resize(compressed_size);
        return woff2_data;
    }
    
    std::vector<uint8_t> convert_from_woff2(const std::vector<uint8_t>& woff2_data) {
        std::vector<uint8_t> font_data;
        
        size_t decompressed_size = woff2_data.size() * 4;
        font_data.resize(decompressed_size);
        
        bool success = woff2::ConvertWOFF2ToTTF(
            woff2_data.data(), woff2_data.size(),
            font_data.data(), &decompressed_size
        );
        
        if (!success) {
            throw std::runtime_error("WOFF2 decompression failed");
        }
        
        font_data.resize(decompressed_size);
        return font_data;
    }
    
    std::vector<FontMatch> find_fonts(const std::string& pattern) {
        auto& state = get_thread_state();
        
        FcPattern* pat = FcNameParse(reinterpret_cast<const FcChar8*>(pattern.c_str()));
        if (!pat) {
            throw std::runtime_error("Invalid font pattern");
        }
        
        FcConfigSubstitute(state.fc_config, pat, FcMatchPattern);
        FcDefaultSubstitute(pat);
        
        FcResult result;
        FcFontSet* fs = FcFontList(state.fc_config, pat, nullptr);
        
        std::vector<FontMatch> matches;
        
        if (fs) {
            for (int i = 0; i < fs->nfont; i++) {
                FcPattern* font = fs->fonts[i];
                
                FontMatch match;
                
                FcChar8* family = nullptr;
                if (FcPatternGetString(font, FC_FAMILY, 0, &family) == FcResultMatch) {
                    match.family = reinterpret_cast<const char*>(family);
                }
                
                FcChar8* style = nullptr;
                if (FcPatternGetString(font, FC_STYLE, 0, &style) == FcResultMatch) {
                    match.style = reinterpret_cast<const char*>(style);
                }
                
                FcChar8* file = nullptr;
                if (FcPatternGetString(font, FC_FILE, 0, &file) == FcResultMatch) {
                    match.file_path = reinterpret_cast<const char*>(file);
                }
                
                int weight = 0;
                if (FcPatternGetInteger(font, FC_WEIGHT, 0, &weight) == FcResultMatch) {
                    match.weight = weight;
                }
                
                int slant = 0;
                if (FcPatternGetInteger(font, FC_SLANT, 0, &slant) == FcResultMatch) {
                    match.slant = slant;
                }
                
                int width = 0;
                if (FcPatternGetInteger(font, FC_WIDTH, 0, &width) == FcResultMatch) {
                    match.width = width;
                }
                
                matches.push_back(match);
            }
            
            FcFontSetDestroy(fs);
        }
        
        FcPatternDestroy(pat);
        
        return matches;
    }
    
    int next_power_of_two(int n) {
        if (n <= 0) return 1;
        n--;
        n |= n >> 1;
        n |= n >> 2;
        n |= n >> 4;
        n |= n >> 8;
        n |= n >> 16;
        return n + 1;
    }
    
    struct OutlineContext {
        msdfgen::Shape* shape;
        msdfgen::Contour** contour;
    };
    
    static int move_to_func(const FT_Vector* to, void* user) {
        OutlineContext* context = static_cast<OutlineContext*>(user);
        context->shape->contours.emplace_back();
        *context->contour = &context->shape->contours.back();
        return 0;
    }
    
    static int line_to_func(const FT_Vector* to, void* user) {
        OutlineContext* context = static_cast<OutlineContext*>(user);
        if (*context->contour) {
            msdfgen::Vector2 end(to->x / 64.0, to->y / 64.0);
            (*context->contour)->addEdge(msdfgen::EdgeHolder((*context->contour)->lastPoint(), end));
        }
        return 0;
    }
    
    static int conic_to_func(const FT_Vector* control, const FT_Vector* to, void* user) {
        OutlineContext* context = static_cast<OutlineContext*>(user);
        if (*context->contour) {
            msdfgen::Vector2 ctrl(control->x / 64.0, control->y / 64.0);
            msdfgen::Vector2 end(to->x / 64.0, to->y / 64.0);
            (*context->contour)->addEdge(msdfgen::EdgeHolder((*context->contour)->lastPoint(), ctrl, end));
        }
        return 0;
    }
    
    static int cubic_to_func(const FT_Vector* control1, const FT_Vector* control2, const FT_Vector* to, void* user) {
        OutlineContext* context = static_cast<OutlineContext*>(user);
        if (*context->contour) {
            msdfgen::Vector2 ctrl1(control1->x / 64.0, control1->y / 64.0);
            msdfgen::Vector2 ctrl2(control2->x / 64.0, control2->y / 64.0);
            msdfgen::Vector2 end(to->x / 64.0, to->y / 64.0);
            (*context->contour)->addEdge(msdfgen::EdgeHolder((*context->contour)->lastPoint(), ctrl1, ctrl2, end));
        }
        return 0;
    }
    
    void update_metrics(const ProcessedFont& font, size_t character_count) {
        fonts_processed++;
        glyphs_processed += font.num_glyphs;
        characters_processed += character_count;
        
        auto& state = get_thread_state();
        std::unique_lock lock(state.mutex);
        
        state.metrics.fonts_processed = fonts_processed.load();
        state.metrics.glyphs_processed = glyphs_processed.load();
        state.metrics.characters_processed = characters_processed.load();
        state.metrics.throughput = calculate_throughput();
    }
    
    double calculate_throughput() {
        static auto start_time = std::chrono::high_resolution_clock::now();
        auto current_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time);
        
        if (duration.count() == 0) return 0.0;
        
        return static_cast<double>(characters_processed.load()) / duration.count();
    }
};

FontConverter::FontConverter() : pimpl(std::make_unique<Impl>()) {}

FontConverter::~FontConverter() = default;

ProcessedFont FontConverter::load_font(const std::string& font_path) {
    auto font = pimpl->load_font(font_path);
    pimpl->update_metrics(font, 0);
    return font;
}

GlyphAtlas FontConverter::generate_glyph_atlas(const ProcessedFont& font,
                                              const std::string& font_path,
                                              const std::vector<uint32_t>& codepoints,
                                              const AtlasSettings& settings) {
    auto atlas = pimpl->generate_glyph_atlas(font, font_path, codepoints, settings);
    pimpl->update_metrics(font, codepoints.size());
    return atlas;
}

GlyphAtlas FontConverter::generate_sdf_atlas(const ProcessedFont& font,
                                            const std::string& font_path,
                                            const std::vector<uint32_t>& codepoints,
                                            const SDFSettings& settings) {
    auto atlas = pimpl->generate_sdf_atlas(font, font_path, codepoints, settings);
    pimpl->update_metrics(font, codepoints.size());
    return atlas;
}

std::vector<ShapedGlyph> FontConverter::shape_text(const std::string& text,
                                                  const std::string& font_path,
                                                  const ShapingSettings& settings) {
    auto glyphs = pimpl->shape_text(text, font_path, settings);
    pimpl->update_metrics(ProcessedFont{}, text.length());
    return glyphs;
}

std::vector<uint8_t> FontConverter::subset_font(const std::string& font_path,
                                               const std::vector<uint32_t>& codepoints,
                                               const SubsetSettings& settings) {
    auto subset = pimpl->subset_font(font_path, codepoints, settings);
    pimpl->update_metrics(ProcessedFont{}, codepoints.size());
    return subset;
}

std::vector<uint8_t> FontConverter::convert_to_woff2(const std::vector<uint8_t>& font_data) {
    return pimpl->convert_to_woff2(font_data);
}

std::vector<uint8_t> FontConverter::convert_from_woff2(const std::vector<uint8_t>& woff2_data) {
    return pimpl->convert_from_woff2(woff2_data);
}

std::vector<FontMatch> FontConverter::find_fonts(const std::string& pattern) {
    return pimpl->find_fonts(pattern);
}

FontMetrics FontConverter::get_metrics() const {
    auto& state = pimpl->get_thread_state();
    std::shared_lock lock(state.mutex);
    return state.metrics;
}

} 