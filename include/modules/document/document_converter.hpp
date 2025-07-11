#pragma once

#include "../../core/converter_engine.hpp"
#include "../../core/format_types.hpp"
#include <memory>
#include <vector>
#include <string>
#include <unordered_map>
#include <expected>

namespace converter::modules::document {

enum class DocumentFormat {
    PDF, DOCX, DOC, ODT, RTF, TXT, HTML, EPUB, MOBI, 
    XLSX, XLS, ODS, CSV, PPTX, PPT, ODP, TEX, MD, XML, JSON
};

enum class PageOrientation { Portrait, Landscape };
enum class PageSize { A4, A3, A5, Letter, Legal, Custom };

struct DocumentMetadata {
    std::string title;
    std::string author;
    std::string subject;
    std::string keywords;
    std::string creator;
    std::string producer;
    std::string creation_date;
    std::string modification_date;
    int page_count = 0;
    bool encrypted = false;
    bool signed = false;
    std::string language;
    std::unordered_map<std::string, std::string> custom_properties;
};

struct DocumentOptions {
    std::optional<PageSize> page_size;
    std::optional<PageOrientation> orientation;
    std::optional<std::pair<int, int>> custom_size;
    std::optional<std::array<int, 4>> margins;
    std::optional<std::string> font_family;
    std::optional<int> font_size;
    std::optional<std::string> encoding;
    std::optional<std::string> language;
    std::optional<int> quality;
    std::optional<std::string> password;
    std::optional<bool> preserve_formatting;
    std::optional<bool> embed_fonts;
    std::optional<bool> compress_images;
    std::optional<bool> optimize_for_web;
    std::optional<std::string> watermark_text;
    std::optional<std::string> header_text;
    std::optional<std::string> footer_text;
    std::optional<std::pair<int, int>> page_range;
    std::optional<bool> extract_images;
    std::optional<bool> extract_text;
    std::optional<bool> ocr_enabled;
    std::optional<std::string> ocr_language;
};

class DocumentBuffer {
public:
    DocumentBuffer();
    DocumentBuffer(const std::string& filename);
    DocumentBuffer(std::vector<uint8_t> data, DocumentFormat format);
    ~DocumentBuffer();
    
    std::expected<void, std::error_code> load_from_file(const std::string& filename);
    std::expected<void, std::error_code> load_from_memory(std::span<const uint8_t> data, DocumentFormat format);
    std::expected<void, std::error_code> save_to_file(const std::string& filename, const DocumentOptions& options = {});
    std::expected<std::vector<uint8_t>, std::error_code> save_to_memory(DocumentFormat format, const DocumentOptions& options = {});
    
    const DocumentMetadata& metadata() const { return metadata_; }
    DocumentMetadata& metadata() { return metadata_; }
    
    std::expected<std::string, std::error_code> extract_text() const;
    std::expected<std::vector<std::vector<uint8_t>>, std::error_code> extract_images() const;
    std::expected<std::vector<std::string>, std::error_code> get_page_text(int page) const;
    std::expected<std::vector<uint8_t>, std::error_code> get_page_image(int page, int dpi = 150) const;
    
    std::expected<void, std::error_code> merge_document(const DocumentBuffer& other);
    std::expected<void, std::error_code> split_pages(const std::string& output_dir, const std::string& prefix = "page_");
    std::expected<void, std::error_code> extract_page_range(int start_page, int end_page);
    std::expected<void, std::error_code> insert_page(int position, const std::vector<uint8_t>& page_data);
    std::expected<void, std::error_code> remove_page(int page);
    
    std::expected<void, std::error_code> set_password(const std::string& password);
    std::expected<void, std::error_code> remove_password(const std::string& password);
    std::expected<void, std::error_code> sign_document(const std::string& certificate_path);
    std::expected<void, std::error_code> add_watermark(const std::string& text, double opacity = 0.5);
    std::expected<void, std::error_code> add_header_footer(const std::string& header, const std::string& footer);
    
    std::expected<void, std::error_code> perform_ocr(const std::string& language = "eng");
    std::expected<void, std::error_code> redact_text(const std::vector<std::string>& patterns);
    std::expected<void, std::error_code> replace_text(const std::string& find, const std::string& replace);
    std::expected<void, std::error_code> highlight_text(const std::string& text, const std::array<uint8_t, 3>& color);
    
    std::expected<void, std::error_code> compress_document(double compression_ratio = 0.8);
    std::expected<void, std::error_code> optimize_for_web();
    std::expected<void, std::error_code> linearize_pdf();
    
    std::expected<void, std::error_code> convert_to_format(DocumentFormat target_format, const DocumentOptions& options = {});
    
    bool is_valid() const { return !data_.empty(); }
    DocumentFormat get_format() const { return format_; }
    std::size_t get_size() const { return data_.size(); }
    int get_page_count() const { return metadata_.page_count; }
    
private:
    std::vector<uint8_t> data_;
    DocumentFormat format_;
    DocumentMetadata metadata_;
    
    std::expected<void, std::error_code> detect_format();
    std::expected<void, std::error_code> parse_metadata();
    std::expected<void, std::error_code> initialize_document_engine();
    
    class DocumentEngine;
    std::unique_ptr<DocumentEngine> engine_;
};

class DocumentConverter : public converter::core::ConversionTask<DocumentBuffer, DocumentBuffer> {
public:
    DocumentConverter(DocumentBuffer input, converter::core::ConversionOptions options, DocumentOptions processing_options = {});
    
    result_type execute() override;
    std::future<result_type> execute_async() override;
    std::generator<result_type> execute_stream() override;
    
    bool validate_input() const override;
    bool can_convert() const override;
    std::string get_format_info() const override;
    std::size_t estimate_output_size() const override;
    std::chrono::milliseconds estimate_duration() const override;
    
    void set_target_format(DocumentFormat format) { target_format_ = format; }
    void set_processing_options(const DocumentOptions& options) { processing_options_ = options; }
    
    static std::expected<DocumentBuffer, std::error_code> load_from_file(const std::string& filename);
    static std::expected<void, std::error_code> save_to_file(const DocumentBuffer& document, const std::string& filename, const DocumentOptions& options = {});
    
    static std::expected<std::vector<DocumentBuffer>, std::error_code> batch_convert(
        const std::vector<std::string>& input_files,
        const std::string& output_directory,
        DocumentFormat target_format,
        const DocumentOptions& options = {}
    );
    
    static std::expected<DocumentBuffer, std::error_code> merge_documents(const std::vector<DocumentBuffer>& documents);
    static std::expected<std::vector<DocumentBuffer>, std::error_code> split_document(const DocumentBuffer& document, int pages_per_part = 10);
    
    static std::expected<void, std::error_code> extract_text_from_pdf(const std::string& input_file, const std::string& output_file);
    static std::expected<void, std::error_code> extract_images_from_pdf(const std::string& input_file, const std::string& output_dir);
    static std::expected<void, std::error_code> pdf_to_images(const std::string& input_file, const std::string& output_dir, int dpi = 150);
    static std::expected<void, std::error_code> images_to_pdf(const std::vector<std::string>& image_files, const std::string& output_file);
    
    static std::expected<void, std::error_code> html_to_pdf(const std::string& html_file, const std::string& output_file, const DocumentOptions& options = {});
    static std::expected<void, std::error_code> markdown_to_html(const std::string& md_file, const std::string& output_file);
    static std::expected<void, std::error_code> markdown_to_pdf(const std::string& md_file, const std::string& output_file);
    
    static std::expected<void, std::error_code> excel_to_csv(const std::string& input_file, const std::string& output_file);
    static std::expected<void, std::error_code> csv_to_excel(const std::string& input_file, const std::string& output_file);
    static std::expected<void, std::error_code> excel_to_json(const std::string& input_file, const std::string& output_file);
    static std::expected<void, std::error_code> json_to_excel(const std::string& input_file, const std::string& output_file);
    
    static std::expected<void, std::error_code> word_to_pdf(const std::string& input_file, const std::string& output_file);
    static std::expected<void, std::error_code> pdf_to_word(const std::string& input_file, const std::string& output_file);
    static std::expected<void, std::error_code> powerpoint_to_pdf(const std::string& input_file, const std::string& output_file);
    static std::expected<void, std::error_code> pdf_to_powerpoint(const std::string& input_file, const std::string& output_file);
    
    static std::expected<void, std::error_code> create_ebook(const std::vector<std::string>& chapter_files, const std::string& output_file, const DocumentOptions& options = {});
    static std::expected<void, std::error_code> epub_to_mobi(const std::string& input_file, const std::string& output_file);
    static std::expected<void, std::error_code> mobi_to_epub(const std::string& input_file, const std::string& output_file);
    
    static std::expected<void, std::error_code> latex_to_pdf(const std::string& tex_file, const std::string& output_file);
    static std::expected<void, std::error_code> pdf_to_latex(const std::string& input_file, const std::string& output_file);
    
    static std::expected<void, std::error_code> create_invoice(const std::unordered_map<std::string, std::string>& data, const std::string& template_file, const std::string& output_file);
    static std::expected<void, std::error_code> create_report(const std::vector<std::unordered_map<std::string, std::string>>& data, const std::string& template_file, const std::string& output_file);
    
    static std::expected<void, std::error_code> bulk_redact_documents(const std::vector<std::string>& input_files, const std::string& output_dir, const std::vector<std::string>& patterns);
    static std::expected<void, std::error_code> bulk_watermark_documents(const std::vector<std::string>& input_files, const std::string& output_dir, const std::string& watermark_text);
    
    static std::expected<void, std::error_code> validate_document_integrity(const std::string& filename);
    static std::expected<void, std::error_code> repair_corrupted_document(const std::string& input_file, const std::string& output_file);
    
    static std::vector<DocumentFormat> get_supported_input_formats();
    static std::vector<DocumentFormat> get_supported_output_formats();
    static bool is_format_supported(DocumentFormat format);
    static std::expected<DocumentMetadata, std::error_code> get_document_info(const std::string& filename);
    
private:
    DocumentFormat target_format_ = DocumentFormat::PDF;
    DocumentOptions processing_options_;
    
    std::expected<DocumentBuffer, std::error_code> apply_processing(const DocumentBuffer& input) const;
    std::expected<std::vector<uint8_t>, std::error_code> encode_document(const DocumentBuffer& document) const;
    std::expected<DocumentBuffer, std::error_code> decode_document(std::span<const uint8_t> data) const;
    
    static std::unordered_map<DocumentFormat, std::string> format_extensions_;
    static std::unordered_map<DocumentFormat, std::vector<std::string>> format_mime_types_;
    static bool is_initialized_;
    static void initialize_document_support();
};

} 