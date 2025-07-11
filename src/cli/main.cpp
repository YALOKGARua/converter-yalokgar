#include "../include/core/converter_engine.hpp"
#include "../include/core/format_types.hpp"
#include "../include/modules/image/image_converter.hpp"
#include "../include/modules/video/video_converter.hpp"
#include "../include/modules/audio/audio_converter.hpp"
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <iomanip>

namespace po = boost::program_options;
namespace fs = boost::filesystem;

class ConverterCLI {
public:
    ConverterCLI() : engine_() {}
    
    int run(int argc, char* argv[]) {
        try {
            po::options_description desc("Universal Converter Options");
            desc.add_options()
                ("help,h", "Show help message")
                ("version,v", "Show version information")
                ("input,i", po::value<std::string>(), "Input file or directory")
                ("output,o", po::value<std::string>(), "Output file or directory")
                ("format,f", po::value<std::string>(), "Target format")
                ("quality,q", po::value<std::string>()->default_value("high"), "Quality setting")
                ("threads,t", po::value<int>()->default_value(0), "Number of threads")
                ("memory,m", po::value<size_t>()->default_value(1024), "Memory limit in MB")
                ("batch,b", "Batch processing mode")
                ("recursive,r", "Recursive directory processing")
                ("overwrite", "Overwrite existing files")
                ("preserve-metadata", "Preserve metadata")
                ("optimize", "Optimize output")
                ("verbose", "Verbose output")
                ("quiet", "Quiet mode")
                ("list-formats", "List supported formats")
                ("list-conversions", po::value<std::string>(), "List conversions for format")
                ("info", po::value<std::string>(), "Show file information")
                ("benchmark", "Run benchmark")
                ("profile", "Enable profiling")
                ("cache", "Enable caching")
                ("no-cache", "Disable caching")
                ("config", po::value<std::string>(), "Configuration file")
                ("width", po::value<int>(), "Target width")
                ("height", po::value<int>(), "Target height")
                ("bitrate", po::value<int>(), "Target bitrate")
                ("fps", po::value<double>(), "Target framerate")
                ("sample-rate", po::value<int>(), "Target sample rate")
                ("channels", po::value<int>(), "Target channels")
                ("start-time", po::value<std::string>(), "Start time")
                ("duration", po::value<std::string>(), "Duration")
                ("crop", po::value<std::string>(), "Crop rectangle")
                ("resize", po::value<std::string>(), "Resize dimensions")
                ("rotate", po::value<double>(), "Rotation angle")
                ("flip-h", "Flip horizontally")
                ("flip-v", "Flip vertically")
                ("watermark", po::value<std::string>(), "Watermark file")
                ("subtitle", po::value<std::string>(), "Subtitle file")
                ("filter", po::value<std::vector<std::string>>(), "Apply filters")
                ("preset", po::value<std::string>(), "Conversion preset")
                ("pipeline", po::value<std::string>(), "Conversion pipeline")
                ("plugin", po::value<std::vector<std::string>>(), "Load plugins")
                ("extract-audio", "Extract audio track")
                ("extract-video", "Extract video track")
                ("extract-subtitle", "Extract subtitles")
                ("generate-thumbnail", "Generate thumbnail")
                ("create-preview", "Create preview")
                ("verify", "Verify output")
                ("test", "Test mode")
                ("dry-run", "Dry run mode")
                ("continue-on-error", "Continue on errors")
                ("stats", "Show statistics")
                ("progress", "Show progress")
                ("json-output", "JSON output format")
                ("xml-output", "XML output format");
            
            po::variables_map vm;
            po::store(po::parse_command_line(argc, argv, desc), vm);
            po::notify(vm);
            
            if (vm.count("help")) {
                std::cout << desc << std::endl;
                return 0;
            }
            
            if (vm.count("version")) {
                show_version();
                return 0;
            }
            
            if (vm.count("list-formats")) {
                list_formats();
                return 0;
            }
            
            if (vm.count("list-conversions")) {
                list_conversions(vm["list-conversions"].as<std::string>());
                return 0;
            }
            
            if (vm.count("info")) {
                show_file_info(vm["info"].as<std::string>());
                return 0;
            }
            
            if (vm.count("benchmark")) {
                run_benchmark();
                return 0;
            }
            
            if (!vm.count("input") || !vm.count("output") || !vm.count("format")) {
                std::cerr << "Error: input, output, and format are required" << std::endl;
                std::cerr << desc << std::endl;
                return 1;
            }
            
            return process_conversion(vm);
            
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
    }
    
private:
    converter::core::ConversionEngine engine_;
    
    void show_version() {
        std::cout << "Universal Converter v2.0.0" << std::endl;
        std::cout << "Enterprise-grade file conversion system" << std::endl;
        std::cout << "Built with C++23, OpenCV, FFmpeg, Boost" << std::endl;
    }
    
    void list_formats() {
        auto formats = engine_.get_supported_formats();
        std::cout << "Supported formats (" << formats.size() << "):" << std::endl;
        for (const auto& format : formats) {
            std::cout << "  " << format << std::endl;
        }
    }
    
    void list_conversions(const std::string& format) {
        auto conversions = engine_.get_supported_conversions(format);
        std::cout << "Conversions for " << format << ":" << std::endl;
        for (const auto& conversion : conversions) {
            std::cout << "  " << format << " -> " << conversion << std::endl;
        }
    }
    
    void show_file_info(const std::string& filename) {
        try {
            auto metadata = engine_.get_conversion_info("auto", "auto", filename);
            if (metadata) {
                std::cout << "File: " << filename << std::endl;
                std::cout << "Size: " << metadata->source_size << " bytes" << std::endl;
                std::cout << "Format: " << metadata->source_format << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error getting file info: " << e.what() << std::endl;
        }
    }
    
    void run_benchmark() {
        std::cout << "Running benchmark..." << std::endl;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < 100; ++i) {
            std::vector<uint8_t> test_data(1024 * 1024);
            std::iota(test_data.begin(), test_data.end(), 0);
            
            auto result = engine_.convert<std::vector<uint8_t>, std::vector<uint8_t>>(
                std::move(test_data), "binary", {});
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        std::cout << "Benchmark completed in " << duration.count() << "ms" << std::endl;
        std::cout << "Average: " << duration.count() / 100.0 << "ms per conversion" << std::endl;
    }
    
    int process_conversion(const po::variables_map& vm) {
        converter::core::ConversionOptions options;
        
        if (vm.count("threads")) {
            int threads = vm["threads"].as<int>();
            if (threads > 0) {
                options.thread_count = threads;
                engine_.set_thread_pool_size(threads);
            }
        }
        
        if (vm.count("memory")) {
            size_t memory = vm["memory"].as<size_t>() * 1024 * 1024;
            options.max_memory_usage = memory;
            engine_.set_memory_limit(memory);
        }
        
        if (vm.count("cache")) {
            options.enable_caching = true;
        }
        
        if (vm.count("no-cache")) {
            options.enable_caching = false;
        }
        
        if (vm.count("profile")) {
            engine_.enable_profiling(true);
        }
        
        if (vm.count("verbose")) {
            options.log_callback = [](const std::string& msg) {
                std::cout << "[LOG] " << msg << std::endl;
            };
        }
        
        if (vm.count("progress")) {
            options.progress_callback = [](float progress) {
                std::cout << "\rProgress: " << std::fixed << std::setprecision(1) 
                         << progress * 100.0f << "%" << std::flush;
            };
        }
        
        std::string input = vm["input"].as<std::string>();
        std::string output = vm["output"].as<std::string>();
        std::string format = vm["format"].as<std::string>();
        
        if (vm.count("batch") || fs::is_directory(input)) {
            return process_batch(input, output, format, options, vm);
        } else {
            return process_single_file(input, output, format, options, vm);
        }
    }
    
    int process_single_file(const std::string& input, const std::string& output, 
                           const std::string& format, const converter::core::ConversionOptions& options,
                           const po::variables_map& vm) {
        
        try {
            std::ifstream file(input, std::ios::binary);
            if (!file) {
                std::cerr << "Error: Cannot open input file " << input << std::endl;
                return 1;
            }
            
            std::vector<uint8_t> input_data((std::istreambuf_iterator<char>(file)),
                                           std::istreambuf_iterator<char>());
            
            auto result = engine_.convert<std::vector<uint8_t>, std::vector<uint8_t>>(
                std::move(input_data), format, options);
            
            if (!result) {
                std::cerr << "Error: Conversion failed" << std::endl;
                return 1;
            }
            
            std::ofstream output_file(output, std::ios::binary);
            if (!output_file) {
                std::cerr << "Error: Cannot create output file " << output << std::endl;
                return 1;
            }
            
            output_file.write(reinterpret_cast<const char*>(result->data()), result->size());
            
            if (vm.count("verbose")) {
                std::cout << "Converted " << input << " to " << output 
                         << " (" << format << ")" << std::endl;
            }
            
            return 0;
            
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
    }
    
    int process_batch(const std::string& input_dir, const std::string& output_dir,
                     const std::string& format, const converter::core::ConversionOptions& options,
                     const po::variables_map& vm) {
        
        try {
            std::vector<std::string> input_files;
            collect_files(input_dir, input_files, vm.count("recursive"));
            
            if (input_files.empty()) {
                std::cerr << "Error: No input files found" << std::endl;
                return 1;
            }
            
            fs::create_directories(output_dir);
            
            auto result = engine_.batch_convert(input_files, format, output_dir, options);
            
            if (!result) {
                std::cerr << "Error: Batch conversion failed" << std::endl;
                return 1;
            }
            
            if (vm.count("verbose")) {
                std::cout << "Converted " << input_files.size() << " files to " << output_dir << std::endl;
            }
            
            return 0;
            
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
    }
    
    void collect_files(const std::string& dir, std::vector<std::string>& files, bool recursive) {
        if (recursive) {
            for (const auto& entry : fs::recursive_directory_iterator(dir)) {
                if (fs::is_regular_file(entry)) {
                    files.push_back(entry.path().string());
                }
            }
        } else {
            for (const auto& entry : fs::directory_iterator(dir)) {
                if (fs::is_regular_file(entry)) {
                    files.push_back(entry.path().string());
                }
            }
        }
    }
};

int main(int argc, char* argv[]) {
    ConverterCLI cli;
    return cli.run(argc, argv);
} 