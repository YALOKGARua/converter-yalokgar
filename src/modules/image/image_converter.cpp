#include "modules/image/image_converter.hpp"
#include <opencv2/opencv.hpp>
#include <opencv2/imgproc.hpp>
#include <opencv2/photo.hpp>
#include <opencv2/dnn.hpp>
#include <opencv2/imgcodecs.hpp>
#include <opencv2/objdetect.hpp>
#include <opencv2/face.hpp>
#include <FreeImage.h>
#include <webp/encode.h>
#include <webp/decode.h>
#include <avif/avif.h>
#include <heif/heif.h>
#include <tiff/tiffio.h>
#include <jpeglib.h>
#include <png.h>
#include <execution>
#include <immintrin.h>
#include <thread>
#include <future>

namespace converter::modules::image {

class ImageConverter::Impl {
public:
    struct ImageState {
        cv::dnn::Net super_resolution_net;
        cv::dnn::Net style_transfer_net;
        cv::dnn::Net denoising_net;
        cv::dnn::Net edge_detection_net;
        cv::HOGDescriptor hog_detector;
        cv::CascadeClassifier face_cascade;
        cv::Ptr<cv::face::LBPHFaceRecognizer> face_recognizer;
        std::unordered_map<std::string, ProcessedImage> image_cache;
        mutable std::shared_mutex mutex;
        ImageMetrics metrics;
        std::vector<cv::Mat> filter_kernels;
        std::vector<cv::Mat> lut_tables;
    };

    std::unordered_map<std::thread::id, std::unique_ptr<ImageState>> thread_states;
    std::shared_mutex states_mutex;
    std::atomic<uint64_t> images_processed{0};
    std::atomic<uint64_t> pixels_processed{0};
    std::atomic<uint64_t> operations_performed{0};
    
    ImageState& get_thread_state() {
        std::thread::id tid = std::this_thread::get_id();
        std::shared_lock lock(states_mutex);
        
        if (auto it = thread_states.find(tid); it != thread_states.end()) {
            return *it->second;
        }
        
        lock.unlock();
        std::unique_lock ulock(states_mutex);
        
        auto state = std::make_unique<ImageState>();
        initialize_neural_networks(*state);
        initialize_detectors(*state);
        initialize_filters(*state);
        initialize_luts(*state);
        
        auto& ref = *state;
        thread_states[tid] = std::move(state);
        return ref;
    }
    
    void initialize_neural_networks(ImageState& state) {
        try {
            state.super_resolution_net = cv::dnn::readNetFromDarknet("models/espcn.cfg", "models/espcn.weights");
            state.style_transfer_net = cv::dnn::readNetFromTensorflow("models/style_transfer.pb");
            state.denoising_net = cv::dnn::readNetFromONNX("models/denoising.onnx");
            state.edge_detection_net = cv::dnn::readNetFromTensorflow("models/edge_detection.pb");
        } catch (const std::exception& e) {
            // Neural networks are optional, continue without them
        }
    }
    
    void initialize_detectors(ImageState& state) {
        state.hog_detector.setSVMDetector(cv::HOGDescriptor::getDefaultPeopleDetector());
        state.face_cascade.load("models/haarcascade_frontalface_alt.xml");
        state.face_recognizer = cv::face::LBPHFaceRecognizer::create();
    }
    
    void initialize_filters(ImageState& state) {
        state.filter_kernels.resize(FilterType::COUNT);
        
        state.filter_kernels[FilterType::BLUR] = cv::getGaussianKernel(15, 5.0);
        state.filter_kernels[FilterType::SHARPEN] = (cv::Mat_<float>(3, 3) <<
            0, -1, 0,
            -1, 5, -1,
            0, -1, 0);
        
        state.filter_kernels[FilterType::EDGE_DETECTION] = (cv::Mat_<float>(3, 3) <<
            -1, -1, -1,
            -1, 8, -1,
            -1, -1, -1);
        
        state.filter_kernels[FilterType::EMBOSS] = (cv::Mat_<float>(3, 3) <<
            -2, -1, 0,
            -1, 1, 1,
            0, 1, 2);
    }
    
    void initialize_luts(ImageState& state) {
        state.lut_tables.resize(LUTType::COUNT);
        
        cv::Mat lut_gamma(1, 256, CV_8U);
        for (int i = 0; i < 256; ++i) {
            lut_gamma.at<uchar>(i) = cv::saturate_cast<uchar>(pow(i / 255.0, 1.0 / 2.2) * 255.0);
        }
        state.lut_tables[LUTType::GAMMA_CORRECTION] = lut_gamma;
        
        cv::Mat lut_contrast(1, 256, CV_8U);
        for (int i = 0; i < 256; ++i) {
            lut_contrast.at<uchar>(i) = cv::saturate_cast<uchar>(1.5 * i);
        }
        state.lut_tables[LUTType::CONTRAST_ENHANCEMENT] = lut_contrast;
        
        cv::Mat lut_sepia(1, 256, CV_8UC3);
        for (int i = 0; i < 256; ++i) {
            cv::Vec3b& pixel = lut_sepia.at<cv::Vec3b>(i);
            pixel[0] = cv::saturate_cast<uchar>(0.272 * i + 0.534 * i + 0.131 * i);
            pixel[1] = cv::saturate_cast<uchar>(0.349 * i + 0.686 * i + 0.168 * i);
            pixel[2] = cv::saturate_cast<uchar>(0.393 * i + 0.769 * i + 0.189 * i);
        }
        state.lut_tables[LUTType::SEPIA] = lut_sepia;
    }
    
    ProcessedImage load_image(const std::string& file_path) {
        auto& state = get_thread_state();
        
        std::string cache_key = file_path + "_" + std::to_string(std::hash<std::string>{}(file_path));
        
        {
            std::shared_lock lock(state.mutex);
            if (auto it = state.image_cache.find(cache_key); it != state.image_cache.end()) {
                return it->second;
            }
        }
        
        cv::Mat image = cv::imread(file_path, cv::IMREAD_COLOR);
        if (image.empty()) {
            throw std::runtime_error("Failed to load image: " + file_path);
        }
        
        ProcessedImage processed;
        processed.data = image;
        processed.width = image.cols;
        processed.height = image.rows;
        processed.channels = image.channels();
        processed.bit_depth = image.depth() == CV_8U ? 8 : (image.depth() == CV_16U ? 16 : 32);
        processed.color_space = determine_color_space(image);
        processed.file_path = file_path;
        
        extract_exif_data(file_path, processed.exif_data);
        analyze_histogram(image, processed.histogram);
        calculate_image_stats(image, processed.stats);
        
        {
            std::unique_lock lock(state.mutex);
            state.image_cache[cache_key] = processed;
        }
        
        return processed;
    }
    
    ColorSpace determine_color_space(const cv::Mat& image) {
        if (image.channels() == 1) {
            return ColorSpace::GRAYSCALE;
        } else if (image.channels() == 3) {
            return ColorSpace::RGB;
        } else if (image.channels() == 4) {
            return ColorSpace::RGBA;
        }
        return ColorSpace::RGB;
    }
    
    void extract_exif_data(const std::string& file_path, ExifData& exif) {
        FreeImage_Initialise();
        
        FREE_IMAGE_FORMAT format = FreeImage_GetFileType(file_path.c_str());
        FIBITMAP* bitmap = FreeImage_Load(format, file_path.c_str());
        
        if (bitmap) {
            FITAG* tag = nullptr;
            
            if (FreeImage_GetMetadata(FIMD_EXIF_MAIN, bitmap, "DateTime", &tag)) {
                exif.date_time = static_cast<const char*>(FreeImage_GetTagValue(tag));
            }
            
            if (FreeImage_GetMetadata(FIMD_EXIF_MAIN, bitmap, "Make", &tag)) {
                exif.camera_make = static_cast<const char*>(FreeImage_GetTagValue(tag));
            }
            
            if (FreeImage_GetMetadata(FIMD_EXIF_MAIN, bitmap, "Model", &tag)) {
                exif.camera_model = static_cast<const char*>(FreeImage_GetTagValue(tag));
            }
            
            if (FreeImage_GetMetadata(FIMD_EXIF_EXIF, bitmap, "ExposureTime", &tag)) {
                DWORD* value = static_cast<DWORD*>(FreeImage_GetTagValue(tag));
                exif.exposure_time = static_cast<double>(value[0]) / value[1];
            }
            
            if (FreeImage_GetMetadata(FIMD_EXIF_EXIF, bitmap, "FNumber", &tag)) {
                DWORD* value = static_cast<DWORD*>(FreeImage_GetTagValue(tag));
                exif.f_number = static_cast<double>(value[0]) / value[1];
            }
            
            if (FreeImage_GetMetadata(FIMD_EXIF_EXIF, bitmap, "ISOSpeedRatings", &tag)) {
                WORD* value = static_cast<WORD*>(FreeImage_GetTagValue(tag));
                exif.iso_speed = *value;
            }
            
            if (FreeImage_GetMetadata(FIMD_EXIF_EXIF, bitmap, "FocalLength", &tag)) {
                DWORD* value = static_cast<DWORD*>(FreeImage_GetTagValue(tag));
                exif.focal_length = static_cast<double>(value[0]) / value[1];
            }
            
            FreeImage_Unload(bitmap);
        }
        
        FreeImage_DeInitialise();
    }
    
    void analyze_histogram(const cv::Mat& image, ImageHistogram& histogram) {
        std::vector<cv::Mat> channels;
        cv::split(image, channels);
        
        int hist_size = 256;
        float range[] = {0, 256};
        const float* hist_range = {range};
        
        histogram.channels.resize(channels.size());
        
        for (size_t i = 0; i < channels.size(); ++i) {
            cv::calcHist(&channels[i], 1, 0, cv::Mat(), histogram.channels[i], 1, &hist_size, &hist_range);
            cv::normalize(histogram.channels[i], histogram.channels[i], 0, 255, cv::NORM_MINMAX);
        }
        
        cv::Mat gray;
        if (image.channels() > 1) {
            cv::cvtColor(image, gray, cv::COLOR_BGR2GRAY);
        } else {
            gray = image;
        }
        
        cv::calcHist(&gray, 1, 0, cv::Mat(), histogram.luminance, 1, &hist_size, &hist_range);
        cv::normalize(histogram.luminance, histogram.luminance, 0, 255, cv::NORM_MINMAX);
    }
    
    void calculate_image_stats(const cv::Mat& image, ImageStats& stats) {
        cv::Scalar mean, stddev;
        cv::meanStdDev(image, mean, stddev);
        
        stats.mean = mean;
        stats.stddev = stddev;
        
        double min_val, max_val;
        cv::minMaxLoc(image, &min_val, &max_val);
        stats.min_value = min_val;
        stats.max_value = max_val;
        
        cv::Mat gray;
        if (image.channels() > 1) {
            cv::cvtColor(image, gray, cv::COLOR_BGR2GRAY);
        } else {
            gray = image;
        }
        
        cv::Mat laplacian;
        cv::Laplacian(gray, laplacian, CV_64F);
        cv::Scalar laplacian_mean, laplacian_stddev;
        cv::meanStdDev(laplacian, laplacian_mean, laplacian_stddev);
        stats.sharpness = laplacian_stddev.val[0] * laplacian_stddev.val[0];
        
        stats.entropy = calculate_entropy(gray);
        stats.contrast = calculate_contrast(gray);
        stats.brightness = mean.val[0];
        stats.saturation = calculate_saturation(image);
    }
    
    double calculate_entropy(const cv::Mat& image) {
        cv::Mat hist;
        int hist_size = 256;
        float range[] = {0, 256};
        const float* hist_range = {range};
        
        cv::calcHist(&image, 1, 0, cv::Mat(), hist, 1, &hist_size, &hist_range);
        
        double entropy = 0;
        double total_pixels = image.rows * image.cols;
        
        for (int i = 0; i < hist_size; ++i) {
            double probability = hist.at<float>(i) / total_pixels;
            if (probability > 0) {
                entropy -= probability * log2(probability);
            }
        }
        
        return entropy;
    }
    
    double calculate_contrast(const cv::Mat& image) {
        cv::Scalar mean, stddev;
        cv::meanStdDev(image, mean, stddev);
        return stddev.val[0];
    }
    
    double calculate_saturation(const cv::Mat& image) {
        if (image.channels() == 1) return 0.0;
        
        cv::Mat hsv;
        cv::cvtColor(image, hsv, cv::COLOR_BGR2HSV);
        
        std::vector<cv::Mat> channels;
        cv::split(hsv, channels);
        
        cv::Scalar mean_saturation = cv::mean(channels[1]);
        return mean_saturation.val[0];
    }
    
    ProcessedImage resize_image(const ProcessedImage& image, int new_width, int new_height, ResizeMethod method) {
        cv::Mat resized;
        
        int interpolation = [method]() {
            switch (method) {
                case ResizeMethod::NEAREST: return cv::INTER_NEAREST;
                case ResizeMethod::LINEAR: return cv::INTER_LINEAR;
                case ResizeMethod::CUBIC: return cv::INTER_CUBIC;
                case ResizeMethod::LANCZOS: return cv::INTER_LANCZOS4;
                case ResizeMethod::AREA: return cv::INTER_AREA;
                default: return cv::INTER_LINEAR;
            }
        }();
        
        cv::resize(image.data, resized, cv::Size(new_width, new_height), 0, 0, interpolation);
        
        ProcessedImage result = image;
        result.data = resized;
        result.width = new_width;
        result.height = new_height;
        
        return result;
    }
    
    ProcessedImage apply_filter(const ProcessedImage& image, FilterType filter_type, const FilterParams& params) {
        auto& state = get_thread_state();
        cv::Mat filtered;
        
        switch (filter_type) {
            case FilterType::BLUR:
                cv::GaussianBlur(image.data, filtered, cv::Size(params.kernel_size, params.kernel_size), params.sigma);
                break;
                
            case FilterType::SHARPEN:
                cv::filter2D(image.data, filtered, -1, state.filter_kernels[FilterType::SHARPEN]);
                break;
                
            case FilterType::EDGE_DETECTION:
                cv::filter2D(image.data, filtered, -1, state.filter_kernels[FilterType::EDGE_DETECTION]);
                break;
                
            case FilterType::EMBOSS:
                cv::filter2D(image.data, filtered, -1, state.filter_kernels[FilterType::EMBOSS]);
                break;
                
            case FilterType::MEDIAN:
                cv::medianBlur(image.data, filtered, params.kernel_size);
                break;
                
            case FilterType::BILATERAL:
                cv::bilateralFilter(image.data, filtered, params.kernel_size, params.sigma_color, params.sigma_space);
                break;
                
            case FilterType::MORPHOLOGICAL:
                apply_morphological_filter(image.data, filtered, params);
                break;
                
            default:
                filtered = image.data.clone();
                break;
        }
        
        ProcessedImage result = image;
        result.data = filtered;
        
        return result;
    }
    
    void apply_morphological_filter(const cv::Mat& input, cv::Mat& output, const FilterParams& params) {
        cv::Mat kernel = cv::getStructuringElement(
            params.morph_shape,
            cv::Size(params.kernel_size, params.kernel_size)
        );
        
        switch (params.morph_operation) {
            case cv::MORPH_ERODE:
                cv::erode(input, output, kernel);
                break;
            case cv::MORPH_DILATE:
                cv::dilate(input, output, kernel);
                break;
            case cv::MORPH_OPEN:
                cv::morphologyEx(input, output, cv::MORPH_OPEN, kernel);
                break;
            case cv::MORPH_CLOSE:
                cv::morphologyEx(input, output, cv::MORPH_CLOSE, kernel);
                break;
            case cv::MORPH_GRADIENT:
                cv::morphologyEx(input, output, cv::MORPH_GRADIENT, kernel);
                break;
            case cv::MORPH_TOPHAT:
                cv::morphologyEx(input, output, cv::MORPH_TOPHAT, kernel);
                break;
            case cv::MORPH_BLACKHAT:
                cv::morphologyEx(input, output, cv::MORPH_BLACKHAT, kernel);
                break;
            default:
                output = input.clone();
                break;
        }
    }
    
    ProcessedImage adjust_color(const ProcessedImage& image, const ColorAdjustment& adjustment) {
        cv::Mat adjusted = image.data.clone();
        
        if (adjustment.brightness != 0.0) {
            adjusted += cv::Scalar(adjustment.brightness, adjustment.brightness, adjustment.brightness);
        }
        
        if (adjustment.contrast != 1.0) {
            adjusted *= adjustment.contrast;
        }
        
        if (adjustment.saturation != 1.0) {
            cv::Mat hsv;
            cv::cvtColor(adjusted, hsv, cv::COLOR_BGR2HSV);
            
            std::vector<cv::Mat> channels;
            cv::split(hsv, channels);
            
            channels[1] *= adjustment.saturation;
            
            cv::merge(channels, hsv);
            cv::cvtColor(hsv, adjusted, cv::COLOR_HSV2BGR);
        }
        
        if (adjustment.hue != 0.0) {
            cv::Mat hsv;
            cv::cvtColor(adjusted, hsv, cv::COLOR_BGR2HSV);
            
            std::vector<cv::Mat> channels;
            cv::split(hsv, channels);
            
            channels[0] += adjustment.hue;
            
            cv::merge(channels, hsv);
            cv::cvtColor(hsv, adjusted, cv::COLOR_HSV2BGR);
        }
        
        if (adjustment.gamma != 1.0) {
            cv::Mat lut(1, 256, CV_8U);
            for (int i = 0; i < 256; ++i) {
                lut.at<uchar>(i) = cv::saturate_cast<uchar>(pow(i / 255.0, 1.0 / adjustment.gamma) * 255.0);
            }
            cv::LUT(adjusted, lut, adjusted);
        }
        
        ProcessedImage result = image;
        result.data = adjusted;
        
        return result;
    }
    
    ProcessedImage apply_neural_enhancement(const ProcessedImage& image, EnhancementType type) {
        auto& state = get_thread_state();
        
        switch (type) {
            case EnhancementType::SUPER_RESOLUTION:
                return apply_super_resolution(image, state);
            case EnhancementType::DENOISING:
                return apply_denoising(image, state);
            case EnhancementType::STYLE_TRANSFER:
                return apply_style_transfer(image, state);
            case EnhancementType::EDGE_ENHANCEMENT:
                return apply_edge_enhancement(image, state);
            default:
                return image;
        }
    }
    
    ProcessedImage apply_super_resolution(const ProcessedImage& image, ImageState& state) {
        if (state.super_resolution_net.empty()) {
            return resize_image(image, image.width * 2, image.height * 2, ResizeMethod::CUBIC);
        }
        
        cv::Mat blob;
        cv::dnn::blobFromImage(image.data, blob, 1.0 / 255.0, cv::Size(image.width, image.height), cv::Scalar(), true, false);
        
        state.super_resolution_net.setInput(blob);
        cv::Mat output = state.super_resolution_net.forward();
        
        cv::Mat result;
        cv::dnn::imagesFromBlob(output, result);
        
        ProcessedImage enhanced = image;
        enhanced.data = result;
        enhanced.width = result.cols;
        enhanced.height = result.rows;
        
        return enhanced;
    }
    
    ProcessedImage apply_denoising(const ProcessedImage& image, ImageState& state) {
        cv::Mat denoised;
        
        if (!state.denoising_net.empty()) {
            cv::Mat blob;
            cv::dnn::blobFromImage(image.data, blob, 1.0 / 255.0, cv::Size(image.width, image.height), cv::Scalar(), true, false);
            
            state.denoising_net.setInput(blob);
            cv::Mat output = state.denoising_net.forward();
            
            cv::dnn::imagesFromBlob(output, denoised);
        } else {
            cv::fastNlMeansDenoisingColored(image.data, denoised, 10, 10, 7, 21);
        }
        
        ProcessedImage result = image;
        result.data = denoised;
        
        return result;
    }
    
    ProcessedImage apply_style_transfer(const ProcessedImage& image, ImageState& state) {
        if (state.style_transfer_net.empty()) {
            return image;
        }
        
        cv::Mat blob;
        cv::dnn::blobFromImage(image.data, blob, 1.0 / 255.0, cv::Size(image.width, image.height), cv::Scalar(), true, false);
        
        state.style_transfer_net.setInput(blob);
        cv::Mat output = state.style_transfer_net.forward();
        
        cv::Mat result;
        cv::dnn::imagesFromBlob(output, result);
        
        ProcessedImage styled = image;
        styled.data = result;
        
        return styled;
    }
    
    ProcessedImage apply_edge_enhancement(const ProcessedImage& image, ImageState& state) {
        cv::Mat enhanced;
        
        if (!state.edge_detection_net.empty()) {
            cv::Mat blob;
            cv::dnn::blobFromImage(image.data, blob, 1.0 / 255.0, cv::Size(image.width, image.height), cv::Scalar(), true, false);
            
            state.edge_detection_net.setInput(blob);
            cv::Mat output = state.edge_detection_net.forward();
            
            cv::dnn::imagesFromBlob(output, enhanced);
        } else {
            cv::Mat gray;
            cv::cvtColor(image.data, gray, cv::COLOR_BGR2GRAY);
            
            cv::Mat edges;
            cv::Canny(gray, edges, 50, 150);
            
            cv::Mat edges_colored;
            cv::cvtColor(edges, edges_colored, cv::COLOR_GRAY2BGR);
            
            cv::addWeighted(image.data, 0.8, edges_colored, 0.2, 0, enhanced);
        }
        
        ProcessedImage result = image;
        result.data = enhanced;
        
        return result;
    }
    
    std::vector<DetectionResult> detect_objects(const ProcessedImage& image, DetectionType type) {
        auto& state = get_thread_state();
        std::vector<DetectionResult> results;
        
        switch (type) {
            case DetectionType::FACES:
                return detect_faces(image, state);
            case DetectionType::PEOPLE:
                return detect_people(image, state);
            case DetectionType::GENERIC:
                return detect_generic_objects(image, state);
            default:
                return results;
        }
    }
    
    std::vector<DetectionResult> detect_faces(const ProcessedImage& image, ImageState& state) {
        std::vector<DetectionResult> results;
        
        if (state.face_cascade.empty()) {
            return results;
        }
        
        cv::Mat gray;
        cv::cvtColor(image.data, gray, cv::COLOR_BGR2GRAY);
        
        std::vector<cv::Rect> faces;
        state.face_cascade.detectMultiScale(gray, faces, 1.1, 3, 0, cv::Size(30, 30));
        
        for (const auto& face : faces) {
            DetectionResult result;
            result.type = DetectionType::FACES;
            result.bounding_box = face;
            result.confidence = 1.0;
            result.label = "Face";
            results.push_back(result);
        }
        
        return results;
    }
    
    std::vector<DetectionResult> detect_people(const ProcessedImage& image, ImageState& state) {
        std::vector<DetectionResult> results;
        
        cv::Mat gray;
        cv::cvtColor(image.data, gray, cv::COLOR_BGR2GRAY);
        
        std::vector<cv::Rect> people;
        std::vector<double> weights;
        
        state.hog_detector.detectMultiScale(gray, people, weights, 0, cv::Size(8, 8), cv::Size(32, 32), 1.05, 2, false);
        
        for (size_t i = 0; i < people.size(); ++i) {
            DetectionResult result;
            result.type = DetectionType::PEOPLE;
            result.bounding_box = people[i];
            result.confidence = weights[i];
            result.label = "Person";
            results.push_back(result);
        }
        
        return results;
    }
    
    std::vector<DetectionResult> detect_generic_objects(const ProcessedImage& image, ImageState& state) {
        std::vector<DetectionResult> results;
        
        // Generic object detection would require a trained model
        // For now, return empty results
        
        return results;
    }
    
    void save_image(const ProcessedImage& image, const std::string& file_path, ImageFormat format, const SaveOptions& options) {
        switch (format) {
            case ImageFormat::JPEG:
                save_jpeg(image, file_path, options);
                break;
            case ImageFormat::PNG:
                save_png(image, file_path, options);
                break;
            case ImageFormat::WEBP:
                save_webp(image, file_path, options);
                break;
            case ImageFormat::AVIF:
                save_avif(image, file_path, options);
                break;
            case ImageFormat::HEIF:
                save_heif(image, file_path, options);
                break;
            case ImageFormat::TIFF:
                save_tiff(image, file_path, options);
                break;
            default:
                cv::imwrite(file_path, image.data);
                break;
        }
    }
    
    void save_jpeg(const ProcessedImage& image, const std::string& file_path, const SaveOptions& options) {
        std::vector<int> compression_params;
        compression_params.push_back(cv::IMWRITE_JPEG_QUALITY);
        compression_params.push_back(options.quality);
        
        if (options.progressive) {
            compression_params.push_back(cv::IMWRITE_JPEG_PROGRESSIVE);
            compression_params.push_back(1);
        }
        
        cv::imwrite(file_path, image.data, compression_params);
    }
    
    void save_png(const ProcessedImage& image, const std::string& file_path, const SaveOptions& options) {
        std::vector<int> compression_params;
        compression_params.push_back(cv::IMWRITE_PNG_COMPRESSION);
        compression_params.push_back(options.compression_level);
        
        cv::imwrite(file_path, image.data, compression_params);
    }
    
    void save_webp(const ProcessedImage& image, const std::string& file_path, const SaveOptions& options) {
        WebPConfig config;
        WebPConfigInit(&config);
        config.quality = options.quality;
        config.method = 6;
        config.lossless = options.lossless;
        
        WebPPicture picture;
        WebPPictureInit(&picture);
        picture.width = image.width;
        picture.height = image.height;
        picture.use_argb = 1;
        
        WebPPictureAlloc(&picture);
        
        cv::Mat bgr;
        cv::cvtColor(image.data, bgr, cv::COLOR_BGR2RGB);
        
        WebPPictureImportRGB(&picture, bgr.data, bgr.step);
        
        WebPMemoryWriter writer;
        WebPMemoryWriterInit(&writer);
        picture.writer = WebPMemoryWrite;
        picture.custom_ptr = &writer;
        
        WebPEncode(&config, &picture);
        
        std::ofstream file(file_path, std::ios::binary);
        file.write(reinterpret_cast<const char*>(writer.mem), writer.size);
        file.close();
        
        WebPPictureFree(&picture);
        WebPMemoryWriterClear(&writer);
    }
    
    void save_avif(const ProcessedImage& image, const std::string& file_path, const SaveOptions& options) {
        avifImage* avif_image = avifImageCreate(image.width, image.height, 8, AVIF_PIXEL_FORMAT_YUV420);
        
        cv::Mat rgb;
        cv::cvtColor(image.data, rgb, cv::COLOR_BGR2RGB);
        
        avifRGBImage rgb_image;
        avifRGBImageSetDefaults(&rgb_image, avif_image);
        rgb_image.pixels = rgb.data;
        rgb_image.rowBytes = rgb.step;
        
        avifImageRGBToYUV(avif_image, &rgb_image);
        
        avifEncoder* encoder = avifEncoderCreate();
        encoder->quality = options.quality;
        encoder->qualityAlpha = AVIF_QUALITY_LOSSLESS;
        
        avifRWData raw_data = AVIF_DATA_EMPTY;
        avifResult result = avifEncoderWrite(encoder, avif_image, &raw_data);
        
        if (result == AVIF_RESULT_OK) {
            std::ofstream file(file_path, std::ios::binary);
            file.write(reinterpret_cast<const char*>(raw_data.data), raw_data.size);
            file.close();
        }
        
        avifRWDataFree(&raw_data);
        avifEncoderDestroy(encoder);
        avifImageDestroy(avif_image);
    }
    
    void save_heif(const ProcessedImage& image, const std::string& file_path, const SaveOptions& options) {
        heif_context* ctx = heif_context_alloc();
        heif_encoder* encoder = nullptr;
        
        heif_context_get_encoder_for_format(ctx, heif_compression_HEVC, &encoder);
        heif_encoder_set_quality(encoder, options.quality);
        
        heif_image* heif_img = nullptr;
        heif_image_create(image.width, image.height, heif_colorspace_RGB, heif_chroma_444, &heif_img);
        
        cv::Mat rgb;
        cv::cvtColor(image.data, rgb, cv::COLOR_BGR2RGB);
        
        heif_image_add_plane(heif_img, heif_channel_R, image.width, image.height, 8);
        heif_image_add_plane(heif_img, heif_channel_G, image.width, image.height, 8);
        heif_image_add_plane(heif_img, heif_channel_B, image.width, image.height, 8);
        
        int stride_r, stride_g, stride_b;
        uint8_t* plane_r = heif_image_get_plane(heif_img, heif_channel_R, &stride_r);
        uint8_t* plane_g = heif_image_get_plane(heif_img, heif_channel_G, &stride_g);
        uint8_t* plane_b = heif_image_get_plane(heif_img, heif_channel_B, &stride_b);
        
        for (int y = 0; y < image.height; ++y) {
            for (int x = 0; x < image.width; ++x) {
                cv::Vec3b pixel = rgb.at<cv::Vec3b>(y, x);
                plane_r[y * stride_r + x] = pixel[0];
                plane_g[y * stride_g + x] = pixel[1];
                plane_b[y * stride_b + x] = pixel[2];
            }
        }
        
        heif_image_handle* handle = nullptr;
        heif_context_encode_image(ctx, heif_img, encoder, nullptr, &handle);
        
        heif_writer writer;
        writer.writer_api_version = 1;
        writer.write = [](heif_context* ctx, const void* data, size_t size, void* userdata) -> heif_error {
            std::ofstream* file = static_cast<std::ofstream*>(userdata);
            file->write(static_cast<const char*>(data), size);
            return heif_error_ok;
        };
        
        std::ofstream file(file_path, std::ios::binary);
        heif_context_write(ctx, &writer, &file);
        file.close();
        
        heif_image_handle_release(handle);
        heif_image_release(heif_img);
        heif_encoder_release(encoder);
        heif_context_free(ctx);
    }
    
    void save_tiff(const ProcessedImage& image, const std::string& file_path, const SaveOptions& options) {
        std::vector<int> compression_params;
        compression_params.push_back(cv::IMWRITE_TIFF_COMPRESSION);
        compression_params.push_back(options.compression_level);
        
        cv::imwrite(file_path, image.data, compression_params);
    }
    
    ProcessedImage create_collage(const std::vector<ProcessedImage>& images, const CollageSettings& settings) {
        if (images.empty()) {
            throw std::runtime_error("No images provided for collage");
        }
        
        int cols = settings.columns;
        int rows = (images.size() + cols - 1) / cols;
        
        int cell_width = settings.output_width / cols;
        int cell_height = settings.output_height / rows;
        
        cv::Mat collage = cv::Mat::zeros(settings.output_height, settings.output_width, CV_8UC3);
        
        if (settings.background_color.size() >= 3) {
            cv::Scalar bg_color(settings.background_color[0], settings.background_color[1], settings.background_color[2]);
            collage.setTo(bg_color);
        }
        
        for (size_t i = 0; i < images.size(); ++i) {
            int row = i / cols;
            int col = i % cols;
            
            int x = col * cell_width + settings.padding;
            int y = row * cell_height + settings.padding;
            
            int available_width = cell_width - 2 * settings.padding;
            int available_height = cell_height - 2 * settings.padding;
            
            cv::Mat resized;
            cv::resize(images[i].data, resized, cv::Size(available_width, available_height));
            
            cv::Rect roi(x, y, available_width, available_height);
            resized.copyTo(collage(roi));
        }
        
        ProcessedImage result;
        result.data = collage;
        result.width = settings.output_width;
        result.height = settings.output_height;
        result.channels = 3;
        result.bit_depth = 8;
        result.color_space = ColorSpace::RGB;
        
        return result;
    }
    
    void update_metrics(const ProcessedImage& image, const std::string& operation) {
        images_processed++;
        pixels_processed += image.width * image.height;
        operations_performed++;
        
        auto& state = get_thread_state();
        std::unique_lock lock(state.mutex);
        
        state.metrics.images_processed = images_processed.load();
        state.metrics.pixels_processed = pixels_processed.load();
        state.metrics.operations_performed = operations_performed.load();
        state.metrics.throughput = calculate_throughput();
        state.metrics.last_operation = operation;
    }
    
    double calculate_throughput() {
        static auto start_time = std::chrono::high_resolution_clock::now();
        auto current_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time);
        
        if (duration.count() == 0) return 0.0;
        
        return static_cast<double>(pixels_processed.load()) / duration.count();
    }
};

ImageConverter::ImageConverter() : pimpl(std::make_unique<Impl>()) {}

ImageConverter::~ImageConverter() = default;

ProcessedImage ImageConverter::load_image(const std::string& file_path) {
    auto image = pimpl->load_image(file_path);
    pimpl->update_metrics(image, "load");
    return image;
}

void ImageConverter::save_image(const ProcessedImage& image, const std::string& file_path, ImageFormat format, const SaveOptions& options) {
    pimpl->save_image(image, file_path, format, options);
    pimpl->update_metrics(image, "save");
}

ProcessedImage ImageConverter::resize_image(const ProcessedImage& image, int new_width, int new_height, ResizeMethod method) {
    auto resized = pimpl->resize_image(image, new_width, new_height, method);
    pimpl->update_metrics(resized, "resize");
    return resized;
}

ProcessedImage ImageConverter::apply_filter(const ProcessedImage& image, FilterType filter_type, const FilterParams& params) {
    auto filtered = pimpl->apply_filter(image, filter_type, params);
    pimpl->update_metrics(filtered, "filter");
    return filtered;
}

ProcessedImage ImageConverter::adjust_color(const ProcessedImage& image, const ColorAdjustment& adjustment) {
    auto adjusted = pimpl->adjust_color(image, adjustment);
    pimpl->update_metrics(adjusted, "color_adjustment");
    return adjusted;
}

ProcessedImage ImageConverter::apply_neural_enhancement(const ProcessedImage& image, EnhancementType type) {
    auto enhanced = pimpl->apply_neural_enhancement(image, type);
    pimpl->update_metrics(enhanced, "neural_enhancement");
    return enhanced;
}

std::vector<DetectionResult> ImageConverter::detect_objects(const ProcessedImage& image, DetectionType type) {
    auto results = pimpl->detect_objects(image, type);
    pimpl->update_metrics(image, "object_detection");
    return results;
}

ProcessedImage ImageConverter::create_collage(const std::vector<ProcessedImage>& images, const CollageSettings& settings) {
    auto collage = pimpl->create_collage(images, settings);
    pimpl->update_metrics(collage, "collage");
    return collage;
}

ImageMetrics ImageConverter::get_metrics() const {
    auto& state = pimpl->get_thread_state();
    std::shared_lock lock(state.mutex);
    return state.metrics;
}

} 