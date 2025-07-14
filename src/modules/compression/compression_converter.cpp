#include "modules/compression/compression_converter.hpp"
#include <zstd.h>
#include <lz4.h>
#include <brotli/encode.h>
#include <brotli/decode.h>
#include <cuda_runtime.h>
#include <torch/torch.h>
#include <execution>
#include <numeric>
#include <random>
#include <immintrin.h>

namespace converter::modules::compression {

class CompressionConverter::Impl {
public:
    struct CompressionState {
        std::vector<uint8_t> buffer;
        std::unique_ptr<ZSTD_CCtx, decltype(&ZSTD_freeCCtx)> zstd_ctx{nullptr, ZSTD_freeCCtx};
        std::unique_ptr<ZSTD_DCtx, decltype(&ZSTD_freeDCtx)> zstd_dctx{nullptr, ZSTD_freeDCtx};
        torch::jit::Module neural_model;
        cudaStream_t cuda_stream;
        mutable std::shared_mutex mutex;
        CompressionMetrics metrics;
    };

    std::unordered_map<std::thread::id, std::unique_ptr<CompressionState>> thread_states;
    std::shared_mutex states_mutex;
    torch::jit::Module global_model;
    std::atomic<uint64_t> processed_bytes{0};
    std::atomic<uint64_t> compressed_bytes{0};
    
    CompressionState& get_thread_state() {
        std::thread::id tid = std::this_thread::get_id();
        std::shared_lock lock(states_mutex);
        
        if (auto it = thread_states.find(tid); it != thread_states.end()) {
            return *it->second;
        }
        
        lock.unlock();
        std::unique_lock ulock(states_mutex);
        
        auto state = std::make_unique<CompressionState>();
        state->zstd_ctx.reset(ZSTD_createCCtx());
        state->zstd_dctx.reset(ZSTD_createDCtx());
        
        if (global_model.defined()) {
            state->neural_model = global_model.clone();
        }
        
        cudaStreamCreate(&state->cuda_stream);
        
        auto& ref = *state;
        thread_states[tid] = std::move(state);
        return ref;
    }
    
    template<typename T>
    std::vector<uint8_t> vectorize_data(const T& data) {
        const auto* ptr = reinterpret_cast<const uint8_t*>(&data);
        return std::vector<uint8_t>(ptr, ptr + sizeof(T));
    }
    
    template<typename Algorithm>
    std::vector<uint8_t> apply_algorithm(const std::vector<uint8_t>& data, Algorithm&& algo) {
        return algo(data);
    }
    
    std::vector<uint8_t> entropy_encode(const std::vector<uint8_t>& data) {
        std::array<uint32_t, 256> freq{};
        std::for_each(std::execution::par_unseq, data.begin(), data.end(),
                     [&](uint8_t byte) { freq[byte]++; });
        
        std::vector<std::pair<uint32_t, uint8_t>> sorted_freq;
        for (size_t i = 0; i < 256; ++i) {
            if (freq[i] > 0) {
                sorted_freq.emplace_back(freq[i], static_cast<uint8_t>(i));
            }
        }
        
        std::sort(sorted_freq.begin(), sorted_freq.end(), std::greater<>());
        
        std::unordered_map<uint8_t, std::string> codes;
        build_huffman_codes(sorted_freq, codes);
        
        std::string encoded;
        for (uint8_t byte : data) {
            encoded += codes[byte];
        }
        
        std::vector<uint8_t> result;
        result.reserve(encoded.size() / 8 + 1);
        
        for (size_t i = 0; i < encoded.size(); i += 8) {
            uint8_t byte = 0;
            for (size_t j = 0; j < 8 && i + j < encoded.size(); ++j) {
                if (encoded[i + j] == '1') {
                    byte |= (1 << (7 - j));
                }
            }
            result.push_back(byte);
        }
        
        return result;
    }
    
    void build_huffman_codes(const std::vector<std::pair<uint32_t, uint8_t>>& freq,
                            std::unordered_map<uint8_t, std::string>& codes) {
        struct Node {
            uint32_t frequency;
            uint8_t symbol;
            std::unique_ptr<Node> left, right;
            
            bool is_leaf() const { return !left && !right; }
        };
        
        auto cmp = [](const std::unique_ptr<Node>& a, const std::unique_ptr<Node>& b) {
            return a->frequency > b->frequency;
        };
        
        std::priority_queue<std::unique_ptr<Node>, std::vector<std::unique_ptr<Node>>, decltype(cmp)> pq(cmp);
        
        for (const auto& [f, s] : freq) {
            auto node = std::make_unique<Node>();
            node->frequency = f;
            node->symbol = s;
            pq.push(std::move(node));
        }
        
        while (pq.size() > 1) {
            auto right = std::move(const_cast<std::unique_ptr<Node>&>(pq.top()));
            pq.pop();
            auto left = std::move(const_cast<std::unique_ptr<Node>&>(pq.top()));
            pq.pop();
            
            auto merged = std::make_unique<Node>();
            merged->frequency = left->frequency + right->frequency;
            merged->left = std::move(left);
            merged->right = std::move(right);
            
            pq.push(std::move(merged));
        }
        
        if (!pq.empty()) {
            generate_codes(pq.top().get(), "", codes);
        }
    }
    
    void generate_codes(Node* node, std::string code, std::unordered_map<uint8_t, std::string>& codes) {
        if (node->is_leaf()) {
            codes[node->symbol] = code.empty() ? "0" : code;
            return;
        }
        
        if (node->left) generate_codes(node->left.get(), code + "0", codes);
        if (node->right) generate_codes(node->right.get(), code + "1", codes);
    }
    
    std::vector<uint8_t> gpu_compress(const std::vector<uint8_t>& data) {
        auto& state = get_thread_state();
        
        uint8_t* d_input;
        uint8_t* d_output;
        size_t* d_output_size;
        
        cudaMalloc(&d_input, data.size());
        cudaMalloc(&d_output, data.size() * 2);
        cudaMalloc(&d_output_size, sizeof(size_t));
        
        cudaMemcpyAsync(d_input, data.data(), data.size(), cudaMemcpyHostToDevice, state.cuda_stream);
        
        const size_t block_size = 256;
        const size_t grid_size = (data.size() + block_size - 1) / block_size;
        
        launch_compression_kernel<<<grid_size, block_size, 0, state.cuda_stream>>>(
            d_input, d_output, data.size(), d_output_size
        );
        
        size_t output_size;
        cudaMemcpyAsync(&output_size, d_output_size, sizeof(size_t), cudaMemcpyDeviceToHost, state.cuda_stream);
        
        std::vector<uint8_t> result(output_size);
        cudaMemcpyAsync(result.data(), d_output, output_size, cudaMemcpyDeviceToHost, state.cuda_stream);
        
        cudaStreamSynchronize(state.cuda_stream);
        
        cudaFree(d_input);
        cudaFree(d_output);
        cudaFree(d_output_size);
        
        return result;
    }
    
    std::vector<uint8_t> neural_compress(const std::vector<uint8_t>& data) {
        auto& state = get_thread_state();
        
        if (!state.neural_model.defined()) {
            return apply_zstd_compression(data);
        }
        
        std::vector<float> normalized_data;
        normalized_data.reserve(data.size());
        
        std::transform(data.begin(), data.end(), std::back_inserter(normalized_data),
                      [](uint8_t byte) { return static_cast<float>(byte) / 255.0f; });
        
        auto tensor = torch::from_blob(normalized_data.data(), {1, 1, static_cast<int64_t>(data.size())});
        
        std::vector<torch::jit::IValue> inputs;
        inputs.push_back(tensor);
        
        torch::NoGradGuard no_grad;
        auto output = state.neural_model.forward(inputs).toTensor();
        
        auto output_data = output.data_ptr<float>();
        size_t output_size = output.numel();
        
        std::vector<uint8_t> result;
        result.reserve(output_size);
        
        std::transform(output_data, output_data + output_size, std::back_inserter(result),
                      [](float val) { return static_cast<uint8_t>(std::clamp(val * 255.0f, 0.0f, 255.0f)); });
        
        return result;
    }
    
    std::vector<uint8_t> apply_zstd_compression(const std::vector<uint8_t>& data) {
        auto& state = get_thread_state();
        
        size_t const compressed_size = ZSTD_compressBound(data.size());
        std::vector<uint8_t> compressed(compressed_size);
        
        size_t const actual_size = ZSTD_compressCCtx(
            state.zstd_ctx.get(),
            compressed.data(), compressed.size(),
            data.data(), data.size(),
            ZSTD_maxCLevel()
        );
        
        if (ZSTD_isError(actual_size)) {
            throw std::runtime_error("ZSTD compression failed");
        }
        
        compressed.resize(actual_size);
        return compressed;
    }
    
    std::vector<uint8_t> apply_brotli_compression(const std::vector<uint8_t>& data) {
        size_t encoded_size = BrotliEncoderMaxCompressedSize(data.size());
        std::vector<uint8_t> encoded(encoded_size);
        
        if (!BrotliEncoderCompress(
            BROTLI_MAX_QUALITY,
            BROTLI_MAX_WINDOW_BITS,
            BROTLI_DEFAULT_MODE,
            data.size(),
            data.data(),
            &encoded_size,
            encoded.data()
        )) {
            throw std::runtime_error("Brotli compression failed");
        }
        
        encoded.resize(encoded_size);
        return encoded;
    }
    
    std::vector<uint8_t> apply_lz4_compression(const std::vector<uint8_t>& data) {
        int const max_size = LZ4_compressBound(static_cast<int>(data.size()));
        std::vector<uint8_t> compressed(max_size);
        
        int const compressed_size = LZ4_compress_default(
            reinterpret_cast<const char*>(data.data()),
            reinterpret_cast<char*>(compressed.data()),
            static_cast<int>(data.size()),
            max_size
        );
        
        if (compressed_size == 0) {
            throw std::runtime_error("LZ4 compression failed");
        }
        
        compressed.resize(compressed_size);
        return compressed;
    }
    
    std::vector<uint8_t> adaptive_compress(const std::vector<uint8_t>& data) {
        struct CompressionResult {
            std::vector<uint8_t> data;
            CompressionAlgorithm algorithm;
            double ratio;
        };
        
        std::vector<std::future<CompressionResult>> futures;
        
        auto test_algorithm = [&](CompressionAlgorithm algo) -> CompressionResult {
            std::vector<uint8_t> compressed;
            
            switch (algo) {
                case CompressionAlgorithm::ZSTD:
                    compressed = apply_zstd_compression(data);
                    break;
                case CompressionAlgorithm::BROTLI:
                    compressed = apply_brotli_compression(data);
                    break;
                case CompressionAlgorithm::LZ4:
                    compressed = apply_lz4_compression(data);
                    break;
                case CompressionAlgorithm::NEURAL:
                    compressed = neural_compress(data);
                    break;
                default:
                    compressed = apply_zstd_compression(data);
                    break;
            }
            
            double ratio = static_cast<double>(compressed.size()) / data.size();
            return {std::move(compressed), algo, ratio};
        };
        
        std::array<CompressionAlgorithm, 4> algorithms = {
            CompressionAlgorithm::ZSTD,
            CompressionAlgorithm::BROTLI,
            CompressionAlgorithm::LZ4,
            CompressionAlgorithm::NEURAL
        };
        
        for (auto algo : algorithms) {
            futures.push_back(std::async(std::launch::async, test_algorithm, algo));
        }
        
        CompressionResult best_result;
        best_result.ratio = std::numeric_limits<double>::max();
        
        for (auto& future : futures) {
            auto result = future.get();
            if (result.ratio < best_result.ratio) {
                best_result = std::move(result);
            }
        }
        
        return best_result.data;
    }
    
    std::vector<uint8_t> streaming_compress(std::istream& input, size_t chunk_size = 64 * 1024) {
        std::vector<uint8_t> result;
        std::vector<uint8_t> buffer(chunk_size);
        
        while (input.read(reinterpret_cast<char*>(buffer.data()), chunk_size) || input.gcount() > 0) {
            auto actual_size = static_cast<size_t>(input.gcount());
            buffer.resize(actual_size);
            
            auto compressed_chunk = adaptive_compress(buffer);
            
            uint32_t chunk_size_header = static_cast<uint32_t>(compressed_chunk.size());
            result.insert(result.end(), 
                         reinterpret_cast<uint8_t*>(&chunk_size_header),
                         reinterpret_cast<uint8_t*>(&chunk_size_header) + sizeof(chunk_size_header));
            
            result.insert(result.end(), compressed_chunk.begin(), compressed_chunk.end());
            
            buffer.resize(chunk_size);
        }
        
        return result;
    }
    
    void update_metrics(const std::vector<uint8_t>& original, const std::vector<uint8_t>& compressed) {
        processed_bytes += original.size();
        compressed_bytes += compressed.size();
        
        auto& state = get_thread_state();
        std::unique_lock lock(state.mutex);
        
        state.metrics.compression_ratio = static_cast<double>(compressed.size()) / original.size();
        state.metrics.bytes_processed = processed_bytes.load();
        state.metrics.bytes_compressed = compressed_bytes.load();
        state.metrics.throughput = calculate_throughput();
    }
    
    double calculate_throughput() {
        static auto start_time = std::chrono::high_resolution_clock::now();
        auto current_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time);
        
        if (duration.count() == 0) return 0.0;
        
        return static_cast<double>(processed_bytes.load()) / duration.count();
    }
    
private:
    __global__ void launch_compression_kernel(const uint8_t* input, uint8_t* output, size_t size, size_t* output_size) {
        extern "C" __global__ void compression_kernel(const uint8_t* input, uint8_t* output, size_t size, size_t* output_size) {
            int idx = blockIdx.x * blockDim.x + threadIdx.x;
            if (idx >= size) return;
            
            __shared__ uint8_t shared_buffer[256];
            __shared__ uint32_t frequencies[256];
            
            if (threadIdx.x == 0) {
                for (int i = 0; i < 256; ++i) {
                    frequencies[i] = 0;
                }
            }
            __syncthreads();
            
            if (idx < size) {
                atomicAdd(&frequencies[input[idx]], 1);
            }
            __syncthreads();
            
            if (threadIdx.x == 0) {
                uint32_t max_freq = 0;
                uint8_t most_frequent = 0;
                
                for (int i = 0; i < 256; ++i) {
                    if (frequencies[i] > max_freq) {
                        max_freq = frequencies[i];
                        most_frequent = i;
                    }
                }
                
                shared_buffer[0] = most_frequent;
            }
            __syncthreads();
            
            if (idx < size) {
                output[idx] = (input[idx] == shared_buffer[0]) ? 0 : input[idx];
            }
            
            if (idx == 0) {
                *output_size = size;
            }
        }
    }
};

CompressionConverter::CompressionConverter() : pimpl(std::make_unique<Impl>()) {}

CompressionConverter::~CompressionConverter() = default;

std::vector<uint8_t> CompressionConverter::compress(const std::vector<uint8_t>& data, CompressionAlgorithm algorithm) {
    auto result = [&] {
        switch (algorithm) {
            case CompressionAlgorithm::ZSTD:
                return pimpl->apply_zstd_compression(data);
            case CompressionAlgorithm::BROTLI:
                return pimpl->apply_brotli_compression(data);
            case CompressionAlgorithm::LZ4:
                return pimpl->apply_lz4_compression(data);
            case CompressionAlgorithm::NEURAL:
                return pimpl->neural_compress(data);
            case CompressionAlgorithm::GPU_ACCELERATED:
                return pimpl->gpu_compress(data);
            case CompressionAlgorithm::ADAPTIVE:
                return pimpl->adaptive_compress(data);
            default:
                return pimpl->apply_zstd_compression(data);
        }
    }();
    
    pimpl->update_metrics(data, result);
    return result;
}

std::vector<uint8_t> CompressionConverter::decompress(const std::vector<uint8_t>& data, CompressionAlgorithm algorithm) {
    auto& state = pimpl->get_thread_state();
    
    switch (algorithm) {
        case CompressionAlgorithm::ZSTD: {
            size_t const decompressed_size = ZSTD_getFrameContentSize(data.data(), data.size());
            std::vector<uint8_t> decompressed(decompressed_size);
            
            size_t const actual_size = ZSTD_decompressDCtx(
                state.zstd_dctx.get(),
                decompressed.data(), decompressed.size(),
                data.data(), data.size()
            );
            
            if (ZSTD_isError(actual_size)) {
                throw std::runtime_error("ZSTD decompression failed");
            }
            
            decompressed.resize(actual_size);
            return decompressed;
        }
        
        case CompressionAlgorithm::BROTLI: {
            size_t decoded_size = data.size() * 4;
            std::vector<uint8_t> decoded(decoded_size);
            
            if (BrotliDecoderDecompress(
                data.size(),
                data.data(),
                &decoded_size,
                decoded.data()
            ) != BROTLI_DECODER_RESULT_SUCCESS) {
                throw std::runtime_error("Brotli decompression failed");
            }
            
            decoded.resize(decoded_size);
            return decoded;
        }
        
        default:
            throw std::runtime_error("Unsupported decompression algorithm");
    }
}

std::vector<uint8_t> CompressionConverter::streaming_compress(std::istream& input, CompressionAlgorithm algorithm) {
    return pimpl->streaming_compress(input);
}

void CompressionConverter::load_neural_model(const std::string& model_path) {
    try {
        pimpl->global_model = torch::jit::load(model_path);
        pimpl->global_model.eval();
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to load neural model: " + std::string(e.what()));
    }
}

CompressionMetrics CompressionConverter::get_metrics() const {
    auto& state = pimpl->get_thread_state();
    std::shared_lock lock(state.mutex);
    return state.metrics;
}

bool CompressionConverter::is_gpu_available() const {
    int device_count = 0;
    cudaGetDeviceCount(&device_count);
    return device_count > 0;
}

void CompressionConverter::set_compression_level(int level) {
    auto& state = pimpl->get_thread_state();
    std::unique_lock lock(state.mutex);
    
    if (state.zstd_ctx) {
        ZSTD_CCtx_setParameter(state.zstd_ctx.get(), ZSTD_c_compressionLevel, level);
    }
}

std::vector<uint8_t> CompressionConverter::benchmark_algorithms(const std::vector<uint8_t>& data) {
    std::vector<std::pair<CompressionAlgorithm, double>> results;
    
    for (auto algo : {CompressionAlgorithm::ZSTD, CompressionAlgorithm::BROTLI, CompressionAlgorithm::LZ4}) {
        auto start = std::chrono::high_resolution_clock::now();
        auto compressed = compress(data, algo);
        auto end = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        double ratio = static_cast<double>(compressed.size()) / data.size();
        double score = ratio + (duration.count() / 1000000.0);
        
        results.emplace_back(algo, score);
    }
    
    auto best = std::min_element(results.begin(), results.end(),
                                [](const auto& a, const auto& b) { return a.second < b.second; });
    
    return compress(data, best->first);
}

} 