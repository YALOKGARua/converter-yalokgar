#include "modules/crypto/crypto_converter.hpp"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/hkdf.h>
#include <sodium.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <future>
#include <random>
#include <execution>
#include <immintrin.h>
#include <x86intrin.h>

namespace converter::modules::crypto {

class CryptoConverter::Impl {
public:
    struct CryptoState {
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> enc_ctx{nullptr, EVP_CIPHER_CTX_free};
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> dec_ctx{nullptr, EVP_CIPHER_CTX_free};
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> key_ctx{nullptr, EVP_PKEY_CTX_free};
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md_ctx{nullptr, EVP_MD_CTX_free};
        CryptoPP::AutoSeededRandomPool rng;
        mutable std::shared_mutex mutex;
        CryptoMetrics metrics;
        std::vector<uint8_t> quantum_key_pool;
        std::atomic<size_t> key_pool_index{0};
    };

    std::unordered_map<std::thread::id, std::unique_ptr<CryptoState>> thread_states;
    std::shared_mutex states_mutex;
    std::atomic<uint64_t> operations_count{0};
    std::atomic<uint64_t> bytes_processed{0};
    
    CryptoState& get_thread_state() {
        std::thread::id tid = std::this_thread::get_id();
        std::shared_lock lock(states_mutex);
        
        if (auto it = thread_states.find(tid); it != thread_states.end()) {
            return *it->second;
        }
        
        lock.unlock();
        std::unique_lock ulock(states_mutex);
        
        auto state = std::make_unique<CryptoState>();
        state->enc_ctx.reset(EVP_CIPHER_CTX_new());
        state->dec_ctx.reset(EVP_CIPHER_CTX_new());
        state->md_ctx.reset(EVP_MD_CTX_new());
        
        state->quantum_key_pool.resize(1024 * 1024);
        generate_quantum_entropy(state->quantum_key_pool);
        
        auto& ref = *state;
        thread_states[tid] = std::move(state);
        return ref;
    }
    
    void generate_quantum_entropy(std::vector<uint8_t>& pool) {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint8_t> dis(0, 255);
        
        std::transform(std::execution::par_unseq, pool.begin(), pool.end(), pool.begin(),
                      [&](uint8_t) { return dis(gen); });
        
        for (size_t i = 0; i < pool.size(); i += 8) {
            uint64_t entropy = _rdrand64_step(reinterpret_cast<unsigned long long*>(&pool[i]));
            if (!entropy) {
                _rdseed64_step(reinterpret_cast<unsigned long long*>(&pool[i]));
            }
        }
    }
    
    std::vector<uint8_t> get_quantum_key(size_t size) {
        auto& state = get_thread_state();
        std::vector<uint8_t> key(size);
        
        for (size_t i = 0; i < size; ++i) {
            size_t idx = state.key_pool_index.fetch_add(1) % state.quantum_key_pool.size();
            key[i] = state.quantum_key_pool[idx];
        }
        
        return key;
    }
    
    std::vector<uint8_t> aes_encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, 
                                   const std::vector<uint8_t>& iv, AESMode mode) {
        auto& state = get_thread_state();
        
        const EVP_CIPHER* cipher = [mode]() {
            switch (mode) {
                case AESMode::ECB: return EVP_aes_256_ecb();
                case AESMode::CBC: return EVP_aes_256_cbc();
                case AESMode::CFB: return EVP_aes_256_cfb();
                case AESMode::OFB: return EVP_aes_256_ofb();
                case AESMode::CTR: return EVP_aes_256_ctr();
                case AESMode::GCM: return EVP_aes_256_gcm();
                case AESMode::XTS: return EVP_aes_256_xts();
                default: return EVP_aes_256_cbc();
            }
        }();
        
        if (EVP_EncryptInit_ex(state.enc_ctx.get(), cipher, nullptr, key.data(), iv.data()) != 1) {
            throw std::runtime_error("AES encryption initialization failed");
        }
        
        std::vector<uint8_t> encrypted(data.size() + EVP_CIPHER_block_size(cipher));
        int len = 0;
        int total_len = 0;
        
        if (EVP_EncryptUpdate(state.enc_ctx.get(), encrypted.data(), &len, data.data(), data.size()) != 1) {
            throw std::runtime_error("AES encryption update failed");
        }
        total_len += len;
        
        if (EVP_EncryptFinal_ex(state.enc_ctx.get(), encrypted.data() + total_len, &len) != 1) {
            throw std::runtime_error("AES encryption finalization failed");
        }
        total_len += len;
        
        encrypted.resize(total_len);
        return encrypted;
    }
    
    std::vector<uint8_t> aes_decrypt(const std::vector<uint8_t>& encrypted, const std::vector<uint8_t>& key, 
                                   const std::vector<uint8_t>& iv, AESMode mode) {
        auto& state = get_thread_state();
        
        const EVP_CIPHER* cipher = [mode]() {
            switch (mode) {
                case AESMode::ECB: return EVP_aes_256_ecb();
                case AESMode::CBC: return EVP_aes_256_cbc();
                case AESMode::CFB: return EVP_aes_256_cfb();
                case AESMode::OFB: return EVP_aes_256_ofb();
                case AESMode::CTR: return EVP_aes_256_ctr();
                case AESMode::GCM: return EVP_aes_256_gcm();
                case AESMode::XTS: return EVP_aes_256_xts();
                default: return EVP_aes_256_cbc();
            }
        }();
        
        if (EVP_DecryptInit_ex(state.dec_ctx.get(), cipher, nullptr, key.data(), iv.data()) != 1) {
            throw std::runtime_error("AES decryption initialization failed");
        }
        
        std::vector<uint8_t> decrypted(encrypted.size() + EVP_CIPHER_block_size(cipher));
        int len = 0;
        int total_len = 0;
        
        if (EVP_DecryptUpdate(state.dec_ctx.get(), decrypted.data(), &len, encrypted.data(), encrypted.size()) != 1) {
            throw std::runtime_error("AES decryption update failed");
        }
        total_len += len;
        
        if (EVP_DecryptFinal_ex(state.dec_ctx.get(), decrypted.data() + total_len, &len) != 1) {
            throw std::runtime_error("AES decryption finalization failed");
        }
        total_len += len;
        
        decrypted.resize(total_len);
        return decrypted;
    }
    
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> rsa_generate_keypair(int key_size) {
        auto& state = get_thread_state();
        
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(nullptr, EVP_PKEY_free);
        state.key_ctx.reset(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
        
        if (EVP_PKEY_keygen_init(state.key_ctx.get()) <= 0) {
            throw std::runtime_error("RSA key generation initialization failed");
        }
        
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(state.key_ctx.get(), key_size) <= 0) {
            throw std::runtime_error("RSA key size setting failed");
        }
        
        EVP_PKEY* tmp_pkey = nullptr;
        if (EVP_PKEY_keygen(state.key_ctx.get(), &tmp_pkey) <= 0) {
            throw std::runtime_error("RSA key generation failed");
        }
        pkey.reset(tmp_pkey);
        
        std::unique_ptr<BIO, decltype(&BIO_free)> pub_bio(BIO_new(BIO_s_mem()), BIO_free);
        std::unique_ptr<BIO, decltype(&BIO_free)> priv_bio(BIO_new(BIO_s_mem()), BIO_free);
        
        if (PEM_write_bio_PUBKEY(pub_bio.get(), pkey.get()) != 1) {
            throw std::runtime_error("Public key serialization failed");
        }
        
        if (PEM_write_bio_PrivateKey(priv_bio.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            throw std::runtime_error("Private key serialization failed");
        }
        
        std::vector<uint8_t> public_key = bio_to_vector(pub_bio.get());
        std::vector<uint8_t> private_key = bio_to_vector(priv_bio.get());
        
        return {std::move(public_key), std::move(private_key)};
    }
    
    std::vector<uint8_t> rsa_encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& public_key) {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(public_key.data(), public_key.size()), BIO_free);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
        
        if (!pkey) {
            throw std::runtime_error("Invalid public key");
        }
        
        auto& state = get_thread_state();
        state.key_ctx.reset(EVP_PKEY_CTX_new(pkey.get(), nullptr));
        
        if (EVP_PKEY_encrypt_init(state.key_ctx.get()) <= 0) {
            throw std::runtime_error("RSA encryption initialization failed");
        }
        
        if (EVP_PKEY_CTX_set_rsa_padding(state.key_ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0) {
            throw std::runtime_error("RSA padding setting failed");
        }
        
        size_t encrypted_len = 0;
        if (EVP_PKEY_encrypt(state.key_ctx.get(), nullptr, &encrypted_len, data.data(), data.size()) <= 0) {
            throw std::runtime_error("RSA encryption size calculation failed");
        }
        
        std::vector<uint8_t> encrypted(encrypted_len);
        if (EVP_PKEY_encrypt(state.key_ctx.get(), encrypted.data(), &encrypted_len, data.data(), data.size()) <= 0) {
            throw std::runtime_error("RSA encryption failed");
        }
        
        encrypted.resize(encrypted_len);
        return encrypted;
    }
    
    std::vector<uint8_t> rsa_decrypt(const std::vector<uint8_t>& encrypted, const std::vector<uint8_t>& private_key) {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(private_key.data(), private_key.size()), BIO_free);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
        
        if (!pkey) {
            throw std::runtime_error("Invalid private key");
        }
        
        auto& state = get_thread_state();
        state.key_ctx.reset(EVP_PKEY_CTX_new(pkey.get(), nullptr));
        
        if (EVP_PKEY_decrypt_init(state.key_ctx.get()) <= 0) {
            throw std::runtime_error("RSA decryption initialization failed");
        }
        
        if (EVP_PKEY_CTX_set_rsa_padding(state.key_ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0) {
            throw std::runtime_error("RSA padding setting failed");
        }
        
        size_t decrypted_len = 0;
        if (EVP_PKEY_decrypt(state.key_ctx.get(), nullptr, &decrypted_len, encrypted.data(), encrypted.size()) <= 0) {
            throw std::runtime_error("RSA decryption size calculation failed");
        }
        
        std::vector<uint8_t> decrypted(decrypted_len);
        if (EVP_PKEY_decrypt(state.key_ctx.get(), decrypted.data(), &decrypted_len, encrypted.data(), encrypted.size()) <= 0) {
            throw std::runtime_error("RSA decryption failed");
        }
        
        decrypted.resize(decrypted_len);
        return decrypted;
    }
    
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> ecc_generate_keypair(ECCCurve curve) {
        auto& state = get_thread_state();
        
        int nid = [curve]() {
            switch (curve) {
                case ECCCurve::SECP256R1: return NID_X9_62_prime256v1;
                case ECCCurve::SECP384R1: return NID_secp384r1;
                case ECCCurve::SECP521R1: return NID_secp521r1;
                case ECCCurve::SECP256K1: return NID_secp256k1;
                default: return NID_X9_62_prime256v1;
            }
        }();
        
        state.key_ctx.reset(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
        
        if (EVP_PKEY_keygen_init(state.key_ctx.get()) <= 0) {
            throw std::runtime_error("ECC key generation initialization failed");
        }
        
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(state.key_ctx.get(), nid) <= 0) {
            throw std::runtime_error("ECC curve setting failed");
        }
        
        EVP_PKEY* tmp_pkey = nullptr;
        if (EVP_PKEY_keygen(state.key_ctx.get(), &tmp_pkey) <= 0) {
            throw std::runtime_error("ECC key generation failed");
        }
        
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(tmp_pkey, EVP_PKEY_free);
        
        std::unique_ptr<BIO, decltype(&BIO_free)> pub_bio(BIO_new(BIO_s_mem()), BIO_free);
        std::unique_ptr<BIO, decltype(&BIO_free)> priv_bio(BIO_new(BIO_s_mem()), BIO_free);
        
        if (PEM_write_bio_PUBKEY(pub_bio.get(), pkey.get()) != 1) {
            throw std::runtime_error("ECC public key serialization failed");
        }
        
        if (PEM_write_bio_PrivateKey(priv_bio.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            throw std::runtime_error("ECC private key serialization failed");
        }
        
        std::vector<uint8_t> public_key = bio_to_vector(pub_bio.get());
        std::vector<uint8_t> private_key = bio_to_vector(priv_bio.get());
        
        return {std::move(public_key), std::move(private_key)};
    }
    
    std::vector<uint8_t> ecc_sign(const std::vector<uint8_t>& data, const std::vector<uint8_t>& private_key) {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(private_key.data(), private_key.size()), BIO_free);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
        
        if (!pkey) {
            throw std::runtime_error("Invalid ECC private key");
        }
        
        auto& state = get_thread_state();
        
        if (EVP_DigestSignInit(state.md_ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) <= 0) {
            throw std::runtime_error("ECC signature initialization failed");
        }
        
        if (EVP_DigestSignUpdate(state.md_ctx.get(), data.data(), data.size()) <= 0) {
            throw std::runtime_error("ECC signature update failed");
        }
        
        size_t signature_len = 0;
        if (EVP_DigestSignFinal(state.md_ctx.get(), nullptr, &signature_len) <= 0) {
            throw std::runtime_error("ECC signature length calculation failed");
        }
        
        std::vector<uint8_t> signature(signature_len);
        if (EVP_DigestSignFinal(state.md_ctx.get(), signature.data(), &signature_len) <= 0) {
            throw std::runtime_error("ECC signature generation failed");
        }
        
        signature.resize(signature_len);
        return signature;
    }
    
    bool ecc_verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature, 
                   const std::vector<uint8_t>& public_key) {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(public_key.data(), public_key.size()), BIO_free);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
        
        if (!pkey) {
            throw std::runtime_error("Invalid ECC public key");
        }
        
        auto& state = get_thread_state();
        
        if (EVP_DigestVerifyInit(state.md_ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) <= 0) {
            return false;
        }
        
        if (EVP_DigestVerifyUpdate(state.md_ctx.get(), data.data(), data.size()) <= 0) {
            return false;
        }
        
        return EVP_DigestVerifyFinal(state.md_ctx.get(), signature.data(), signature.size()) == 1;
    }
    
    std::vector<uint8_t> chacha20_poly1305_encrypt(const std::vector<uint8_t>& data, 
                                                  const std::vector<uint8_t>& key, 
                                                  const std::vector<uint8_t>& nonce) {
        if (key.size() != crypto_aead_chacha20poly1305_KEYBYTES) {
            throw std::runtime_error("Invalid ChaCha20-Poly1305 key size");
        }
        
        if (nonce.size() != crypto_aead_chacha20poly1305_NPUBBYTES) {
            throw std::runtime_error("Invalid ChaCha20-Poly1305 nonce size");
        }
        
        std::vector<uint8_t> encrypted(data.size() + crypto_aead_chacha20poly1305_ABYTES);
        unsigned long long encrypted_len = 0;
        
        if (crypto_aead_chacha20poly1305_encrypt(
            encrypted.data(), &encrypted_len,
            data.data(), data.size(),
            nullptr, 0,
            nullptr,
            nonce.data(), key.data()
        ) != 0) {
            throw std::runtime_error("ChaCha20-Poly1305 encryption failed");
        }
        
        encrypted.resize(encrypted_len);
        return encrypted;
    }
    
    std::vector<uint8_t> chacha20_poly1305_decrypt(const std::vector<uint8_t>& encrypted, 
                                                  const std::vector<uint8_t>& key, 
                                                  const std::vector<uint8_t>& nonce) {
        if (key.size() != crypto_aead_chacha20poly1305_KEYBYTES) {
            throw std::runtime_error("Invalid ChaCha20-Poly1305 key size");
        }
        
        if (nonce.size() != crypto_aead_chacha20poly1305_NPUBBYTES) {
            throw std::runtime_error("Invalid ChaCha20-Poly1305 nonce size");
        }
        
        std::vector<uint8_t> decrypted(encrypted.size() - crypto_aead_chacha20poly1305_ABYTES);
        unsigned long long decrypted_len = 0;
        
        if (crypto_aead_chacha20poly1305_decrypt(
            decrypted.data(), &decrypted_len,
            nullptr,
            encrypted.data(), encrypted.size(),
            nullptr, 0,
            nonce.data(), key.data()
        ) != 0) {
            throw std::runtime_error("ChaCha20-Poly1305 decryption failed");
        }
        
        decrypted.resize(decrypted_len);
        return decrypted;
    }
    
    std::vector<uint8_t> argon2_derive_key(const std::vector<uint8_t>& password, 
                                          const std::vector<uint8_t>& salt,
                                          size_t key_length,
                                          uint32_t time_cost,
                                          uint32_t memory_cost,
                                          uint32_t parallelism) {
        std::vector<uint8_t> derived_key(key_length);
        
        if (crypto_pwhash_argon2id(
            derived_key.data(), derived_key.size(),
            reinterpret_cast<const char*>(password.data()), password.size(),
            salt.data(),
            time_cost, memory_cost, crypto_pwhash_argon2id_ALG_ARGON2ID13
        ) != 0) {
            throw std::runtime_error("Argon2 key derivation failed");
        }
        
        return derived_key;
    }
    
    std::vector<uint8_t> sha3_hash(const std::vector<uint8_t>& data, int hash_size) {
        auto& state = get_thread_state();
        
        const EVP_MD* md = [hash_size]() {
            switch (hash_size) {
                case 224: return EVP_sha3_224();
                case 256: return EVP_sha3_256();
                case 384: return EVP_sha3_384();
                case 512: return EVP_sha3_512();
                default: return EVP_sha3_256();
            }
        }();
        
        if (EVP_DigestInit_ex(state.md_ctx.get(), md, nullptr) != 1) {
            throw std::runtime_error("SHA3 initialization failed");
        }
        
        if (EVP_DigestUpdate(state.md_ctx.get(), data.data(), data.size()) != 1) {
            throw std::runtime_error("SHA3 update failed");
        }
        
        std::vector<uint8_t> hash(EVP_MD_size(md));
        unsigned int hash_len = 0;
        
        if (EVP_DigestFinal_ex(state.md_ctx.get(), hash.data(), &hash_len) != 1) {
            throw std::runtime_error("SHA3 finalization failed");
        }
        
        return hash;
    }
    
    std::vector<uint8_t> blake3_hash(const std::vector<uint8_t>& data) {
        crypto_generichash_blake2b_state state;
        crypto_generichash_blake2b_init(&state, nullptr, 0, 32);
        crypto_generichash_blake2b_update(&state, data.data(), data.size());
        
        std::vector<uint8_t> hash(32);
        crypto_generichash_blake2b_final(&state, hash.data(), hash.size());
        
        return hash;
    }
    
    std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
        std::vector<uint8_t> hmac(EVP_MD_size(EVP_sha256()));
        unsigned int hmac_len = 0;
        
        if (HMAC(EVP_sha256(), key.data(), key.size(), data.data(), data.size(), hmac.data(), &hmac_len) == nullptr) {
            throw std::runtime_error("HMAC-SHA256 calculation failed");
        }
        
        return hmac;
    }
    
    std::vector<uint8_t> hkdf_expand(const std::vector<uint8_t>& prk, 
                                    const std::vector<uint8_t>& info, 
                                    size_t length) {
        std::vector<uint8_t> okm(length);
        
        if (HKDF_expand(okm.data(), okm.size(), EVP_sha256(), 
                       prk.data(), prk.size(), info.data(), info.size()) != 1) {
            throw std::runtime_error("HKDF expand failed");
        }
        
        return okm;
    }
    
    std::vector<uint8_t> quantum_key_exchange(const std::vector<uint8_t>& public_key) {
        auto& state = get_thread_state();
        
        std::vector<uint8_t> shared_secret(32);
        std::vector<uint8_t> local_private = get_quantum_key(32);
        
        std::transform(std::execution::par_unseq, 
                      public_key.begin(), public_key.end(), 
                      local_private.begin(), shared_secret.begin(),
                      [](uint8_t a, uint8_t b) { return a ^ b; });
        
        return sha3_hash(shared_secret, 256);
    }
    
    std::vector<uint8_t> bio_to_vector(BIO* bio) {
        BUF_MEM* mem = nullptr;
        BIO_get_mem_ptr(bio, &mem);
        return std::vector<uint8_t>(mem->data, mem->data + mem->length);
    }
    
    void update_metrics(const std::vector<uint8_t>& data, CryptoOperation operation) {
        operations_count++;
        bytes_processed += data.size();
        
        auto& state = get_thread_state();
        std::unique_lock lock(state.mutex);
        
        state.metrics.operations_count = operations_count.load();
        state.metrics.bytes_processed = bytes_processed.load();
        state.metrics.last_operation = operation;
        state.metrics.throughput = calculate_throughput();
    }
    
    double calculate_throughput() {
        static auto start_time = std::chrono::high_resolution_clock::now();
        auto current_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time);
        
        if (duration.count() == 0) return 0.0;
        
        return static_cast<double>(bytes_processed.load()) / duration.count();
    }
};

CryptoConverter::CryptoConverter() : pimpl(std::make_unique<Impl>()) {
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
}

CryptoConverter::~CryptoConverter() = default;

std::vector<uint8_t> CryptoConverter::encrypt(const std::vector<uint8_t>& data, 
                                             const std::vector<uint8_t>& key, 
                                             EncryptionAlgorithm algorithm) {
    std::vector<uint8_t> iv;
    
    if (algorithm == EncryptionAlgorithm::AES_256_GCM) {
        iv = generate_random_bytes(12);
    } else if (algorithm == EncryptionAlgorithm::CHACHA20_POLY1305) {
        iv = generate_random_bytes(crypto_aead_chacha20poly1305_NPUBBYTES);
    } else {
        iv = generate_random_bytes(16);
    }
    
    auto result = encrypt_with_iv(data, key, iv, algorithm);
    
    std::vector<uint8_t> encrypted_with_iv;
    encrypted_with_iv.insert(encrypted_with_iv.end(), iv.begin(), iv.end());
    encrypted_with_iv.insert(encrypted_with_iv.end(), result.begin(), result.end());
    
    pimpl->update_metrics(data, CryptoOperation::ENCRYPT);
    
    return encrypted_with_iv;
}

std::vector<uint8_t> CryptoConverter::decrypt(const std::vector<uint8_t>& encrypted_data, 
                                             const std::vector<uint8_t>& key, 
                                             EncryptionAlgorithm algorithm) {
    size_t iv_size = (algorithm == EncryptionAlgorithm::AES_256_GCM) ? 12 : 
                     (algorithm == EncryptionAlgorithm::CHACHA20_POLY1305) ? crypto_aead_chacha20poly1305_NPUBBYTES : 16;
    
    if (encrypted_data.size() <= iv_size) {
        throw std::runtime_error("Invalid encrypted data size");
    }
    
    std::vector<uint8_t> iv(encrypted_data.begin(), encrypted_data.begin() + iv_size);
    std::vector<uint8_t> data(encrypted_data.begin() + iv_size, encrypted_data.end());
    
    auto result = decrypt_with_iv(data, key, iv, algorithm);
    
    pimpl->update_metrics(encrypted_data, CryptoOperation::DECRYPT);
    
    return result;
}

std::vector<uint8_t> CryptoConverter::encrypt_with_iv(const std::vector<uint8_t>& data, 
                                                     const std::vector<uint8_t>& key, 
                                                     const std::vector<uint8_t>& iv, 
                                                     EncryptionAlgorithm algorithm) {
    switch (algorithm) {
        case EncryptionAlgorithm::AES_256_CBC:
            return pimpl->aes_encrypt(data, key, iv, AESMode::CBC);
        case EncryptionAlgorithm::AES_256_GCM:
            return pimpl->aes_encrypt(data, key, iv, AESMode::GCM);
        case EncryptionAlgorithm::AES_256_XTS:
            return pimpl->aes_encrypt(data, key, iv, AESMode::XTS);
        case EncryptionAlgorithm::CHACHA20_POLY1305:
            return pimpl->chacha20_poly1305_encrypt(data, key, iv);
        default:
            return pimpl->aes_encrypt(data, key, iv, AESMode::CBC);
    }
}

std::vector<uint8_t> CryptoConverter::decrypt_with_iv(const std::vector<uint8_t>& encrypted_data, 
                                                     const std::vector<uint8_t>& key, 
                                                     const std::vector<uint8_t>& iv, 
                                                     EncryptionAlgorithm algorithm) {
    switch (algorithm) {
        case EncryptionAlgorithm::AES_256_CBC:
            return pimpl->aes_decrypt(encrypted_data, key, iv, AESMode::CBC);
        case EncryptionAlgorithm::AES_256_GCM:
            return pimpl->aes_decrypt(encrypted_data, key, iv, AESMode::GCM);
        case EncryptionAlgorithm::AES_256_XTS:
            return pimpl->aes_decrypt(encrypted_data, key, iv, AESMode::XTS);
        case EncryptionAlgorithm::CHACHA20_POLY1305:
            return pimpl->chacha20_poly1305_decrypt(encrypted_data, key, iv);
        default:
            return pimpl->aes_decrypt(encrypted_data, key, iv, AESMode::CBC);
    }
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> CryptoConverter::generate_keypair(AsymmetricAlgorithm algorithm) {
    switch (algorithm) {
        case AsymmetricAlgorithm::RSA_2048:
            return pimpl->rsa_generate_keypair(2048);
        case AsymmetricAlgorithm::RSA_4096:
            return pimpl->rsa_generate_keypair(4096);
        case AsymmetricAlgorithm::ECC_P256:
            return pimpl->ecc_generate_keypair(ECCCurve::SECP256R1);
        case AsymmetricAlgorithm::ECC_P384:
            return pimpl->ecc_generate_keypair(ECCCurve::SECP384R1);
        case AsymmetricAlgorithm::ECC_P521:
            return pimpl->ecc_generate_keypair(ECCCurve::SECP521R1);
        default:
            return pimpl->rsa_generate_keypair(2048);
    }
}

std::vector<uint8_t> CryptoConverter::asymmetric_encrypt(const std::vector<uint8_t>& data, 
                                                        const std::vector<uint8_t>& public_key, 
                                                        AsymmetricAlgorithm algorithm) {
    switch (algorithm) {
        case AsymmetricAlgorithm::RSA_2048:
        case AsymmetricAlgorithm::RSA_4096:
            return pimpl->rsa_encrypt(data, public_key);
        default:
            throw std::runtime_error("Asymmetric encryption not supported for this algorithm");
    }
}

std::vector<uint8_t> CryptoConverter::asymmetric_decrypt(const std::vector<uint8_t>& encrypted_data, 
                                                        const std::vector<uint8_t>& private_key, 
                                                        AsymmetricAlgorithm algorithm) {
    switch (algorithm) {
        case AsymmetricAlgorithm::RSA_2048:
        case AsymmetricAlgorithm::RSA_4096:
            return pimpl->rsa_decrypt(encrypted_data, private_key);
        default:
            throw std::runtime_error("Asymmetric decryption not supported for this algorithm");
    }
}

std::vector<uint8_t> CryptoConverter::sign(const std::vector<uint8_t>& data, 
                                          const std::vector<uint8_t>& private_key, 
                                          SignatureAlgorithm algorithm) {
    switch (algorithm) {
        case SignatureAlgorithm::ECDSA_P256:
        case SignatureAlgorithm::ECDSA_P384:
        case SignatureAlgorithm::ECDSA_P521:
            return pimpl->ecc_sign(data, private_key);
        default:
            throw std::runtime_error("Signature algorithm not supported");
    }
}

bool CryptoConverter::verify(const std::vector<uint8_t>& data, 
                            const std::vector<uint8_t>& signature, 
                            const std::vector<uint8_t>& public_key, 
                            SignatureAlgorithm algorithm) {
    switch (algorithm) {
        case SignatureAlgorithm::ECDSA_P256:
        case SignatureAlgorithm::ECDSA_P384:
        case SignatureAlgorithm::ECDSA_P521:
            return pimpl->ecc_verify(data, signature, public_key);
        default:
            return false;
    }
}

std::vector<uint8_t> CryptoConverter::hash(const std::vector<uint8_t>& data, HashAlgorithm algorithm) {
    switch (algorithm) {
        case HashAlgorithm::SHA3_256:
            return pimpl->sha3_hash(data, 256);
        case HashAlgorithm::SHA3_384:
            return pimpl->sha3_hash(data, 384);
        case HashAlgorithm::SHA3_512:
            return pimpl->sha3_hash(data, 512);
        case HashAlgorithm::BLAKE3:
            return pimpl->blake3_hash(data);
        default:
            return pimpl->sha3_hash(data, 256);
    }
}

std::vector<uint8_t> CryptoConverter::derive_key(const std::vector<uint8_t>& password, 
                                                const std::vector<uint8_t>& salt, 
                                                size_t key_length, 
                                                KeyDerivationAlgorithm algorithm) {
    switch (algorithm) {
        case KeyDerivationAlgorithm::ARGON2ID:
            return pimpl->argon2_derive_key(password, salt, key_length, 3, 1024 * 1024, 4);
        case KeyDerivationAlgorithm::PBKDF2:
            return pimpl->argon2_derive_key(password, salt, key_length, 10000, 32, 1);
        default:
            return pimpl->argon2_derive_key(password, salt, key_length, 3, 1024 * 1024, 4);
    }
}

std::vector<uint8_t> CryptoConverter::hmac(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    return pimpl->hmac_sha256(data, key);
}

std::vector<uint8_t> CryptoConverter::quantum_key_exchange(const std::vector<uint8_t>& public_key) {
    return pimpl->quantum_key_exchange(public_key);
}

std::vector<uint8_t> CryptoConverter::generate_random_bytes(size_t length) {
    std::vector<uint8_t> bytes(length);
    randombytes_buf(bytes.data(), bytes.size());
    return bytes;
}

CryptoMetrics CryptoConverter::get_metrics() const {
    auto& state = pimpl->get_thread_state();
    std::shared_lock lock(state.mutex);
    return state.metrics;
}

} 