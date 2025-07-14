#include "security/encryption_manager.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/hkdf.h>
#include <openssl/pbkdf2.h>
#include <openssl/scrypt.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/ts.h>
#include <openssl/ocsp.h>
#include <sodium.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/chacha.h>
#include <cryptopp/poly1305.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <execution>
#include <immintrin.h>
#include <random>

namespace converter::security {

class EncryptionManager::Impl {
public:
    struct CryptoState {
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> cipher_ctx{nullptr, EVP_CIPHER_CTX_free};
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md_ctx{nullptr, EVP_MD_CTX_free};
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pkey_ctx{nullptr, EVP_PKEY_CTX_free};
        CryptoPP::AutoSeededRandomPool rng;
        std::unordered_map<std::string, SecureKey> key_cache;
        std::unordered_map<std::string, CertificateChain> cert_cache;
        mutable std::shared_mutex mutex;
        EncryptionMetrics metrics;
        HSMConfig hsm_config;
        bool hsm_enabled = false;
    };

    std::unordered_map<std::thread::id, std::unique_ptr<CryptoState>> thread_states;
    std::shared_mutex states_mutex;
    std::atomic<uint64_t> operations_count{0};
    std::atomic<uint64_t> bytes_encrypted{0};
    std::atomic<uint64_t> keys_generated{0};
    
    CryptoState& get_thread_state() {
        std::thread::id tid = std::this_thread::get_id();
        std::shared_lock lock(states_mutex);
        
        if (auto it = thread_states.find(tid); it != thread_states.end()) {
            return *it->second;
        }
        
        lock.unlock();
        std::unique_lock ulock(states_mutex);
        
        auto state = std::make_unique<CryptoState>();
        state->cipher_ctx.reset(EVP_CIPHER_CTX_new());
        state->md_ctx.reset(EVP_MD_CTX_new());
        
        auto& ref = *state;
        thread_states[tid] = std::move(state);
        return ref;
    }
    
    SecureKey generate_key(KeyType type, size_t key_size, const KeyDerivationParams& params) {
        auto& state = get_thread_state();
        
        SecureKey key;
        key.key_id = generate_key_id();
        key.type = type;
        key.size = key_size;
        key.created_timestamp = std::chrono::system_clock::now();
        key.algorithm = params.algorithm;
        key.usage_flags = params.usage_flags;
        
        switch (type) {
            case KeyType::SYMMETRIC:
                key.key_data = generate_symmetric_key(key_size, state);
                break;
            case KeyType::ASYMMETRIC_PRIVATE:
                key = generate_asymmetric_keypair(params.asymmetric_algorithm, key_size, state);
                break;
            case KeyType::DERIVED:
                key.key_data = derive_key_from_password(params.password, params.salt, key_size, params.kdf_algorithm, state);
                break;
            case KeyType::QUANTUM_RESISTANT:
                key.key_data = generate_post_quantum_key(params.pq_algorithm, key_size, state);
                break;
        }
        
        if (params.store_in_hsm && state.hsm_enabled) {
            store_key_in_hsm(key, state);
        }
        
        if (params.escrow_key) {
            escrow_key(key, params.escrow_params);
        }
        
        {
            std::unique_lock lock(state.mutex);
            state.key_cache[key.key_id] = key;
        }
        
        keys_generated++;
        return key;
    }
    
    std::string generate_key_id() {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dis;
        
        uint64_t id_part1 = dis(gen);
        uint64_t id_part2 = dis(gen);
        
        std::ostringstream oss;
        oss << std::hex << id_part1 << id_part2;
        return oss.str();
    }
    
    std::vector<uint8_t> generate_symmetric_key(size_t key_size, CryptoState& state) {
        std::vector<uint8_t> key(key_size);
        
        if (RAND_bytes(key.data(), static_cast<int>(key_size)) != 1) {
            throw std::runtime_error("Failed to generate random key");
        }
        
        apply_key_strengthening(key);
        
        return key;
    }
    
    void apply_key_strengthening(std::vector<uint8_t>& key) {
        std::vector<uint8_t> strengthened_key(key.size());
        
        for (size_t i = 0; i < key.size(); i += 16) {
            __m128i block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.data() + i));
            __m128i rounds = _mm_set1_epi32(0x1F);
            
            for (int round = 0; round < 16; ++round) {
                block = _mm_aeskeygenassist_si128(block, round);
                block = _mm_xor_si128(block, rounds);
            }
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(strengthened_key.data() + i), block);
        }
        
        key = std::move(strengthened_key);
    }
    
    SecureKey generate_asymmetric_keypair(AsymmetricAlgorithm algorithm, size_t key_size, CryptoState& state) {
        SecureKey key_pair;
        key_pair.key_id = generate_key_id();
        key_pair.type = KeyType::ASYMMETRIC_PRIVATE;
        key_pair.size = key_size;
        key_pair.created_timestamp = std::chrono::system_clock::now();
        
        switch (algorithm) {
            case AsymmetricAlgorithm::RSA:
                generate_rsa_keypair(key_pair, key_size, state);
                break;
            case AsymmetricAlgorithm::ECC_P256:
            case AsymmetricAlgorithm::ECC_P384:
            case AsymmetricAlgorithm::ECC_P521:
                generate_ecc_keypair(key_pair, algorithm, state);
                break;
            case AsymmetricAlgorithm::ED25519:
                generate_ed25519_keypair(key_pair, state);
                break;
            case AsymmetricAlgorithm::X25519:
                generate_x25519_keypair(key_pair, state);
                break;
        }
        
        return key_pair;
    }
    
    void generate_rsa_keypair(SecureKey& key_pair, size_t key_size, CryptoState& state) {
        state.pkey_ctx.reset(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
        
        if (EVP_PKEY_keygen_init(state.pkey_ctx.get()) <= 0) {
            throw std::runtime_error("RSA key generation initialization failed");
        }
        
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(state.pkey_ctx.get(), static_cast<int>(key_size)) <= 0) {
            throw std::runtime_error("RSA key size setting failed");
        }
        
        if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(state.pkey_ctx.get(), BN_value_one()) <= 0) {
            BIGNUM* pubexp = BN_new();
            BN_set_word(pubexp, 65537);
            EVP_PKEY_CTX_set_rsa_keygen_pubexp(state.pkey_ctx.get(), pubexp);
            BN_free(pubexp);
        }
        
        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(state.pkey_ctx.get(), &pkey) <= 0) {
            throw std::runtime_error("RSA key generation failed");
        }
        
        serialize_keypair(pkey, key_pair);
        EVP_PKEY_free(pkey);
    }
    
    void generate_ecc_keypair(SecureKey& key_pair, AsymmetricAlgorithm algorithm, CryptoState& state) {
        int nid = get_ecc_curve_nid(algorithm);
        
        state.pkey_ctx.reset(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
        
        if (EVP_PKEY_keygen_init(state.pkey_ctx.get()) <= 0) {
            throw std::runtime_error("ECC key generation initialization failed");
        }
        
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(state.pkey_ctx.get(), nid) <= 0) {
            throw std::runtime_error("ECC curve setting failed");
        }
        
        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(state.pkey_ctx.get(), &pkey) <= 0) {
            throw std::runtime_error("ECC key generation failed");
        }
        
        serialize_keypair(pkey, key_pair);
        EVP_PKEY_free(pkey);
    }
    
    int get_ecc_curve_nid(AsymmetricAlgorithm algorithm) {
        switch (algorithm) {
            case AsymmetricAlgorithm::ECC_P256: return NID_X9_62_prime256v1;
            case AsymmetricAlgorithm::ECC_P384: return NID_secp384r1;
            case AsymmetricAlgorithm::ECC_P521: return NID_secp521r1;
            default: return NID_X9_62_prime256v1;
        }
    }
    
    void generate_ed25519_keypair(SecureKey& key_pair, CryptoState& state) {
        std::vector<uint8_t> public_key(crypto_sign_ed25519_PUBLICKEYBYTES);
        std::vector<uint8_t> private_key(crypto_sign_ed25519_SECRETKEYBYTES);
        
        if (crypto_sign_ed25519_keypair(public_key.data(), private_key.data()) != 0) {
            throw std::runtime_error("Ed25519 key generation failed");
        }
        
        key_pair.key_data = private_key;
        key_pair.public_key = public_key;
    }
    
    void generate_x25519_keypair(SecureKey& key_pair, CryptoState& state) {
        std::vector<uint8_t> public_key(crypto_box_PUBLICKEYBYTES);
        std::vector<uint8_t> private_key(crypto_box_SECRETKEYBYTES);
        
        if (crypto_box_keypair(public_key.data(), private_key.data()) != 0) {
            throw std::runtime_error("X25519 key generation failed");
        }
        
        key_pair.key_data = private_key;
        key_pair.public_key = public_key;
    }
    
    void serialize_keypair(EVP_PKEY* pkey, SecureKey& key_pair) {
        std::unique_ptr<BIO, decltype(&BIO_free)> private_bio(BIO_new(BIO_s_mem()), BIO_free);
        std::unique_ptr<BIO, decltype(&BIO_free)> public_bio(BIO_new(BIO_s_mem()), BIO_free);
        
        if (PEM_write_bio_PrivateKey(private_bio.get(), pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            throw std::runtime_error("Private key serialization failed");
        }
        
        if (PEM_write_bio_PUBKEY(public_bio.get(), pkey) != 1) {
            throw std::runtime_error("Public key serialization failed");
        }
        
        key_pair.key_data = bio_to_vector(private_bio.get());
        key_pair.public_key = bio_to_vector(public_bio.get());
    }
    
    std::vector<uint8_t> bio_to_vector(BIO* bio) {
        BUF_MEM* mem = nullptr;
        BIO_get_mem_ptr(bio, &mem);
        return std::vector<uint8_t>(mem->data, mem->data + mem->length);
    }
    
    std::vector<uint8_t> derive_key_from_password(const std::vector<uint8_t>& password,
                                                 const std::vector<uint8_t>& salt,
                                                 size_t key_length,
                                                 KDFAlgorithm algorithm,
                                                 CryptoState& state) {
        std::vector<uint8_t> derived_key(key_length);
        
        switch (algorithm) {
            case KDFAlgorithm::PBKDF2_SHA256:
                derive_pbkdf2(password, salt, derived_key, 100000, EVP_sha256());
                break;
            case KDFAlgorithm::PBKDF2_SHA512:
                derive_pbkdf2(password, salt, derived_key, 100000, EVP_sha512());
                break;
            case KDFAlgorithm::SCRYPT:
                derive_scrypt(password, salt, derived_key);
                break;
            case KDFAlgorithm::ARGON2ID:
                derive_argon2(password, salt, derived_key);
                break;
            case KDFAlgorithm::HKDF_SHA256:
                derive_hkdf(password, salt, derived_key, EVP_sha256());
                break;
        }
        
        return derived_key;
    }
    
    void derive_pbkdf2(const std::vector<uint8_t>& password,
                      const std::vector<uint8_t>& salt,
                      std::vector<uint8_t>& derived_key,
                      int iterations,
                      const EVP_MD* md) {
        if (PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(password.data()),
                             static_cast<int>(password.size()),
                             salt.data(), static_cast<int>(salt.size()),
                             iterations, md,
                             static_cast<int>(derived_key.size()),
                             derived_key.data()) != 1) {
            throw std::runtime_error("PBKDF2 key derivation failed");
        }
    }
    
    void derive_scrypt(const std::vector<uint8_t>& password,
                      const std::vector<uint8_t>& salt,
                      std::vector<uint8_t>& derived_key) {
        if (EVP_PBE_scrypt(reinterpret_cast<const char*>(password.data()),
                          password.size(),
                          salt.data(), salt.size(),
                          16384, 8, 1,
                          0,
                          derived_key.data(), derived_key.size()) != 1) {
            throw std::runtime_error("Scrypt key derivation failed");
        }
    }
    
    void derive_argon2(const std::vector<uint8_t>& password,
                      const std::vector<uint8_t>& salt,
                      std::vector<uint8_t>& derived_key) {
        if (crypto_pwhash(derived_key.data(), derived_key.size(),
                         reinterpret_cast<const char*>(password.data()),
                         password.size(),
                         salt.data(),
                         crypto_pwhash_OPSLIMIT_INTERACTIVE,
                         crypto_pwhash_MEMLIMIT_INTERACTIVE,
                         crypto_pwhash_ALG_ARGON2ID13) != 0) {
            throw std::runtime_error("Argon2 key derivation failed");
        }
    }
    
    void derive_hkdf(const std::vector<uint8_t>& password,
                    const std::vector<uint8_t>& salt,
                    std::vector<uint8_t>& derived_key,
                    const EVP_MD* md) {
        if (HKDF(derived_key.data(), derived_key.size(),
                md,
                password.data(), password.size(),
                salt.data(), salt.size(),
                nullptr, 0) != 1) {
            throw std::runtime_error("HKDF key derivation failed");
        }
    }
    
    std::vector<uint8_t> generate_post_quantum_key(PostQuantumAlgorithm algorithm, size_t key_size, CryptoState& state) {
        // Post-quantum cryptography implementation
        // For now, return a strong random key
        return generate_symmetric_key(key_size, state);
    }
    
    void store_key_in_hsm(const SecureKey& key, CryptoState& state) {
        // HSM integration implementation
        // This would interface with hardware security modules
    }
    
    void escrow_key(const SecureKey& key, const EscrowParams& params) {
        // Key escrow implementation for compliance
        // Split key using Shamir's Secret Sharing
        split_key_for_escrow(key, params);
    }
    
    void split_key_for_escrow(const SecureKey& key, const EscrowParams& params) {
        // Shamir's Secret Sharing implementation
        size_t threshold = params.threshold;
        size_t total_shares = params.total_shares;
        
        std::vector<std::vector<uint8_t>> shares = generate_shamir_shares(key.key_data, threshold, total_shares);
        
        for (size_t i = 0; i < shares.size(); ++i) {
            store_escrow_share(shares[i], i, params.escrow_agents[i]);
        }
    }
    
    std::vector<std::vector<uint8_t>> generate_shamir_shares(const std::vector<uint8_t>& secret, size_t threshold, size_t total_shares) {
        // Simplified Shamir's Secret Sharing
        std::vector<std::vector<uint8_t>> shares(total_shares);
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dis(0, 255);
        
        for (size_t i = 0; i < total_shares; ++i) {
            shares[i].resize(secret.size() + 8);
            
            *reinterpret_cast<uint64_t*>(shares[i].data()) = i + 1;
            
            for (size_t j = 0; j < secret.size(); ++j) {
                shares[i][j + 8] = secret[j] ^ dis(gen);
            }
        }
        
        return shares;
    }
    
    void store_escrow_share(const std::vector<uint8_t>& share, size_t share_index, const std::string& agent_id) {
        // Store escrow share with designated agent
    }
    
    EncryptionResult encrypt_data(const std::vector<uint8_t>& data,
                                 const SecureKey& key,
                                 EncryptionAlgorithm algorithm,
                                 const EncryptionParams& params) {
        auto& state = get_thread_state();
        
        EncryptionResult result;
        result.algorithm = algorithm;
        result.key_id = key.key_id;
        result.timestamp = std::chrono::system_clock::now();
        
        switch (algorithm) {
            case EncryptionAlgorithm::AES_256_GCM:
                result = encrypt_aes_gcm(data, key, params, state);
                break;
            case EncryptionAlgorithm::AES_256_CTR:
                result = encrypt_aes_ctr(data, key, params, state);
                break;
            case EncryptionAlgorithm::CHACHA20_POLY1305:
                result = encrypt_chacha20_poly1305(data, key, params, state);
                break;
            case EncryptionAlgorithm::AES_256_XTS:
                result = encrypt_aes_xts(data, key, params, state);
                break;
            case EncryptionAlgorithm::SALSA20:
                result = encrypt_salsa20(data, key, params, state);
                break;
        }
        
        if (params.compress_before_encrypt) {
            result.compressed_data = compress_data(data);
        }
        
        if (params.sign_after_encrypt && !params.signing_key.key_data.empty()) {
            result.signature = sign_data(result.ciphertext, params.signing_key, state);
        }
        
        operations_count++;
        bytes_encrypted += data.size();
        
        return result;
    }
    
    EncryptionResult encrypt_aes_gcm(const std::vector<uint8_t>& data,
                                    const SecureKey& key,
                                    const EncryptionParams& params,
                                    CryptoState& state) {
        EncryptionResult result;
        
        std::vector<uint8_t> iv = generate_random_iv(12);
        result.iv = iv;
        
        if (EVP_EncryptInit_ex(state.cipher_ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            throw std::runtime_error("AES-GCM initialization failed");
        }
        
        if (EVP_CIPHER_CTX_ctrl(state.cipher_ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
            throw std::runtime_error("AES-GCM IV length setting failed");
        }
        
        if (EVP_EncryptInit_ex(state.cipher_ctx.get(), nullptr, nullptr, key.key_data.data(), iv.data()) != 1) {
            throw std::runtime_error("AES-GCM key/IV setting failed");
        }
        
        if (!params.aad.empty()) {
            int len;
            if (EVP_EncryptUpdate(state.cipher_ctx.get(), nullptr, &len, params.aad.data(), params.aad.size()) != 1) {
                throw std::runtime_error("AES-GCM AAD setting failed");
            }
        }
        
        std::vector<uint8_t> ciphertext(data.size());
        int len;
        
        if (EVP_EncryptUpdate(state.cipher_ctx.get(), ciphertext.data(), &len, data.data(), data.size()) != 1) {
            throw std::runtime_error("AES-GCM encryption failed");
        }
        
        if (EVP_EncryptFinal_ex(state.cipher_ctx.get(), ciphertext.data() + len, &len) != 1) {
            throw std::runtime_error("AES-GCM finalization failed");
        }
        
        std::vector<uint8_t> tag(16);
        if (EVP_CIPHER_CTX_ctrl(state.cipher_ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
            throw std::runtime_error("AES-GCM tag extraction failed");
        }
        
        result.ciphertext = ciphertext;
        result.tag = tag;
        result.aad = params.aad;
        
        return result;
    }
    
    EncryptionResult encrypt_aes_ctr(const std::vector<uint8_t>& data,
                                    const SecureKey& key,
                                    const EncryptionParams& params,
                                    CryptoState& state) {
        EncryptionResult result;
        
        std::vector<uint8_t> iv = generate_random_iv(16);
        result.iv = iv;
        
        if (EVP_EncryptInit_ex(state.cipher_ctx.get(), EVP_aes_256_ctr(), nullptr, key.key_data.data(), iv.data()) != 1) {
            throw std::runtime_error("AES-CTR initialization failed");
        }
        
        std::vector<uint8_t> ciphertext(data.size());
        int len;
        
        if (EVP_EncryptUpdate(state.cipher_ctx.get(), ciphertext.data(), &len, data.data(), data.size()) != 1) {
            throw std::runtime_error("AES-CTR encryption failed");
        }
        
        result.ciphertext = ciphertext;
        
        return result;
    }
    
    EncryptionResult encrypt_chacha20_poly1305(const std::vector<uint8_t>& data,
                                              const SecureKey& key,
                                              const EncryptionParams& params,
                                              CryptoState& state) {
        EncryptionResult result;
        
        std::vector<uint8_t> nonce = generate_random_iv(crypto_aead_chacha20poly1305_NPUBBYTES);
        result.iv = nonce;
        
        std::vector<uint8_t> ciphertext(data.size() + crypto_aead_chacha20poly1305_ABYTES);
        unsigned long long ciphertext_len;
        
        if (crypto_aead_chacha20poly1305_encrypt(
            ciphertext.data(), &ciphertext_len,
            data.data(), data.size(),
            params.aad.data(), params.aad.size(),
            nullptr,
            nonce.data(), key.key_data.data()) != 0) {
            throw std::runtime_error("ChaCha20-Poly1305 encryption failed");
        }
        
        ciphertext.resize(ciphertext_len);
        result.ciphertext = ciphertext;
        result.aad = params.aad;
        
        return result;
    }
    
    EncryptionResult encrypt_aes_xts(const std::vector<uint8_t>& data,
                                    const SecureKey& key,
                                    const EncryptionParams& params,
                                    CryptoState& state) {
        EncryptionResult result;
        
        std::vector<uint8_t> iv = generate_random_iv(16);
        result.iv = iv;
        
        if (EVP_EncryptInit_ex(state.cipher_ctx.get(), EVP_aes_256_xts(), nullptr, key.key_data.data(), iv.data()) != 1) {
            throw std::runtime_error("AES-XTS initialization failed");
        }
        
        std::vector<uint8_t> ciphertext(data.size());
        int len;
        
        if (EVP_EncryptUpdate(state.cipher_ctx.get(), ciphertext.data(), &len, data.data(), data.size()) != 1) {
            throw std::runtime_error("AES-XTS encryption failed");
        }
        
        result.ciphertext = ciphertext;
        
        return result;
    }
    
    EncryptionResult encrypt_salsa20(const std::vector<uint8_t>& data,
                                    const SecureKey& key,
                                    const EncryptionParams& params,
                                    CryptoState& state) {
        EncryptionResult result;
        
        std::vector<uint8_t> nonce = generate_random_iv(crypto_stream_salsa20_NONCEBYTES);
        result.iv = nonce;
        
        std::vector<uint8_t> ciphertext(data.size());
        
        if (crypto_stream_salsa20_xor(ciphertext.data(), data.data(), data.size(), nonce.data(), key.key_data.data()) != 0) {
            throw std::runtime_error("Salsa20 encryption failed");
        }
        
        result.ciphertext = ciphertext;
        
        return result;
    }
    
    std::vector<uint8_t> generate_random_iv(size_t size) {
        std::vector<uint8_t> iv(size);
        
        if (RAND_bytes(iv.data(), static_cast<int>(size)) != 1) {
            throw std::runtime_error("Failed to generate random IV");
        }
        
        return iv;
    }
    
    std::vector<uint8_t> compress_data(const std::vector<uint8_t>& data) {
        // Compression implementation
        return data;
    }
    
    std::vector<uint8_t> sign_data(const std::vector<uint8_t>& data, const SecureKey& signing_key, CryptoState& state) {
        if (signing_key.algorithm == AsymmetricAlgorithm::ED25519) {
            return sign_ed25519(data, signing_key);
        } else {
            return sign_ecdsa(data, signing_key, state);
        }
    }
    
    std::vector<uint8_t> sign_ed25519(const std::vector<uint8_t>& data, const SecureKey& signing_key) {
        std::vector<uint8_t> signature(crypto_sign_ed25519_BYTES);
        unsigned long long signature_len;
        
        if (crypto_sign_ed25519_detached(signature.data(), &signature_len,
                                        data.data(), data.size(),
                                        signing_key.key_data.data()) != 0) {
            throw std::runtime_error("Ed25519 signing failed");
        }
        
        signature.resize(signature_len);
        return signature;
    }
    
    std::vector<uint8_t> sign_ecdsa(const std::vector<uint8_t>& data, const SecureKey& signing_key, CryptoState& state) {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(signing_key.key_data.data(), signing_key.key_data.size()), BIO_free);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
        
        if (!pkey) {
            throw std::runtime_error("Invalid signing key");
        }
        
        if (EVP_DigestSignInit(state.md_ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) <= 0) {
            throw std::runtime_error("Signature initialization failed");
        }
        
        if (EVP_DigestSignUpdate(state.md_ctx.get(), data.data(), data.size()) <= 0) {
            throw std::runtime_error("Signature update failed");
        }
        
        size_t signature_len = 0;
        if (EVP_DigestSignFinal(state.md_ctx.get(), nullptr, &signature_len) <= 0) {
            throw std::runtime_error("Signature length calculation failed");
        }
        
        std::vector<uint8_t> signature(signature_len);
        if (EVP_DigestSignFinal(state.md_ctx.get(), signature.data(), &signature_len) <= 0) {
            throw std::runtime_error("Signature generation failed");
        }
        
        signature.resize(signature_len);
        return signature;
    }
    
    std::vector<uint8_t> decrypt_data(const EncryptionResult& encrypted_data,
                                     const SecureKey& key,
                                     const DecryptionParams& params) {
        auto& state = get_thread_state();
        
        if (encrypted_data.key_id != key.key_id) {
            throw std::runtime_error("Key ID mismatch");
        }
        
        if (!encrypted_data.signature.empty() && !params.verification_key.key_data.empty()) {
            if (!verify_signature(encrypted_data.ciphertext, encrypted_data.signature, params.verification_key, state)) {
                throw std::runtime_error("Signature verification failed");
            }
        }
        
        std::vector<uint8_t> plaintext;
        
        switch (encrypted_data.algorithm) {
            case EncryptionAlgorithm::AES_256_GCM:
                plaintext = decrypt_aes_gcm(encrypted_data, key, state);
                break;
            case EncryptionAlgorithm::AES_256_CTR:
                plaintext = decrypt_aes_ctr(encrypted_data, key, state);
                break;
            case EncryptionAlgorithm::CHACHA20_POLY1305:
                plaintext = decrypt_chacha20_poly1305(encrypted_data, key, state);
                break;
            case EncryptionAlgorithm::AES_256_XTS:
                plaintext = decrypt_aes_xts(encrypted_data, key, state);
                break;
            case EncryptionAlgorithm::SALSA20:
                plaintext = decrypt_salsa20(encrypted_data, key, state);
                break;
        }
        
        if (!encrypted_data.compressed_data.empty() && params.decompress_after_decrypt) {
            plaintext = decompress_data(plaintext);
        }
        
        operations_count++;
        
        return plaintext;
    }
    
    std::vector<uint8_t> decrypt_aes_gcm(const EncryptionResult& encrypted_data, const SecureKey& key, CryptoState& state) {
        if (EVP_DecryptInit_ex(state.cipher_ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            throw std::runtime_error("AES-GCM decryption initialization failed");
        }
        
        if (EVP_CIPHER_CTX_ctrl(state.cipher_ctx.get(), EVP_CTRL_GCM_SET_IVLEN, encrypted_data.iv.size(), nullptr) != 1) {
            throw std::runtime_error("AES-GCM IV length setting failed");
        }
        
        if (EVP_DecryptInit_ex(state.cipher_ctx.get(), nullptr, nullptr, key.key_data.data(), encrypted_data.iv.data()) != 1) {
            throw std::runtime_error("AES-GCM key/IV setting failed");
        }
        
        if (!encrypted_data.aad.empty()) {
            int len;
            if (EVP_DecryptUpdate(state.cipher_ctx.get(), nullptr, &len, encrypted_data.aad.data(), encrypted_data.aad.size()) != 1) {
                throw std::runtime_error("AES-GCM AAD setting failed");
            }
        }
        
        std::vector<uint8_t> plaintext(encrypted_data.ciphertext.size());
        int len;
        
        if (EVP_DecryptUpdate(state.cipher_ctx.get(), plaintext.data(), &len, encrypted_data.ciphertext.data(), encrypted_data.ciphertext.size()) != 1) {
            throw std::runtime_error("AES-GCM decryption failed");
        }
        
        if (EVP_CIPHER_CTX_ctrl(state.cipher_ctx.get(), EVP_CTRL_GCM_SET_TAG, encrypted_data.tag.size(), const_cast<uint8_t*>(encrypted_data.tag.data())) != 1) {
            throw std::runtime_error("AES-GCM tag setting failed");
        }
        
        if (EVP_DecryptFinal_ex(state.cipher_ctx.get(), plaintext.data() + len, &len) != 1) {
            throw std::runtime_error("AES-GCM authentication failed");
        }
        
        return plaintext;
    }
    
    std::vector<uint8_t> decrypt_aes_ctr(const EncryptionResult& encrypted_data, const SecureKey& key, CryptoState& state) {
        if (EVP_DecryptInit_ex(state.cipher_ctx.get(), EVP_aes_256_ctr(), nullptr, key.key_data.data(), encrypted_data.iv.data()) != 1) {
            throw std::runtime_error("AES-CTR decryption initialization failed");
        }
        
        std::vector<uint8_t> plaintext(encrypted_data.ciphertext.size());
        int len;
        
        if (EVP_DecryptUpdate(state.cipher_ctx.get(), plaintext.data(), &len, encrypted_data.ciphertext.data(), encrypted_data.ciphertext.size()) != 1) {
            throw std::runtime_error("AES-CTR decryption failed");
        }
        
        return plaintext;
    }
    
    std::vector<uint8_t> decrypt_chacha20_poly1305(const EncryptionResult& encrypted_data, const SecureKey& key, CryptoState& state) {
        std::vector<uint8_t> plaintext(encrypted_data.ciphertext.size() - crypto_aead_chacha20poly1305_ABYTES);
        unsigned long long plaintext_len;
        
        if (crypto_aead_chacha20poly1305_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,
            encrypted_data.ciphertext.data(), encrypted_data.ciphertext.size(),
            encrypted_data.aad.data(), encrypted_data.aad.size(),
            encrypted_data.iv.data(), key.key_data.data()) != 0) {
            throw std::runtime_error("ChaCha20-Poly1305 decryption failed");
        }
        
        plaintext.resize(plaintext_len);
        return plaintext;
    }
    
    std::vector<uint8_t> decrypt_aes_xts(const EncryptionResult& encrypted_data, const SecureKey& key, CryptoState& state) {
        if (EVP_DecryptInit_ex(state.cipher_ctx.get(), EVP_aes_256_xts(), nullptr, key.key_data.data(), encrypted_data.iv.data()) != 1) {
            throw std::runtime_error("AES-XTS decryption initialization failed");
        }
        
        std::vector<uint8_t> plaintext(encrypted_data.ciphertext.size());
        int len;
        
        if (EVP_DecryptUpdate(state.cipher_ctx.get(), plaintext.data(), &len, encrypted_data.ciphertext.data(), encrypted_data.ciphertext.size()) != 1) {
            throw std::runtime_error("AES-XTS decryption failed");
        }
        
        return plaintext;
    }
    
    std::vector<uint8_t> decrypt_salsa20(const EncryptionResult& encrypted_data, const SecureKey& key, CryptoState& state) {
        std::vector<uint8_t> plaintext(encrypted_data.ciphertext.size());
        
        if (crypto_stream_salsa20_xor(plaintext.data(), encrypted_data.ciphertext.data(), encrypted_data.ciphertext.size(), encrypted_data.iv.data(), key.key_data.data()) != 0) {
            throw std::runtime_error("Salsa20 decryption failed");
        }
        
        return plaintext;
    }
    
    bool verify_signature(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature, const SecureKey& verification_key, CryptoState& state) {
        if (verification_key.algorithm == AsymmetricAlgorithm::ED25519) {
            return verify_ed25519(data, signature, verification_key);
        } else {
            return verify_ecdsa(data, signature, verification_key, state);
        }
    }
    
    bool verify_ed25519(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature, const SecureKey& verification_key) {
        return crypto_sign_ed25519_verify_detached(signature.data(), data.data(), data.size(), verification_key.public_key.data()) == 0;
    }
    
    bool verify_ecdsa(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature, const SecureKey& verification_key, CryptoState& state) {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(verification_key.public_key.data(), verification_key.public_key.size()), BIO_free);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
        
        if (!pkey) {
            return false;
        }
        
        if (EVP_DigestVerifyInit(state.md_ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) <= 0) {
            return false;
        }
        
        if (EVP_DigestVerifyUpdate(state.md_ctx.get(), data.data(), data.size()) <= 0) {
            return false;
        }
        
        return EVP_DigestVerifyFinal(state.md_ctx.get(), signature.data(), signature.size()) == 1;
    }
    
    std::vector<uint8_t> decompress_data(const std::vector<uint8_t>& compressed_data) {
        // Decompression implementation
        return compressed_data;
    }
    
    void update_metrics() {
        auto& state = get_thread_state();
        std::unique_lock lock(state.mutex);
        
        state.metrics.operations_count = operations_count.load();
        state.metrics.bytes_encrypted = bytes_encrypted.load();
        state.metrics.keys_generated = keys_generated.load();
        state.metrics.throughput = calculate_throughput();
    }
    
    double calculate_throughput() {
        static auto start_time = std::chrono::high_resolution_clock::now();
        auto current_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time);
        
        if (duration.count() == 0) return 0.0;
        
        return static_cast<double>(bytes_encrypted.load()) / duration.count();
    }
};

EncryptionManager::EncryptionManager() : pimpl(std::make_unique<Impl>()) {
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
}

EncryptionManager::~EncryptionManager() = default;

SecureKey EncryptionManager::generate_key(KeyType type, size_t key_size, const KeyDerivationParams& params) {
    return pimpl->generate_key(type, key_size, params);
}

EncryptionResult EncryptionManager::encrypt_data(const std::vector<uint8_t>& data, const SecureKey& key, EncryptionAlgorithm algorithm, const EncryptionParams& params) {
    return pimpl->encrypt_data(data, key, algorithm, params);
}

std::vector<uint8_t> EncryptionManager::decrypt_data(const EncryptionResult& encrypted_data, const SecureKey& key, const DecryptionParams& params) {
    return pimpl->decrypt_data(encrypted_data, key, params);
}

EncryptionMetrics EncryptionManager::get_metrics() const {
    auto& state = pimpl->get_thread_state();
    std::shared_lock lock(state.mutex);
    return state.metrics;
}

} 