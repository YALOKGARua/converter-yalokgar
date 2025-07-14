#pragma once

#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <chrono>
#include <cstdint>

namespace converter::security {

enum class KeyType {
    SYMMETRIC, ASYMMETRIC_PRIVATE, ASYMMETRIC_PUBLIC, DERIVED, QUANTUM_RESISTANT
};

enum class EncryptionAlgorithm {
    AES_256_GCM, AES_256_CTR, AES_256_XTS, CHACHA20_POLY1305, SALSA20, UNKNOWN
};

enum class AsymmetricAlgorithm {
    RSA, ECC_P256, ECC_P384, ECC_P521, ED25519, X25519
};

enum class KDFAlgorithm {
    PBKDF2_SHA256, PBKDF2_SHA512, SCRYPT, ARGON2ID, HKDF_SHA256
};

enum class PostQuantumAlgorithm {
    KYBER, DILITHIUM, FALCON, SPHINCS_PLUS
};

struct HSMConfig {
    std::string provider;
    std::string slot_id;
    std::string pin;
    bool use_hardware_rng;
};

struct EscrowParams {
    size_t threshold;
    size_t total_shares;
    std::vector<std::string> escrow_agents;
};

struct KeyDerivationParams {
    std::vector<uint8_t> password;
    std::vector<uint8_t> salt;
    KDFAlgorithm kdf_algorithm;
    AsymmetricAlgorithm asymmetric_algorithm;
    PostQuantumAlgorithm pq_algorithm;
    std::string algorithm;
    uint32_t usage_flags;
    bool store_in_hsm;
    bool escrow_key;
    EscrowParams escrow_params;
};

struct SecureKey {
    std::string key_id;
    KeyType type;
    std::vector<uint8_t> key_data;
    std::vector<uint8_t> public_key;
    size_t size;
    std::chrono::system_clock::time_point created_timestamp;
    std::chrono::system_clock::time_point expiry_timestamp;
    std::string algorithm;
    uint32_t usage_flags;
    bool is_hardware_backed;
    std::vector<uint8_t> wrapped_key;
};

struct EncryptionParams {
    std::vector<uint8_t> aad;
    bool compress_before_encrypt;
    bool sign_after_encrypt;
    SecureKey signing_key;
};

struct DecryptionParams {
    bool decompress_after_decrypt;
    bool verify_signature;
    SecureKey verification_key;
};

struct EncryptionResult {
    std::string key_id;
    EncryptionAlgorithm algorithm;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> tag;
    std::vector<uint8_t> aad;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> compressed_data;
    std::chrono::system_clock::time_point timestamp;
};

struct EncryptionMetrics {
    uint64_t operations_count;
    uint64_t bytes_encrypted;
    uint64_t keys_generated;
    double throughput;
    std::chrono::steady_clock::time_point last_operation;
};

class EncryptionManager {
public:
    EncryptionManager();
    ~EncryptionManager();

    SecureKey generate_key(KeyType type, size_t key_size, const KeyDerivationParams& params);
    
    EncryptionResult encrypt_data(const std::vector<uint8_t>& data, 
                                 const SecureKey& key, 
                                 EncryptionAlgorithm algorithm, 
                                 const EncryptionParams& params = {});
    
    std::vector<uint8_t> decrypt_data(const EncryptionResult& encrypted_data, 
                                     const SecureKey& key, 
                                     const DecryptionParams& params = {});
    
    EncryptionMetrics get_metrics() const;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

} 