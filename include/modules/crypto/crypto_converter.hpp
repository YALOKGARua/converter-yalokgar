#pragma once

#include "../../core/converter_engine.hpp"
#include "../../core/format_types.hpp"
#include <memory>
#include <vector>
#include <string>
#include <unordered_map>
#include <expected>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

namespace converter::modules::crypto {

enum class CryptoAlgorithm {
    AES_128_ECB, AES_192_ECB, AES_256_ECB,
    AES_128_CBC, AES_192_CBC, AES_256_CBC,
    AES_128_CFB, AES_192_CFB, AES_256_CFB,
    AES_128_OFB, AES_192_OFB, AES_256_OFB,
    AES_128_CTR, AES_192_CTR, AES_256_CTR,
    AES_128_GCM, AES_192_GCM, AES_256_GCM,
    AES_128_CCM, AES_192_CCM, AES_256_CCM,
    AES_128_XTS, AES_256_XTS,
    DES_ECB, DES_CBC, DES_CFB, DES_OFB,
    DES_EDE_ECB, DES_EDE_CBC, DES_EDE_CFB, DES_EDE_OFB,
    DES_EDE3_ECB, DES_EDE3_CBC, DES_EDE3_CFB, DES_EDE3_OFB,
    BLOWFISH_ECB, BLOWFISH_CBC, BLOWFISH_CFB, BLOWFISH_OFB,
    CAST5_ECB, CAST5_CBC, CAST5_CFB, CAST5_OFB,
    RC2_ECB, RC2_CBC, RC2_CFB, RC2_OFB,
    RC4, RC4_40, RC4_HMAC_MD5,
    RC5_32_12_16_ECB, RC5_32_12_16_CBC, RC5_32_12_16_CFB, RC5_32_12_16_OFB,
    IDEA_ECB, IDEA_CBC, IDEA_CFB, IDEA_OFB,
    SEED_ECB, SEED_CBC, SEED_CFB, SEED_OFB,
    CAMELLIA_128_ECB, CAMELLIA_192_ECB, CAMELLIA_256_ECB,
    CAMELLIA_128_CBC, CAMELLIA_192_CBC, CAMELLIA_256_CBC,
    CAMELLIA_128_CFB, CAMELLIA_192_CFB, CAMELLIA_256_CFB,
    CAMELLIA_128_OFB, CAMELLIA_192_OFB, CAMELLIA_256_OFB,
    ARIA_128_ECB, ARIA_192_ECB, ARIA_256_ECB,
    ARIA_128_CBC, ARIA_192_CBC, ARIA_256_CBC,
    ARIA_128_CFB, ARIA_192_CFB, ARIA_256_CFB,
    ARIA_128_OFB, ARIA_192_OFB, ARIA_256_OFB,
    ARIA_128_CTR, ARIA_192_CTR, ARIA_256_CTR,
    ARIA_128_GCM, ARIA_192_GCM, ARIA_256_GCM,
    ARIA_128_CCM, ARIA_192_CCM, ARIA_256_CCM,
    CHACHA20, CHACHA20_POLY1305,
    SM4_ECB, SM4_CBC, SM4_CFB, SM4_OFB, SM4_CTR,
    RSA_PKCS1, RSA_PKCS1_OAEP, RSA_PSS,
    ECDSA_P256, ECDSA_P384, ECDSA_P521,
    ECDH_P256, ECDH_P384, ECDH_P521,
    ED25519, ED448, X25519, X448,
    DSA_1024, DSA_2048, DSA_3072,
    DH_1024, DH_2048, DH_3072, DH_4096
};

enum class HashAlgorithm {
    MD5, SHA1, SHA224, SHA256, SHA384, SHA512,
    SHA512_224, SHA512_256, SHA3_224, SHA3_256,
    SHA3_384, SHA3_512, SHAKE128, SHAKE256,
    BLAKE2B_256, BLAKE2B_384, BLAKE2B_512,
    BLAKE2S_128, BLAKE2S_160, BLAKE2S_224, BLAKE2S_256,
    RIPEMD160, WHIRLPOOL, SM3,
    PBKDF2_SHA1, PBKDF2_SHA256, PBKDF2_SHA512,
    SCRYPT, ARGON2I, ARGON2D, ARGON2ID,
    BCRYPT, HMAC_MD5, HMAC_SHA1, HMAC_SHA256,
    HMAC_SHA384, HMAC_SHA512, POLY1305,
    SipHash_2_4, SipHash_4_8
};

enum class KeyFormat {
    RAW, HEX, BASE64, PEM, DER, PKCS8, PKCS12,
    JWK, SSH_PUBLIC, SSH_PRIVATE, OPENSSH,
    PUTTY_PUBLIC, PUTTY_PRIVATE, GPGKEY
};

enum class CertificateFormat {
    X509_PEM, X509_DER, PKCS7_PEM, PKCS7_DER,
    PKCS12, CRL_PEM, CRL_DER, CSR_PEM, CSR_DER,
    JKS, P7B, P7C, CRT, CER, KEY, PFX
};

enum class EncodingFormat {
    BINARY, HEX, BASE64, BASE32, BASE58, BASE85,
    UUENCODE, YENCODE, QUOTED_PRINTABLE, URL_ENCODE,
    ROT13, ROT47, ATBASH, CAESAR, VIGENERE,
    MORSE_CODE, BRAILLE, ASCII_ARMOR, RADIX64
};

struct CryptoMetadata {
    std::string algorithm_name;
    std::string mode_name;
    std::string padding_name;
    std::size_t key_size;
    std::size_t iv_size;
    std::size_t block_size;
    std::size_t tag_size;
    std::size_t salt_size;
    std::size_t iteration_count;
    std::string key_derivation_function;
    std::string compression_algorithm;
    std::string encoding_format;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> tag;
    std::vector<uint8_t> aad;
    std::unordered_map<std::string, std::string> parameters;
    std::string version;
    std::string created_by;
    std::string created_at;
    std::string comment;
    bool is_authenticated;
    bool is_compressed;
    bool is_armored;
    std::string checksum;
    std::string signature;
};

struct CryptoOptions {
    std::optional<CryptoAlgorithm> algorithm;
    std::optional<HashAlgorithm> hash_algorithm;
    std::optional<KeyFormat> key_format;
    std::optional<CertificateFormat> certificate_format;
    std::optional<EncodingFormat> encoding_format;
    std::optional<std::string> password;
    std::optional<std::string> key_file;
    std::optional<std::string> certificate_file;
    std::optional<std::vector<uint8_t>> key_data;
    std::optional<std::vector<uint8_t>> iv;
    std::optional<std::vector<uint8_t>> salt;
    std::optional<std::vector<uint8_t>> aad;
    std::optional<std::size_t> key_size;
    std::optional<std::size_t> iv_size;
    std::optional<std::size_t> tag_size;
    std::optional<std::size_t> iteration_count;
    std::optional<std::string> padding_mode;
    std::optional<std::string> cipher_mode;
    std::optional<std::string> key_derivation_function;
    std::optional<bool> generate_key;
    std::optional<bool> generate_iv;
    std::optional<bool> generate_salt;
    std::optional<bool> verify_signature;
    std::optional<bool> compress_before_encrypt;
    std::optional<bool> armor_output;
    std::optional<bool> include_metadata;
    std::optional<std::string> compression_algorithm;
    std::optional<int> compression_level;
    std::optional<std::string> random_source;
    std::optional<std::size_t> memory_cost;
    std::optional<std::size_t> time_cost;
    std::optional<std::size_t> parallelism;
    std::optional<std::string> associated_data;
    std::optional<std::string> nonce;
    std::optional<std::string> counter;
    std::optional<std::string> tweak;
    std::optional<bool> constant_time;
    std::optional<bool> secure_memory;
    std::optional<bool> zeroize_memory;
    std::optional<std::string> entropy_source;
    std::optional<std::size_t> entropy_bits;
    std::optional<bool> validate_input;
    std::optional<bool> strict_mode;
    std::optional<std::string> curve_name;
    std::optional<std::size_t> rsa_key_size;
    std::optional<std::size_t> dh_prime_size;
    std::optional<std::string> signature_algorithm;
    std::optional<std::string> mgf_algorithm;
    std::optional<std::size_t> salt_length;
    std::optional<std::string> label;
    std::optional<bool> use_pss_padding;
    std::optional<bool> use_oaep_padding;
    std::optional<std::string> hash_function;
    std::optional<std::string> kdf_algorithm;
    std::optional<std::string> mac_algorithm;
    std::optional<std::size_t> mac_size;
    std::optional<bool> encrypt_then_mac;
    std::optional<bool> mac_then_encrypt;
    std::optional<std::string> authenticated_encryption;
    std::optional<std::size_t> min_key_size;
    std::optional<std::size_t> max_key_size;
    std::optional<std::vector<std::string>> supported_key_sizes;
    std::optional<std::vector<std::string>> supported_modes;
    std::optional<std::vector<std::string>> supported_paddings;
    std::optional<bool> hardware_acceleration;
    std::optional<std::string> provider_name;
    std::optional<std::string> engine_name;
    std::optional<std::unordered_map<std::string, std::string>> custom_parameters;
};

class CryptoBuffer {
public:
    CryptoBuffer();
    CryptoBuffer(const std::string& filename);
    CryptoBuffer(std::vector<uint8_t> data);
    CryptoBuffer(const std::string& data, EncodingFormat format);
    ~CryptoBuffer();
    
    std::expected<void, std::error_code> load_from_file(const std::string& filename);
    std::expected<void, std::error_code> load_from_memory(std::span<const uint8_t> data);
    std::expected<void, std::error_code> load_from_string(const std::string& data, EncodingFormat format);
    std::expected<void, std::error_code> save_to_file(const std::string& filename, const CryptoOptions& options = {});
    std::expected<std::vector<uint8_t>, std::error_code> save_to_memory(const CryptoOptions& options = {});
    std::expected<std::string, std::error_code> save_to_string(EncodingFormat format, const CryptoOptions& options = {});
    
    const CryptoMetadata& metadata() const { return metadata_; }
    CryptoMetadata& metadata() { return metadata_; }
    
    const std::vector<uint8_t>& data() const { return data_; }
    std::vector<uint8_t>& data() { return data_; }
    
    std::expected<void, std::error_code> encrypt(CryptoAlgorithm algorithm, const std::vector<uint8_t>& key, const CryptoOptions& options = {});
    std::expected<void, std::error_code> decrypt(CryptoAlgorithm algorithm, const std::vector<uint8_t>& key, const CryptoOptions& options = {});
    std::expected<void, std::error_code> encrypt_with_password(CryptoAlgorithm algorithm, const std::string& password, const CryptoOptions& options = {});
    std::expected<void, std::error_code> decrypt_with_password(CryptoAlgorithm algorithm, const std::string& password, const CryptoOptions& options = {});
    
    std::expected<void, std::error_code> sign_data(const std::vector<uint8_t>& private_key, CryptoAlgorithm algorithm, const CryptoOptions& options = {});
    std::expected<bool, std::error_code> verify_signature(const std::vector<uint8_t>& public_key, const std::vector<uint8_t>& signature, CryptoAlgorithm algorithm, const CryptoOptions& options = {});
    std::expected<void, std::error_code> sign_with_certificate(const std::string& certificate_file, const std::string& private_key_file, const CryptoOptions& options = {});
    std::expected<bool, std::error_code> verify_with_certificate(const std::string& certificate_file, const std::vector<uint8_t>& signature, const CryptoOptions& options = {});
    
    std::expected<std::vector<uint8_t>, std::error_code> compute_hash(HashAlgorithm algorithm, const CryptoOptions& options = {});
    std::expected<std::vector<uint8_t>, std::error_code> compute_hmac(HashAlgorithm algorithm, const std::vector<uint8_t>& key, const CryptoOptions& options = {});
    std::expected<std::vector<uint8_t>, std::error_code> compute_pbkdf2(const std::string& password, const std::vector<uint8_t>& salt, HashAlgorithm algorithm, std::size_t iterations, std::size_t key_length);
    std::expected<std::vector<uint8_t>, std::error_code> compute_scrypt(const std::string& password, const std::vector<uint8_t>& salt, std::size_t n, std::size_t r, std::size_t p, std::size_t key_length);
    std::expected<std::vector<uint8_t>, std::error_code> compute_argon2(const std::string& password, const std::vector<uint8_t>& salt, std::size_t memory_cost, std::size_t time_cost, std::size_t parallelism, std::size_t key_length, HashAlgorithm variant);
    
    std::expected<void, std::error_code> encode_data(EncodingFormat format, const CryptoOptions& options = {});
    std::expected<void, std::error_code> decode_data(EncodingFormat format, const CryptoOptions& options = {});
    
    std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, std::error_code> generate_key_pair(CryptoAlgorithm algorithm, std::size_t key_size);
    std::expected<std::vector<uint8_t>, std::error_code> generate_symmetric_key(CryptoAlgorithm algorithm, std::size_t key_size = 0);
    std::expected<std::vector<uint8_t>, std::error_code> generate_random_bytes(std::size_t size);
    std::expected<std::vector<uint8_t>, std::error_code> generate_salt(std::size_t size = 16);
    std::expected<std::vector<uint8_t>, std::error_code> generate_iv(CryptoAlgorithm algorithm);
    std::expected<std::vector<uint8_t>, std::error_code> generate_nonce(std::size_t size = 12);
    
    std::expected<void, std::error_code> derive_key_from_password(const std::string& password, const std::vector<uint8_t>& salt, HashAlgorithm kdf, const CryptoOptions& options = {});
    std::expected<std::vector<uint8_t>, std::error_code> perform_key_exchange(const std::vector<uint8_t>& private_key, const std::vector<uint8_t>& public_key, CryptoAlgorithm algorithm);
    std::expected<std::vector<uint8_t>, std::error_code> wrap_key(const std::vector<uint8_t>& key_to_wrap, const std::vector<uint8_t>& wrapping_key, CryptoAlgorithm algorithm);
    std::expected<std::vector<uint8_t>, std::error_code> unwrap_key(const std::vector<uint8_t>& wrapped_key, const std::vector<uint8_t>& unwrapping_key, CryptoAlgorithm algorithm);
    
    std::expected<void, std::error_code> compress_data(const std::string& algorithm = "gzip", int level = 6);
    std::expected<void, std::error_code> decompress_data(const std::string& algorithm = "gzip");
    
    std::expected<void, std::error_code> add_armor(const std::string& type = "MESSAGE", const std::unordered_map<std::string, std::string>& headers = {});
    std::expected<void, std::error_code> remove_armor();
    std::expected<bool, std::error_code> is_armored() const;
    std::expected<std::unordered_map<std::string, std::string>, std::error_code> get_armor_headers() const;
    
    std::expected<void, std::error_code> add_integrity_check();
    std::expected<bool, std::error_code> verify_integrity();
    std::expected<void, std::error_code> add_timestamp();
    std::expected<std::string, std::error_code> get_timestamp();
    
    std::expected<void, std::error_code> create_secure_container(const std::string& password, const CryptoOptions& options = {});
    std::expected<void, std::error_code> open_secure_container(const std::string& password, const CryptoOptions& options = {});
    
    std::expected<void, std::error_code> steganography_embed(const std::vector<uint8_t>& cover_data, const std::string& method = "lsb");
    std::expected<std::vector<uint8_t>, std::error_code> steganography_extract(const std::string& method = "lsb");
    
    std::expected<void, std::error_code> obfuscate_data(const std::string& method = "xor", const std::vector<uint8_t>& key = {});
    std::expected<void, std::error_code> deobfuscate_data(const std::string& method = "xor", const std::vector<uint8_t>& key = {});
    
    std::expected<void, std::error_code> split_secret(std::size_t threshold, std::size_t total_shares, std::vector<std::vector<uint8_t>>& shares);
    std::expected<void, std::error_code> reconstruct_secret(const std::vector<std::vector<uint8_t>>& shares, std::size_t threshold);
    
    std::expected<void, std::error_code> create_merkle_tree(std::vector<std::vector<uint8_t>>& tree_nodes, std::vector<uint8_t>& root_hash);
    std::expected<bool, std::error_code> verify_merkle_proof(const std::vector<uint8_t>& leaf_hash, const std::vector<std::vector<uint8_t>>& proof, const std::vector<uint8_t>& root_hash);
    
    std::expected<void, std::error_code> zero_knowledge_proof_generate(const std::vector<uint8_t>& secret, const std::vector<uint8_t>& public_input, std::vector<uint8_t>& proof);
    std::expected<bool, std::error_code> zero_knowledge_proof_verify(const std::vector<uint8_t>& proof, const std::vector<uint8_t>& public_input);
    
    std::expected<void, std::error_code> homomorphic_encrypt(const std::vector<uint8_t>& public_key, const std::string& scheme = "paillier");
    std::expected<void, std::error_code> homomorphic_decrypt(const std::vector<uint8_t>& private_key, const std::string& scheme = "paillier");
    std::expected<void, std::error_code> homomorphic_add(const CryptoBuffer& other);
    std::expected<void, std::error_code> homomorphic_multiply(const CryptoBuffer& other);
    
    std::expected<void, std::error_code> quantum_resistant_encrypt(const std::vector<uint8_t>& public_key, const std::string& algorithm = "kyber");
    std::expected<void, std::error_code> quantum_resistant_decrypt(const std::vector<uint8_t>& private_key, const std::string& algorithm = "kyber");
    std::expected<void, std::error_code> quantum_resistant_sign(const std::vector<uint8_t>& private_key, const std::string& algorithm = "dilithium");
    std::expected<bool, std::error_code> quantum_resistant_verify(const std::vector<uint8_t>& public_key, const std::vector<uint8_t>& signature, const std::string& algorithm = "dilithium");
    
    std::expected<void, std::error_code> format_as_pem(const std::string& type, const std::unordered_map<std::string, std::string>& headers = {});
    std::expected<void, std::error_code> parse_pem(std::string& type, std::unordered_map<std::string, std::string>& headers);
    std::expected<void, std::error_code> format_as_der();
    std::expected<void, std::error_code> parse_der();
    
    std::expected<void, std::error_code> convert_key_format(KeyFormat from_format, KeyFormat to_format, const CryptoOptions& options = {});
    std::expected<void, std::error_code> convert_certificate_format(CertificateFormat from_format, CertificateFormat to_format, const CryptoOptions& options = {});
    
    std::expected<void, std::error_code> benchmark_algorithm(CryptoAlgorithm algorithm, std::size_t data_size, std::size_t iterations, std::unordered_map<std::string, double>& results);
    std::expected<void, std::error_code> analyze_entropy(std::unordered_map<std::string, double>& analysis);
    std::expected<void, std::error_code> analyze_randomness(std::unordered_map<std::string, double>& analysis);
    
    std::expected<void, std::error_code> secure_erase();
    std::expected<void, std::error_code> constant_time_compare(const CryptoBuffer& other, bool& equal);
    
    bool is_valid() const { return !data_.empty(); }
    std::size_t size() const { return data_.size(); }
    bool is_encrypted() const { return metadata_.algorithm_name != ""; }
    bool is_signed() const { return !metadata_.signature.empty(); }
    bool has_checksum() const { return !metadata_.checksum.empty(); }
    
private:
    std::vector<uint8_t> data_;
    CryptoMetadata metadata_;
    
    std::expected<void, std::error_code> initialize_crypto_engine();
    std::expected<const EVP_CIPHER*, std::error_code> get_cipher(CryptoAlgorithm algorithm);
    std::expected<const EVP_MD*, std::error_code> get_digest(HashAlgorithm algorithm);
    std::expected<void, std::error_code> setup_cipher_context(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, bool encrypt);
    
    class CryptoEngine;
    std::unique_ptr<CryptoEngine> engine_;
};

class CryptoConverter : public converter::core::ConversionTask<CryptoBuffer, CryptoBuffer> {
public:
    CryptoConverter(CryptoBuffer input, converter::core::ConversionOptions options, CryptoOptions processing_options = {});
    
    result_type execute() override;
    std::future<result_type> execute_async() override;
    std::generator<result_type> execute_stream() override;
    
    bool validate_input() const override;
    bool can_convert() const override;
    std::string get_format_info() const override;
    std::size_t estimate_output_size() const override;
    std::chrono::milliseconds estimate_duration() const override;
    
    void set_target_algorithm(CryptoAlgorithm algorithm) { target_algorithm_ = algorithm; }
    void set_target_encoding(EncodingFormat format) { target_encoding_ = format; }
    void set_processing_options(const CryptoOptions& options) { processing_options_ = options; }
    
    static std::expected<CryptoBuffer, std::error_code> load_from_file(const std::string& filename);
    static std::expected<void, std::error_code> save_to_file(const CryptoBuffer& crypto, const std::string& filename, const CryptoOptions& options = {});
    
    static std::expected<std::vector<CryptoBuffer>, std::error_code> batch_convert(
        const std::vector<std::string>& input_files,
        const std::string& output_directory,
        CryptoAlgorithm target_algorithm,
        const CryptoOptions& options = {}
    );
    
    static std::expected<void, std::error_code> encrypt_file(const std::string& input_file, const std::string& output_file, CryptoAlgorithm algorithm, const std::string& password, const CryptoOptions& options = {});
    static std::expected<void, std::error_code> decrypt_file(const std::string& input_file, const std::string& output_file, CryptoAlgorithm algorithm, const std::string& password, const CryptoOptions& options = {});
    
    static std::expected<void, std::error_code> sign_file(const std::string& input_file, const std::string& signature_file, const std::string& private_key_file, CryptoAlgorithm algorithm, const CryptoOptions& options = {});
    static std::expected<bool, std::error_code> verify_file(const std::string& input_file, const std::string& signature_file, const std::string& public_key_file, CryptoAlgorithm algorithm, const CryptoOptions& options = {});
    
    static std::expected<void, std::error_code> hash_file(const std::string& input_file, const std::string& output_file, HashAlgorithm algorithm, const CryptoOptions& options = {});
    static std::expected<void, std::error_code> hmac_file(const std::string& input_file, const std::string& output_file, HashAlgorithm algorithm, const std::vector<uint8_t>& key, const CryptoOptions& options = {});
    
    static std::expected<void, std::error_code> generate_key_pair_to_files(const std::string& private_key_file, const std::string& public_key_file, CryptoAlgorithm algorithm, std::size_t key_size, KeyFormat format = KeyFormat::PEM);
    static std::expected<void, std::error_code> generate_symmetric_key_to_file(const std::string& key_file, CryptoAlgorithm algorithm, std::size_t key_size, KeyFormat format = KeyFormat::RAW);
    
    static std::expected<void, std::error_code> convert_key_format(const std::string& input_file, const std::string& output_file, KeyFormat from_format, KeyFormat to_format, const CryptoOptions& options = {});
    static std::expected<void, std::error_code> convert_certificate_format(const std::string& input_file, const std::string& output_file, CertificateFormat from_format, CertificateFormat to_format, const CryptoOptions& options = {});
    
    static std::expected<void, std::error_code> create_certificate(const std::string& private_key_file, const std::string& certificate_file, const std::unordered_map<std::string, std::string>& subject_info, std::size_t validity_days = 365);
    static std::expected<void, std::error_code> create_certificate_request(const std::string& private_key_file, const std::string& csr_file, const std::unordered_map<std::string, std::string>& subject_info);
    static std::expected<void, std::error_code> sign_certificate_request(const std::string& csr_file, const std::string& ca_private_key_file, const std::string& ca_certificate_file, const std::string& output_certificate_file, std::size_t validity_days = 365);
    
    static std::expected<void, std::error_code> create_pkcs12(const std::string& private_key_file, const std::string& certificate_file, const std::string& output_file, const std::string& password);
    static std::expected<void, std::error_code> extract_from_pkcs12(const std::string& pkcs12_file, const std::string& password, const std::string& private_key_file, const std::string& certificate_file);
    
    static std::expected<void, std::error_code> encode_file(const std::string& input_file, const std::string& output_file, EncodingFormat format, const CryptoOptions& options = {});
    static std::expected<void, std::error_code> decode_file(const std::string& input_file, const std::string& output_file, EncodingFormat format, const CryptoOptions& options = {});
    
    static std::expected<void, std::error_code> secure_delete_file(const std::string& filename, std::size_t passes = 3);
    static std::expected<void, std::error_code> shred_directory(const std::string& directory, std::size_t passes = 3);
    
    static std::expected<void, std::error_code> create_encrypted_archive(const std::string& source_directory, const std::string& output_file, const std::string& password, CryptoAlgorithm algorithm = CryptoAlgorithm::AES_256_GCM);
    static std::expected<void, std::error_code> extract_encrypted_archive(const std::string& archive_file, const std::string& output_directory, const std::string& password);
    
    static std::expected<void, std::error_code> backup_encrypt(const std::string& source_directory, const std::string& backup_file, const std::string& password, const CryptoOptions& options = {});
    static std::expected<void, std::error_code> backup_decrypt(const std::string& backup_file, const std::string& output_directory, const std::string& password, const CryptoOptions& options = {});
    
    static std::expected<void, std::error_code> benchmark_algorithms(const std::string& test_file, const std::string& report_file, const std::vector<CryptoAlgorithm>& algorithms = {});
    static std::expected<void, std::error_code> analyze_file_entropy(const std::string& input_file, const std::string& report_file);
    static std::expected<void, std::error_code> audit_crypto_usage(const std::string& directory, const std::string& report_file);
    
    static std::expected<void, std::error_code> quantum_safe_migrate(const std::string& input_file, const std::string& output_file, const std::string& algorithm = "kyber");
    static std::expected<void, std::error_code> hybrid_encrypt(const std::string& input_file, const std::string& output_file, const std::string& classical_key_file, const std::string& quantum_key_file);
    
    static std::expected<void, std::error_code> create_pgp_message(const std::string& input_file, const std::string& output_file, const std::string& recipient_public_key, const std::string& sender_private_key = "");
    static std::expected<void, std::error_code> decrypt_pgp_message(const std::string& input_file, const std::string& output_file, const std::string& recipient_private_key);
    
    static std::expected<void, std::error_code> create_smime_message(const std::string& input_file, const std::string& output_file, const std::string& certificate_file, const std::string& private_key_file);
    static std::expected<void, std::error_code> verify_smime_message(const std::string& input_file, const std::string& output_file, const std::string& ca_certificates_file);
    
    static std::expected<void, std::error_code> create_jwt_token(const std::unordered_map<std::string, std::string>& payload, const std::string& private_key_file, const std::string& algorithm, std::string& token);
    static std::expected<bool, std::error_code> verify_jwt_token(const std::string& token, const std::string& public_key_file, const std::string& algorithm, std::unordered_map<std::string, std::string>& payload);
    
    static std::expected<void, std::error_code> create_blockchain_transaction(const std::unordered_map<std::string, std::string>& transaction_data, const std::string& private_key_file, std::string& signed_transaction);
    static std::expected<bool, std::error_code> verify_blockchain_transaction(const std::string& signed_transaction, const std::string& public_key_file);
    
    static std::vector<CryptoAlgorithm> get_supported_crypto_algorithms();
    static std::vector<HashAlgorithm> get_supported_hash_algorithms();
    static std::vector<KeyFormat> get_supported_key_formats();
    static std::vector<CertificateFormat> get_supported_certificate_formats();
    static std::vector<EncodingFormat> get_supported_encoding_formats();
    static bool is_algorithm_supported(CryptoAlgorithm algorithm);
    static bool is_quantum_resistant(CryptoAlgorithm algorithm);
    static std::expected<CryptoMetadata, std::error_code> get_crypto_info(const std::string& filename);
    
private:
    CryptoAlgorithm target_algorithm_ = CryptoAlgorithm::AES_256_GCM;
    EncodingFormat target_encoding_ = EncodingFormat::BASE64;
    CryptoOptions processing_options_;
    
    std::expected<CryptoBuffer, std::error_code> apply_processing(const CryptoBuffer& input) const;
    std::expected<std::vector<uint8_t>, std::error_code> perform_crypto_operation(const CryptoBuffer& crypto) const;
    std::expected<CryptoBuffer, std::error_code> parse_crypto_data(std::span<const uint8_t> data) const;
    
    static std::unordered_map<CryptoAlgorithm, std::string> algorithm_names_;
    static std::unordered_map<HashAlgorithm, std::string> hash_names_;
    static std::unordered_map<EncodingFormat, std::string> encoding_names_;
    static bool is_initialized_;
    static void initialize_crypto_support();
};

} 