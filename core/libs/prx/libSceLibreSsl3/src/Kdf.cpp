#include "prx/libSceLibreSsl3/libSceLibreSsl3.hpp"
#include "prx/libc/libc.hpp"
#include "prx/libc/include/General.hpp"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>

namespace {

constexpr std::size_t MaxDigestSize = 64;

void Clear(void* memory, std::size_t size) {
    auto* bytes = static_cast<volatile unsigned char*>(memory);
    for (std::size_t index = 0; index < size; ++index) bytes[index] = 0;
}

int DigestSize(const EvpMd* digest, const char* function) {
    if (!digest) return -1;
    if (digest->mdSize < 0 || static_cast<std::size_t>(digest->mdSize) > MaxDigestSize) {
        throw std::invalid_argument(std::string(function) + ": digest size " + std::to_string(digest->mdSize) + " is outside 0 to 64");
    }
    return digest->mdSize;
}

class ScopedHmac {
public:
    ScopedHmac() { HMAC_CTX_init_nid_postfix(&context); }
    ~ScopedHmac() { HMAC_CTX_cleanup_nid_postfix(&context); }
    ScopedHmac(const ScopedHmac&) = delete;
    ScopedHmac& operator=(const ScopedHmac&) = delete;
    HmacContext* get() { return &context; }

private:
    HmacContext context;
};

bool Restart(HmacContext* context) {
    return HMAC_Init_ex_nid_postfix(context, nullptr, 0, nullptr, nullptr) != 0;
}

}

extern "C" {

HmacContext* APS5_VABI HMAC_CTX_new_nid_postfix() {
    return static_cast<HmacContext*>(calloc_nid_postfix(1, sizeof(HmacContext)));
}

void APS5_VABI HMAC_CTX_free_nid_postfix(HmacContext* context) {
    if (!context) return;
    HMAC_CTX_cleanup_nid_postfix(context);
    free_nid_postfix(context);
}

int APS5_VABI EVP_MD_block_size_nid_postfix(const LibreSsl3::DigestMethod* digest) {
    if (!digest) throw std::invalid_argument("EVP_MD_block_size: null digest");
    return digest->blockSize;
}

int APS5_VABI PKCS5_PBKDF2_HMAC_nid_postfix(const char* password, int passwordLength, const unsigned char* salt, int saltLength, int iterations, const EvpMd* digest, int keyLength, unsigned char* output) {
    const int digestLength = DigestSize(digest, __func__);
    if (digestLength < 0) return 0;
    if (saltLength < 0) throw std::invalid_argument("PKCS5_PBKDF2_HMAC: negative salt length");
    if (keyLength < 0) throw std::invalid_argument("PKCS5_PBKDF2_HMAC: negative key length");
    if (keyLength > 0 && !output) throw std::invalid_argument("PKCS5_PBKDF2_HMAC: null output");
    if (digestLength == 0 && keyLength > 0) throw std::invalid_argument("PKCS5_PBKDF2_HMAC: zero-size digest");
    if (!password) passwordLength = 0;
    else if (passwordLength == -1) passwordLength = static_cast<int>(std::strlen(password));
    ScopedHmac hmac;
    if (!HMAC_Init_ex_nid_postfix(hmac.get(), password, passwordLength, digest, nullptr)) return 0;
    unsigned char block[MaxDigestSize];
    unsigned char* out = output;
    int remaining = keyLength;
    std::uint64_t index = 1;
    int result = 1;
    while (remaining > 0) {
        const int length = remaining > digestLength ? digestLength : remaining;
        const unsigned char counter[4] = {
            static_cast<unsigned char>((index >> 24) & 0xff), static_cast<unsigned char>((index >> 16) & 0xff),
            static_cast<unsigned char>((index >> 8) & 0xff), static_cast<unsigned char>(index & 0xff)};
        if (!Restart(hmac.get()) || !HMAC_Update_nid_postfix(hmac.get(), salt, static_cast<std::size_t>(saltLength)) ||
            !HMAC_Update_nid_postfix(hmac.get(), counter, sizeof(counter)) || !HMAC_Final_nid_postfix(hmac.get(), block, nullptr)) {
            result = 0;
            break;
        }
        std::memcpy(out, block, static_cast<std::size_t>(length));
        for (int round = 1; round < iterations; ++round) {
            if (!Restart(hmac.get()) || !HMAC_Update_nid_postfix(hmac.get(), block, static_cast<std::size_t>(digestLength)) ||
                !HMAC_Final_nid_postfix(hmac.get(), block, nullptr)) {
                result = 0;
                break;
            }
            for (int byte = 0; byte < length; ++byte) out[byte] ^= block[byte];
        }
        if (!result) break;
        remaining -= length;
        out += length;
        ++index;
    }
    Clear(block, sizeof(block));
    return result;
}

int APS5_VABI HKDF_nid_postfix(std::uint8_t* output, std::size_t outputLength, const EvpMd* digest, const std::uint8_t* secret, std::size_t secretLength, const std::uint8_t* salt, std::size_t saltLength, const std::uint8_t* info, std::size_t infoLength) {
    const int digestLength = DigestSize(digest, __func__);
    if (digestLength < 0) return 0;
    if (digestLength == 0) throw std::invalid_argument("HKDF: zero-size digest");
    if (saltLength > 0x7fffffff) throw std::invalid_argument("HKDF: salt longer than an HMAC key length");
    if (outputLength > 0 && !output) throw std::invalid_argument("HKDF: null output");
    const unsigned char emptyKey[1] = {0};
    const void* key = salt ? static_cast<const void*>(salt) : emptyKey;
    const int keyLength = salt ? static_cast<int>(saltLength) : 0;
    unsigned char prk[MaxDigestSize];
    unsigned char block[MaxDigestSize];
    std::uint32_t prkLength = 0;
    int result = 0;
    {
        ScopedHmac hmac;
        if (!HMAC_Init_ex_nid_postfix(hmac.get(), key, keyLength, digest, nullptr) ||
            !HMAC_Update_nid_postfix(hmac.get(), secret, secretLength) || !HMAC_Final_nid_postfix(hmac.get(), prk, &prkLength)) {
            Clear(prk, sizeof(prk));
            return 0;
        }
    }
    {
        ScopedHmac hmac;
        if (HMAC_Init_ex_nid_postfix(hmac.get(), prk, static_cast<int>(prkLength), digest, nullptr)) {
            std::size_t remaining = outputLength;
            std::uint8_t* out = output;
            unsigned char counter = 0;
            result = 1;
            while (remaining > 0) {
                if (++counter == 0 || !HMAC_Update_nid_postfix(hmac.get(), info, infoLength) || !HMAC_Update_nid_postfix(hmac.get(), &counter, 1) ||
                    !HMAC_Final_nid_postfix(hmac.get(), block, nullptr)) {
                    result = 0;
                    break;
                }
                const std::size_t length = remaining > static_cast<std::size_t>(digestLength) ? static_cast<std::size_t>(digestLength) : remaining;
                std::memcpy(out, block, length);
                out += length;
                remaining -= length;
                if (remaining > 0 && (!Restart(hmac.get()) || !HMAC_Update_nid_postfix(hmac.get(), block, static_cast<std::size_t>(digestLength)))) {
                    result = 0;
                    break;
                }
            }
        }
    }
    Clear(prk, sizeof(prk));
    Clear(block, sizeof(block));
    return result;
}

}
