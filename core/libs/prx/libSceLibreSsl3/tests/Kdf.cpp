#include "prx/libSceLibreSsl3/libSceLibreSsl3.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <source_location>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void Require(bool condition, std::source_location location = std::source_location::current()) {
    if (condition) return;
    std::fprintf(stderr, "LibreSSL3 KDF check failed at line %u\n", location.line());
    std::abort();
}

std::vector<unsigned char> Hex(const char* text) {
    std::vector<unsigned char> bytes;
    for (std::size_t i = 0; text[i] && text[i + 1]; i += 2) bytes.push_back(static_cast<unsigned char>(std::stoul(std::string(text + i, 2), nullptr, 16)));
    return bytes;
}

const EvpMd* Sha1() {
    return reinterpret_cast<const EvpMd*>(EVP_sha1_nid_postfix());
}

std::vector<unsigned char> Pbkdf2(const char* password, int passwordLength, const char* salt, int saltLength, int iterations, const EvpMd* digest, int keyLength) {
    std::vector<unsigned char> key(static_cast<std::size_t>(keyLength) + 1, 0xA5);
    Require(PKCS5_PBKDF2_HMAC_nid_postfix(password, passwordLength, reinterpret_cast<const unsigned char*>(salt), saltLength, iterations, digest, keyLength, key.data()) == 1);
    Require(key.back() == 0xA5);
    key.pop_back();
    return key;
}

template <typename TCall>
void RequireThrows(TCall call) {
    bool threw = false;
    try {
        call();
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    Require(threw);
}

void TestPbkdf2() {
    Require(Pbkdf2("password", 8, "salt", 4, 1, Sha1(), 20) == Hex("0c60c80f961f0e71f3a9b524af6012062fe037a6"));
    Require(Pbkdf2("password", -1, "salt", 4, 2, Sha1(), 20) == Hex("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"));
    Require(Pbkdf2("password", 8, "salt", 4, 4096, Sha1(), 20) == Hex("4b007901b765489abead49d926f721d065a429c1"));
    Require(Pbkdf2("passwordPASSWORDpassword", 24, "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096, Sha1(), 25) == Hex("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"));
    Require(Pbkdf2("pass\0word", 9, "sa\0lt", 5, 4096, Sha1(), 16) == Hex("56fa6aa75548099dcc37d7f03425e0c3"));
    Require(Pbkdf2("passwd", 6, "salt", 4, 1, EVP_sha256_nid_postfix(), 64) == Hex("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"));
    Require(Pbkdf2("password", 8, "salt", 4, 0, Sha1(), 20) == Pbkdf2("password", 8, "salt", 4, 1, Sha1(), 20));
    unsigned char untouched = 0x5A;
    Require(PKCS5_PBKDF2_HMAC_nid_postfix(nullptr, 5, reinterpret_cast<const unsigned char*>("salt"), 4, 1, Sha1(), 1, &untouched) == 0);
    Require(untouched == 0x5A);
    Require(Pbkdf2("", 0, "salt", 4, 1, Sha1(), 20) == Pbkdf2("", -1, "salt", 4, 1, Sha1(), 20));
    Require(PKCS5_PBKDF2_HMAC_nid_postfix("password", 8, nullptr, 0, 1, Sha1(), 0, &untouched) == 1);
    Require(untouched == 0x5A);
    Require(PKCS5_PBKDF2_HMAC_nid_postfix("password", 8, nullptr, 0, 1, nullptr, 20, &untouched) == 0);
    Require(PKCS5_PBKDF2_HMAC_nid_postfix("password", -2, nullptr, 0, 1, Sha1(), 1, &untouched) == 0);
    Require(untouched == 0x5A);
    RequireThrows([&] { PKCS5_PBKDF2_HMAC_nid_postfix("password", 8, nullptr, 0, 1, Sha1(), -1, &untouched); });
    RequireThrows([&] { PKCS5_PBKDF2_HMAC_nid_postfix("password", 8, nullptr, -1, 1, Sha1(), 1, &untouched); });
}

std::vector<unsigned char> Hkdf(const std::vector<unsigned char>& secret, const std::vector<unsigned char>* salt, const std::vector<unsigned char>& info, std::size_t length) {
    std::vector<unsigned char> key(length + 1, 0xA5);
    Require(HKDF_nid_postfix(key.data(), length, EVP_sha256_nid_postfix(), secret.data(), secret.size(), salt ? salt->data() : nullptr, salt ? salt->size() : 0, info.empty() ? nullptr : info.data(), info.size()) == 1);
    Require(key.back() == 0xA5);
    key.pop_back();
    return key;
}

void TestHkdf() {
    const auto secret = Hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const auto salt = Hex("000102030405060708090a0b0c");
    Require(Hkdf(secret, &salt, Hex("f0f1f2f3f4f5f6f7f8f9"), 42) == Hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
    std::vector<unsigned char> longSecret, longSalt, longInfo;
    for (int i = 0x00; i <= 0x4f; ++i) longSecret.push_back(static_cast<unsigned char>(i));
    for (int i = 0x60; i <= 0xaf; ++i) longSalt.push_back(static_cast<unsigned char>(i));
    for (int i = 0xb0; i <= 0xff; ++i) longInfo.push_back(static_cast<unsigned char>(i));
    Require(Hkdf(longSecret, &longSalt, longInfo, 82) == Hex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"));
    const std::vector<unsigned char> empty;
    Require(Hkdf(secret, &empty, empty, 42) == Hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"));
    Require(Hkdf(secret, nullptr, empty, 42) == Hkdf(secret, &empty, empty, 42));
    unsigned char untouched[32 * 255 + 1];
    std::memset(untouched, 0x5A, sizeof(untouched));
    Require(HKDF_nid_postfix(untouched, 32 * 255, EVP_sha256_nid_postfix(), secret.data(), secret.size(), nullptr, 0, nullptr, 0) == 1);
    Require(HKDF_nid_postfix(untouched, 32 * 255 + 1, EVP_sha256_nid_postfix(), secret.data(), secret.size(), nullptr, 0, nullptr, 0) == 0);
    unsigned char marker = 0x5A;
    Require(HKDF_nid_postfix(&marker, 0, EVP_sha256_nid_postfix(), secret.data(), secret.size(), nullptr, 0, nullptr, 0) == 1);
    Require(marker == 0x5A);
    Require(HKDF_nid_postfix(&marker, 1, nullptr, secret.data(), secret.size(), nullptr, 0, nullptr, 0) == 0);
    Require(marker == 0x5A);
}

void TestHmacContext() {
    HmacContext* context = HMAC_CTX_new_nid_postfix();
    Require(context != nullptr);
    const auto* bytes = reinterpret_cast<const unsigned char*>(context);
    for (std::size_t i = 0; i < sizeof(HmacContext); ++i) Require(bytes[i] == 0);
    const auto key = Hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const char* data = "Hi There";
    unsigned char mac[32];
    std::uint32_t length = 0;
    Require(HMAC_Init_ex_nid_postfix(context, key.data(), static_cast<int>(key.size()), EVP_sha256_nid_postfix(), nullptr) == 1);
    Require(HMAC_Update_nid_postfix(context, reinterpret_cast<const unsigned char*>(data), 8) == 1);
    Require(HMAC_Final_nid_postfix(context, mac, &length) == 1);
    Require(length == 32);
    Require(std::vector<unsigned char>(mac, mac + 32) == Hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    HMAC_CTX_free_nid_postfix(context);
    HMAC_CTX_free_nid_postfix(nullptr);
    HMAC_CTX_free_nid_postfix(HMAC_CTX_new_nid_postfix());
}

void TestBlockSize() {
    Require(EVP_MD_block_size_nid_postfix(EVP_sha1_nid_postfix()) == 64);
    Require(EVP_MD_block_size_nid_postfix(EVP_sha224_nid_postfix()) == 64);
    Require(EVP_MD_block_size_nid_postfix(reinterpret_cast<const LibreSsl3::DigestMethod*>(EVP_sha256_nid_postfix())) == 64);
    Require(EVP_MD_block_size_nid_postfix(reinterpret_cast<const LibreSsl3::DigestMethod*>(EVP_sha512_nid_postfix())) == 128);
    RequireThrows([] { EVP_MD_block_size_nid_postfix(nullptr); });
}

}

int main() {
    TestPbkdf2();
    TestHkdf();
    TestHmacContext();
    TestBlockSize();
    std::puts("LibreSSL3 KDF tests passed");
}
