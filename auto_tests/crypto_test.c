#include <bits/stdint-intn.h>
#include <bits/stdint-uintn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#include "../testing/misc_tools.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/net_crypto.h"
#include "check_compat.h"
#include "../other/fun/create_common.h"
#include "../toxcore/mem.h"

static void rand_bytes(const Random *rng, uint8_t *b, size_t blen)
{
    size_t i;

    for (i = 0; i < blen; i++) {
        b[i] = random_u08(rng);
    }
}

// These test vectors are from libsodium's test suite

static const uint8_t alicesk[32] = {
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
    0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
};

static const uint8_t bobpk[32] = {
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
    0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
    0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
};

static const uint8_t test_nonce[24] = {
    0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
    0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
    0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37
};

static const uint8_t test_m[131] = {
    0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5,
    0xcf, 0x14, 0x13, 0x16, 0xeb, 0xeb, 0x0c, 0x7b,
    0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4,
    0x4b, 0x66, 0x84, 0x9b, 0x64, 0x24, 0x4f, 0xfc,
    0xe5, 0xec, 0xba, 0xaf, 0x33, 0xbd, 0x75, 0x1a,
    0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29,
    0x6c, 0xdc, 0x3c, 0x01, 0x23, 0x35, 0x61, 0xf4,
    0x1d, 0xb6, 0x6c, 0xce, 0x31, 0x4a, 0xdb, 0x31,
    0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d,
    0xce, 0xea, 0x3a, 0x7f, 0xa1, 0x34, 0x80, 0x57,
    0xe2, 0xf6, 0x55, 0x6a, 0xd6, 0xb1, 0x31, 0x8a,
    0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f, 0xde,
    0x04, 0x89, 0x77, 0xeb, 0x48, 0xf5, 0x9f, 0xfd,
    0x49, 0x24, 0xca, 0x1c, 0x60, 0x90, 0x2e, 0x52,
    0xf0, 0xa0, 0x89, 0xbc, 0x76, 0x89, 0x70, 0x40,
    0xe0, 0x82, 0xf9, 0x37, 0x76, 0x38, 0x48, 0x64,
    0x5e, 0x07, 0x05
};

static const uint8_t test_c[147] = {
    0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5,
    0x2a, 0x7d, 0xfb, 0x4b, 0x3d, 0x33, 0x05, 0xd9,
    0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73,
    0xc2, 0x96, 0x50, 0xba, 0x32, 0xfc, 0x76, 0xce,
    0x48, 0x33, 0x2e, 0xa7, 0x16, 0x4d, 0x96, 0xa4,
    0x47, 0x6f, 0xb8, 0xc5, 0x31, 0xa1, 0x18, 0x6a,
    0xc0, 0xdf, 0xc1, 0x7c, 0x98, 0xdc, 0xe8, 0x7b,
    0x4d, 0xa7, 0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72,
    0x71, 0xd2, 0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2,
    0x27, 0x0d, 0x6f, 0xb8, 0x63, 0xd5, 0x17, 0x38,
    0xb4, 0x8e, 0xee, 0xe3, 0x14, 0xa7, 0xcc, 0x8a,
    0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26, 0xae,
    0x90, 0x22, 0x43, 0x68, 0x51, 0x7a, 0xcf, 0xea,
    0xbd, 0x6b, 0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda,
    0x99, 0x83, 0x2b, 0x61, 0xca, 0x01, 0xb6, 0xde,
    0x56, 0x24, 0x4a, 0x9e, 0x88, 0xd5, 0xf9, 0xb3,
    0x79, 0x73, 0xf6, 0x22, 0xa4, 0x3d, 0x14, 0xa6,
    0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4, 0x5a, 0x74,
    0xe3, 0x55, 0xa5
};

static void test_known(void)
{
    uint8_t c[147];
    uint8_t m[131];
    uint16_t clen, mlen;

    ck_assert_msg(sizeof(c) == sizeof(m) + CRYPTO_MAC_SIZE * sizeof(uint8_t),
                  "cyphertext should be CRYPTO_MAC_SIZE bytes longer than plaintext");
    ck_assert_msg(sizeof(test_c) == sizeof(c), "sanity check failed");
    ck_assert_msg(sizeof(test_m) == sizeof(m), "sanity check failed");

    clen = encrypt_data(bobpk, alicesk, test_nonce, test_m, sizeof(test_m) / sizeof(uint8_t), c);

    ck_assert_msg(memcmp(test_c, c, sizeof(c)) == 0, "cyphertext doesn't match test vector");
    ck_assert_msg(clen == sizeof(c) / sizeof(uint8_t), "wrong ciphertext length");

    mlen = decrypt_data(bobpk, alicesk, test_nonce, test_c, sizeof(test_c) / sizeof(uint8_t), m);

    ck_assert_msg(memcmp(test_m, m, sizeof(m)) == 0, "decrypted text doesn't match test vector");
    ck_assert_msg(mlen == sizeof(m) / sizeof(uint8_t), "wrong plaintext length");
}

static void test_fast_known(void)
{
    uint8_t k[CRYPTO_SHARED_KEY_SIZE];
    uint8_t c[147];
    uint8_t m[131];
    uint16_t clen, mlen;

    encrypt_precompute(bobpk, alicesk, k);

    ck_assert_msg(sizeof(c) == sizeof(m) + CRYPTO_MAC_SIZE * sizeof(uint8_t),
                  "cyphertext should be CRYPTO_MAC_SIZE bytes longer than plaintext");
    ck_assert_msg(sizeof(test_c) == sizeof(c), "sanity check failed");
    ck_assert_msg(sizeof(test_m) == sizeof(m), "sanity check failed");

    clen = encrypt_data_symmetric(k, test_nonce, test_m, sizeof(test_m) / sizeof(uint8_t), c);

    ck_assert_msg(memcmp(test_c, c, sizeof(c)) == 0, "cyphertext doesn't match test vector");
    ck_assert_msg(clen == sizeof(c) / sizeof(uint8_t), "wrong ciphertext length");

    mlen = decrypt_data_symmetric(k, test_nonce, test_c, sizeof(test_c) / sizeof(uint8_t), m);

    ck_assert_msg(memcmp(test_m, m, sizeof(m)) == 0, "decrypted text doesn't match test vector");
    ck_assert_msg(mlen == sizeof(m) / sizeof(uint8_t), "wrong plaintext length");
}

static const uint8_t test_nonce_chacha20[8] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t test_nonce_chacha20_ietf[12] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

static const uint8_t test_nonce_xchacha20[24] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t test_nonce_one_zero_byte[1] = {
    0x00
};

static const uint8_t prologue[11] = {
    0x50, 0x72, 0x6f, 0x6c, 0x6f, 0x67, 0x75, 0x65, 0x31, 0x32, 0x33
};

uint8_t init_static[32] = {
    0xe6, 0x1e, 0xf9, 0x91, 0x9c, 0xde, 0x45, 0xdd, 
    0x5f, 0x82, 0x16, 0x64, 0x04, 0xbd, 0x08, 0xe3, 
    0x8b, 0xce, 0xb5, 0xdf, 0xdf, 0xde, 0xd0, 0xa3, 
    0x4c, 0x8d, 0xf7, 0xed, 0x54, 0x22, 0x14, 0xd1
};

uint8_t init_ephemeral[32] = {
    0x89, 0x3e, 0x28, 0xb9, 0xdc, 0x6c, 0xa8, 0xd6, 
    0x11, 0xab, 0x66, 0x47, 0x54, 0xb8, 0xce, 0xb7, 
    0xba, 0xc5, 0x11, 0x73, 0x49, 0xa4, 0x43, 0x9a, 
    0x6b, 0x05, 0x69, 0xda, 0x97, 0x7c, 0x46, 0x4a
};

uint8_t init_remote_static[32] = {
    0x31, 0xe0, 0x30, 0x3f, 0xd6, 0x41, 0x8d, 0x2f, 
    0x8c, 0x0e, 0x78, 0xb9, 0x1f, 0x22, 0xe8, 0xca, 
    0xed, 0x0f, 0xbe, 0x48, 0x65, 0x6d, 0xcf, 0x47, 
    0x67, 0xe4, 0x83, 0x4f, 0x70, 0x1b, 0x8f, 0x62
};

uint8_t resp_static[32] = {
    0x4a, 0x3a, 0xcb, 0xfd, 0xb1, 0x63, 0xde, 0xc6,
    0x51, 0xdf, 0xa3, 0x19, 0x4d, 0xec, 0xe6, 0x76,
    0xd4, 0x37, 0x02, 0x9c, 0x62, 0xa4, 0x08, 0xb4,
    0xc5, 0xea, 0x91, 0x14, 0x24, 0x6e, 0x48, 0x93
};

uint8_t resp_ephemeral[32] = {
    0xbb, 0xdb, 0x4c, 0xdb, 0xd3, 0x09, 0xf1, 0xa1,
    0xf2, 0xe1, 0x45, 0x69, 0x67, 0xfe, 0x28, 0x8c,
    0xad, 0xd6, 0xf7, 0x12, 0xd6, 0x5d, 0xc7, 0xb7,
    0x79, 0x3d, 0x5e, 0x63, 0xda, 0x6b, 0x37, 0x5b
};

// 4c 75 64 77 69 67 20 76 6f 6e 20 4d 69 73 65 73
uint8_t payload_hs_initiator[16] = {
        0x4c, 0x75, 0x64, 0x77, 0x69, 0x67, 0x20, 0x76, 0x6f,
        0x6e, 0x20, 0x4d, 0x69, 0x73, 0x65, 0x73
    };

// 4d 75 72 72 61 79 20 52 6f 74 68 62 61 72 64
uint8_t payload_hs_responder[15] = {
        0x4d, 0x75, 0x72, 0x72, 0x61, 0x79, 0x20, 0x52, 
        0x6f, 0x74, 0x68, 0x62, 0x61, 0x72, 0x64
    };

// 46 2e 20 41 2e 20 48 61 79 65 6b
uint8_t payload_transport_initiator1[11] = {
        0x46, 0x2e, 0x20, 0x41, 0x2e, 0x20, 0x48, 0x61, 0x79, 
        0x65, 0x6b
    };

// 43 61 72 6c 20 4d 65 6e 67 65 72
uint8_t payload_transport_responder1[11] = {
        0x43, 0x61, 0x72, 0x6c, 0x20, 0x4d, 0x65, 0x6e, 0x67, 0x65, 0x72
    };

// 4a 65 61 6e 2d 42 61 70 74 69 73 74 65 20 53 61 79
uint8_t payload_transport_initiator2[17] = {
        0x4a, 0x65, 0x61, 0x6e, 0x2d, 0x42, 0x61, 0x70, 0x74, 0x69, 0x73, 
        0x74, 0x65, 0x20, 0x53, 0x61, 0x79
};

// 45 75 67 65 6e 20 42 f6 68 6d 20 76 6f 6e 20 42 61 77 65 72 6b
uint8_t payload_transport_responder2[21] = {
        0x45, 0x75, 0x67, 0x65, 0x6e, 0x20, 0x42, 0xf6, 0x68, 0x6d, 0x20, 
        0x76, 0x6f, 0x6e, 0x20, 0x42, 0x61, 0x77, 0x65, 0x72, 0x6b
    };

static void test_fast_known2(void)
{
    uint8_t k[CRYPTO_SHARED_KEY_SIZE];
    uint8_t m1[131];
    uint8_t m2[131];
    uint8_t xm1[131];
    uint8_t xm2[131];
    uint8_t c1[147];
    uint8_t c2[147];
    uint8_t xc1[147];
    uint8_t xc2[147];
    uint16_t xclen2, xmlen2;
    unsigned long long mlen1 = 0;
    unsigned long long clen1 = 0;
    unsigned long long mlen2 = 0;
    unsigned long long clen2 = 0;
    unsigned long long xclen1 = 0; 
    unsigned long long xmlen1 = 0; 
    int result;

    uint8_t hash[CRYPTO_SHA512_SIZE];
    uint8_t send_key1[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t recv_key1[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t send_key2[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t recv_key2[CRYPTO_PUBLIC_KEY_SIZE];

    encrypt_precompute(bobpk, alicesk, k);

    // ck_assert_msg(sizeof(c) == sizeof(m) + CRYPTO_MAC_SIZE * sizeof(uint8_t),
    //               "cyphertext should be CRYPTO_MAC_SIZE bytes longer than plaintext");
    // ck_assert_msg(sizeof(test_m) == sizeof(m), "sanity check failed");

    // crypto_sha512(hash, k, CRYPTO_PUBLIC_KEY_SIZE);
    // crypto_hkdf(send_key1, recv_key1, NULL, k,
	// 	CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_PUBLIC_KEY_SIZE, 0,
	// 	CRYPTO_PUBLIC_KEY_SIZE, hash);

    // char send_key1_string[CRYPTO_SHA512_SIZE * 2 + 1];
    // char recv_key1_string[CRYPTO_SHA512_SIZE * 2 + 1];
    // bin2hex_toupper(send_key1_string, sizeof(send_key1_string), send_key1, CRYPTO_PUBLIC_KEY_SIZE);
    // bin2hex_toupper(recv_key1_string, sizeof(recv_key1_string), recv_key1, CRYPTO_PUBLIC_KEY_SIZE);
    // printf("libsodium-HMAC: %s\n", send_key1_string);
    // printf("libsodium-HMAC: %s\n", recv_key1_string);

    // crypto_hkdf_libsodium(send_key2, recv_key2, NULL, k,
	// 	CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_PUBLIC_KEY_SIZE, 0,
	// 	CRYPTO_PUBLIC_KEY_SIZE, hash);

    // char send_key2_string[CRYPTO_SHA512_SIZE * 2 + 1];
    // char recv_key2_string[CRYPTO_SHA512_SIZE * 2 + 1];
    // bin2hex_toupper(send_key2_string, sizeof(send_key2_string), send_key2, CRYPTO_PUBLIC_KEY_SIZE);
    // bin2hex_toupper(recv_key2_string, sizeof(recv_key2_string), recv_key2, CRYPTO_PUBLIC_KEY_SIZE);
    // printf("libsodium-HKDF: %s\n", send_key2_string);
    // printf("libsodium-HKDF: %s\n", recv_key2_string);

    char ciphertext_hex[147 * 2 + 1];

    /* All-zero nonces with matching length (8/12/24 bytes)*/
    /* crypto_aead_chacha20poly1305_encrypt */
    crypto_aead_chacha20poly1305_encrypt(c1, &clen1, test_m, sizeof(test_m) / sizeof(uint8_t), NULL, 0, NULL, test_nonce_chacha20, k);
    bin2hex_toupper(ciphertext_hex, sizeof(ciphertext_hex), c1, clen1);
    printf("crypto_aead_chacha20poly1305_encrypt: %s\n", ciphertext_hex);
    /* crypto_aead_chacha20poly1305_ietf_encrypt */
    crypto_aead_chacha20poly1305_ietf_encrypt(c2, &clen2, test_m, sizeof(test_m) / sizeof(uint8_t), NULL, 0, NULL, test_nonce_chacha20_ietf, k);
    bin2hex_toupper(ciphertext_hex, sizeof(ciphertext_hex), c2, clen2);
    printf("crypto_aead_chacha20poly1305_ietf_encrypt: %s\n", ciphertext_hex);
    /* crypto_aead_xchacha20poly1305_ietf_encrypt */
    crypto_aead_xchacha20poly1305_ietf_encrypt(xc1, &xclen1, test_m, sizeof(test_m) / sizeof(uint8_t), NULL, 0, NULL, test_nonce_xchacha20, k);
    bin2hex_toupper(ciphertext_hex, sizeof(ciphertext_hex), xc1, xclen1);
    printf("crypto_aead_xchacha20poly1305_ietf_encrypt: %s\n", ciphertext_hex);
    /* Tox crypto_core XChaCha20 */
    clen2 = encrypt_data_symmetric_xaead(k, test_nonce_xchacha20, test_m, sizeof(test_m) / sizeof(uint8_t), xc2, NULL, 0);
    bin2hex_toupper(ciphertext_hex, sizeof(ciphertext_hex), xc2, xclen2);
    printf("encrypt_data_symmetric_xaead(XChaCha20): %s\n", ciphertext_hex);

    /* nonce with only one zero byte => different results! */
    /* crypto_aead_chacha20poly1305_encrypt */
    // crypto_aead_chacha20poly1305_encrypt(c1, &clen1, test_m, sizeof(test_m) / sizeof(uint8_t), NULL, 0, NULL, test_nonce_one_zero_byte, k);
    // bin2hex_toupper(ciphertext_hex, sizeof(ciphertext_hex), c1, clen1);
    // printf("crypto_aead_chacha20poly1305_encrypt: %s\n", ciphertext_hex);
    // /* crypto_aead_chacha20poly1305_ietf_encrypt */
    // crypto_aead_chacha20poly1305_ietf_encrypt(c2, &clen2, test_m, sizeof(test_m) / sizeof(uint8_t), NULL, 0, NULL, test_nonce_one_zero_byte, k);
    // bin2hex_toupper(ciphertext_hex, sizeof(ciphertext_hex), c2, clen2);
    // printf("crypto_aead_chacha20poly1305_ietf_encrypt: %s\n", ciphertext_hex);
    // /* crypto_aead_xchacha20poly1305_ietf_encrypt */
    // crypto_aead_xchacha20poly1305_ietf_encrypt(xc1, &xclen1, test_m, sizeof(test_m) / sizeof(uint8_t), NULL, 0, NULL, test_nonce_one_zero_byte, k);
    // bin2hex_toupper(ciphertext_hex, sizeof(ciphertext_hex), xc1, xclen1);
    // printf("crypto_aead_xchacha20poly1305_ietf_encrypt: %s\n", ciphertext_hex);
    // /* Tox crypto_core XChaCha20 */
    // clen2 = encrypt_data_symmetric_xaead(k, test_nonce_one_zero_byte, test_m, sizeof(test_m) / sizeof(uint8_t), xc2, NULL, 0);
    // bin2hex_toupper(ciphertext_hex, sizeof(ciphertext_hex), xc2, xclen2);
    // printf("encrypt_data_symmetric_xaead(XChaCha20): %s\n", ciphertext_hex);


    // ck_assert_msg(memcmp(test_c, c, sizeof(c)) == 0, "cyphertext doesn't match test vector");
    // ck_assert_msg(clen == sizeof(c) / sizeof(uint8_t), "wrong ciphertext length");

    // char correct_plain[131 * 2 + 1];
    // char plaintext_hex[147 * 2 + 1];
    // bin2hex_toupper(correct_plain, sizeof(correct_plain), test_m, 131);
    // printf("Correct Plaintext: %s\n", correct_plain);

    // /* All-zero nonces with matching length (8/12/24 bytes)*/
    // /* crypto_aead_chacha20poly1305_decrypt */
    // result = crypto_aead_chacha20poly1305_decrypt(m1, &mlen1, NULL, c1, clen1, NULL, 0, test_nonce_chacha20, k);
    // bin2hex_toupper(plaintext_hex, sizeof(plaintext_hex), m1, mlen1);
    // printf("crypto_aead_chacha20poly1305_decrypt: %d, %s\n", result, plaintext_hex);
    // /* crypto_aead_chacha20poly1305_ietf_decrypt */
    // result = crypto_aead_chacha20poly1305_ietf_decrypt(m2, &mlen2, NULL, c2, clen2, NULL, 0, test_nonce_chacha20_ietf, k);
    // bin2hex_toupper(plaintext_hex, sizeof(plaintext_hex), m2, mlen2);
    // printf("crypto_aead_chacha20poly1305_ietf_decrypt: %d, %s\n", result, plaintext_hex);
    // /* crypto_aead_xchacha20poly1305_ietf_decrypt */
    // result = crypto_aead_xchacha20poly1305_ietf_decrypt(xm1, &xmlen1, NULL, xc1, xclen1, NULL, 0, test_nonce_xchacha20, k);
    // bin2hex_toupper(plaintext_hex, sizeof(plaintext_hex), xm1, xmlen1);
    // printf("crypto_aead_xchacha20poly1305_ietf_decrypt: %d, %s\n", result, plaintext_hex);
    // /* Tox crypto_core XChaCha20 */
    // xmlen2 = decrypt_data_symmetric_xaead(k, test_nonce_xchacha20, xc2, xclen2, xm2, NULL, 0);
    // bin2hex_toupper(plaintext_hex, sizeof(plaintext_hex), xm2, xmlen2);
    // printf("decrypt_data_symmetric_xaead(XChaCha20): %s\n", plaintext_hex);

    /* nonce with only one zero byte */
    /* crypto_aead_chacha20poly1305_decrypt */
    // result = crypto_aead_chacha20poly1305_decrypt(m1, &mlen1, NULL, c1, clen1, NULL, 0, test_nonce_one_zero_byte, k);
    // bin2hex_toupper(plaintext_hex, sizeof(plaintext_hex), m1, mlen1);
    // printf("crypto_aead_chacha20poly1305_decrypt: %d, %s\n", result, plaintext_hex);
    // /* crypto_aead_chacha20poly1305_ietf_decrypt */
    // result = crypto_aead_chacha20poly1305_ietf_decrypt(m2, &mlen2, NULL, c2, clen2, NULL, 0, test_nonce_one_zero_byte, k);
    // bin2hex_toupper(plaintext_hex, sizeof(plaintext_hex), m2, mlen2);
    // printf("crypto_aead_chacha20poly1305_ietf_decrypt: %d, %s\n", result, plaintext_hex);
    // /* crypto_aead_xchacha20poly1305_ietf_decrypt */
    // result = crypto_aead_xchacha20poly1305_ietf_decrypt(xm1, &xmlen1, NULL, xc1, xclen1, NULL, 0, test_nonce_one_zero_byte, k);
    // bin2hex_toupper(plaintext_hex, sizeof(plaintext_hex), xm1, xmlen1);
    // printf("crypto_aead_xchacha20poly1305_ietf_decrypt: %d, %s\n", result, plaintext_hex);
    // /* Tox crypto_core XChaCha20 */
    // xmlen2 = decrypt_data_symmetric_xaead(k, test_nonce_one_zero_byte, xc2, xclen2, xm2, NULL, 0);
    // bin2hex_toupper(plaintext_hex, sizeof(plaintext_hex), xm2, xmlen2);
    // printf("decrypt_data_symmetric_xaead(XChaCha20): %s\n", plaintext_hex);

    // ck_assert_msg(memcmp(test_m, m, sizeof(m)) == 0, "decrypted text doesn't match test vector");
    // ck_assert_msg(mlen == sizeof(m) / sizeof(uint8_t), "wrong plaintext length");

    char h_print[CRYPTO_SHA512_SIZE * 2 + 1];
    char ck_print[CRYPTO_SHA512_SIZE * 2 + 1];
    char key_print[CRYPTO_SHARED_KEY_SIZE * 2 + 1];

    // INITIATOR: Create handshake packet for responder
    Noise_Handshake *noise_handshake_initiator = (Noise_Handshake *) calloc(1, sizeof(Noise_Handshake));

    /* Troubleshooting info, intermediary values */
    // bin2hex_toupper(h_print, sizeof(h_print), noise_handshake->hash, CRYPTO_SHA512_SIZE);
    // printf("noise_handshake->hash: %s\n", h_print);
    // bin2hex_toupper(ck_print, sizeof(ck_print), noise_handshake->chaining_key, CRYPTO_SHA512_SIZE);
    // printf("noise_handshake->chaining_key: %s\n", ck_print);

    noise_handshake_init(nullptr, noise_handshake_initiator, init_static, init_remote_static, true);

    /* Troubleshooting info, intermediary values */
    // bin2hex_toupper(h_print, sizeof(h_print), noise_handshake->hash, CRYPTO_SHA512_SIZE);
    // printf("noise_handshake->hash: %s\n", h_print);
    // bin2hex_toupper(ck_print, sizeof(ck_print), noise_handshake->chaining_key, CRYPTO_SHA512_SIZE);
    // printf("noise_handshake->chaining_key: %s\n", ck_print);

    memcpy(noise_handshake_initiator->ephemeral_private, init_ephemeral, CRYPTO_SECRET_KEY_SIZE);
    crypto_derive_public_key(noise_handshake_initiator->ephemeral_public, init_ephemeral);

    char ephemeral_public_print[32 * 2 + 1];
    bin2hex_toupper(ephemeral_public_print, sizeof(ephemeral_public_print), noise_handshake_initiator->ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);
    printf("ephemeral_public_print: %s\n", ephemeral_public_print);

    char resp_static_print[32 * 2 + 1];
    uint8_t resp_static_pub[32];
    crypto_derive_public_key(resp_static_pub, resp_static);
    bin2hex_toupper(resp_static_print, sizeof(resp_static_print), resp_static_pub, CRYPTO_PUBLIC_KEY_SIZE);
    printf("resp_static_pub: %s\n", resp_static_print);

    /* e */
    noise_mix_hash(noise_handshake_initiator->hash, noise_handshake_initiator->ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);

    /* Troubleshooting info, intermediary values */
    // char log_hash1[CRYPTO_SHA512_SIZE*2+1];
    // bytes2string(log_hash1, sizeof(log_hash1), noise_handshake->hash, CRYPTO_SHA512_SIZE, c->log);
    // LOGGER_DEBUG(c->log, "hash1 INITIATOR: %s", log_hash1);

    /* es */
    uint8_t noise_handshake_temp_key[CRYPTO_SHARED_KEY_SIZE];
    noise_mix_key(noise_handshake_initiator->chaining_key, noise_handshake_temp_key, noise_handshake_initiator->ephemeral_private, noise_handshake_initiator->remote_static);

    /* Troubleshooting info, intermediary values */
    // bin2hex_toupper(ck_print, sizeof(ck_print), noise_handshake->chaining_key, CRYPTO_SHA512_SIZE);
    // printf("noise_handshake->chaining_key (after es): %s\n", ck_print);
    // bin2hex_toupper(key_print, sizeof(key_print), noise_handshake_temp_key, CRYPTO_SHARED_KEY_SIZE);
    // printf("noise_handshake_temp_key (after es): %s\n", key_print);

    /* s */
    //TODO: remove; not necessary to due change to ChaCha20-Poly1305 instead of XChaCha20-Poly1305
    /*Nonce provided as parameter is the base nonce! -> This adds nonce for static pub key encryption to packet (XChaCha20-Poly1305) */
    // random_nonce(c->rng, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE);
    // noise_encrypt_and_hash(packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, noise_handshake->static_public, CRYPTO_PUBLIC_KEY_SIZE, noise_handshake_temp_key,
                        //    noise_handshake->hash, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE);

    /* Nonce for static pub key encryption is _always_ 0 in case of ChaCha20-Poly1305 */
    uint8_t ciphertext1[CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE];
    noise_encrypt_and_hash(ciphertext1, noise_handshake_initiator->static_public, CRYPTO_PUBLIC_KEY_SIZE, noise_handshake_temp_key,
                            noise_handshake_initiator->hash);

    char ciphertext1_print[sizeof(ciphertext1) * 2 + 1];
    bin2hex_toupper(ciphertext1_print, sizeof(ciphertext1_print), ciphertext1, sizeof(ciphertext1));
    printf("Initiator: HS ciphertext static pub key: %s\n", ciphertext1_print);

    //TODO: remove from production code
    // char log_hash2[CRYPTO_SHA512_SIZE*2+1];
    // bytes2string(log_hash2, sizeof(log_hash2), noise_handshake->hash, CRYPTO_SHA512_SIZE, c->log);
    // LOGGER_DEBUG(c->log, "hash2 INITIATOR: %s", log_hash2);
    // char log_ephemeral[CRYPTO_PUBLIC_KEY_SIZE * 2 + 1];
    // bytes2string(log_ephemeral, sizeof(log_ephemeral), noise_handshake->ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE, c->log);
    // LOGGER_DEBUG(c->log, "ephemeral public: %s", log_ephemeral);

    /* ss */
    noise_mix_key(noise_handshake_initiator->chaining_key, noise_handshake_temp_key, 
        noise_handshake_initiator->static_private, noise_handshake_initiator->remote_static);

    /* Noise Handshake Payload */
    // uint8_t handshake_payload_plain[15];
    uint8_t ciphertext2[sizeof(payload_hs_initiator) + CRYPTO_MAC_SIZE];

    //TODO: remove; not necessary to due change to ChaCha20-Poly1305 instead of XChaCha20-Poly1305
    /* Add Handshake payload nonce */
    // random_nonce(c->rng, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE);
    // noise_encrypt_and_hash(packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE + CRYPTO_NONCE_SIZE,
    //                        handshake_payload_plain, sizeof(handshake_payload_plain), noise_handshake_temp_key,
    //                        noise_handshake->hash, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE);

    /* Nonce for payload encryption is _always_ 0 in case of ChaCha20-Poly1305 */
    noise_encrypt_and_hash(ciphertext2,
                            payload_hs_initiator, sizeof(payload_hs_initiator), noise_handshake_temp_key,
                            noise_handshake_initiator->hash);

    char ciphertext2_print[sizeof(ciphertext2) * 2 + 1];
    bin2hex_toupper(ciphertext2_print, sizeof(ciphertext2_print), ciphertext2, sizeof(ciphertext2));
    printf("Initiator: HS ciphertext payload: %s\n", ciphertext2_print);

    // INITIATOR: END Create handshake packet for responder

    // RESPONDER: Consume handshake packet from initiator
    Noise_Handshake *noise_handshake_responder = (Noise_Handshake *) calloc(1, sizeof(Noise_Handshake));

    /* Troubleshooting info, intermediary values */
    // bin2hex_toupper(h_print, sizeof(h_print), noise_handshake->hash, CRYPTO_SHA512_SIZE);
    // printf("noise_handshake->hash: %s\n", h_print);
    // bin2hex_toupper(ck_print, sizeof(ck_print), noise_handshake->chaining_key, CRYPTO_SHA512_SIZE);
    // printf("noise_handshake->chaining_key: %s\n", ck_print);

    char init_static_print[CRYPTO_PUBLIC_KEY_SIZE * 2 + 1];
    uint8_t init_static_pub[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_derive_public_key(init_static_pub, init_static);
    bin2hex_toupper(init_static_print, sizeof(init_static_print), init_static_pub, CRYPTO_PUBLIC_KEY_SIZE);
    printf("init_static_pub: %s\n", init_static_print);

    noise_handshake_init(nullptr, noise_handshake_responder, resp_static, init_static_pub, false);

    /* e */
    memcpy(noise_handshake_responder->remote_ephemeral, noise_handshake_initiator->ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);
    noise_mix_hash(noise_handshake_responder->hash, noise_handshake_initiator->ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);

    /* es */
    uint8_t noise_handshake_temp_key_resp[CRYPTO_SHARED_KEY_SIZE];
    noise_mix_key(noise_handshake_responder->chaining_key, noise_handshake_temp_key_resp, 
        noise_handshake_responder->static_private, noise_handshake_responder->remote_ephemeral);

    /* s */ 
    noise_decrypt_and_hash(noise_handshake_responder->remote_static, ciphertext1, CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE,
                                       noise_handshake_temp_key_resp, noise_handshake_responder->hash);

    /* ss */
    noise_mix_key(noise_handshake_responder->chaining_key, noise_handshake_temp_key_resp, noise_handshake_responder->static_private, 
        noise_handshake_responder->remote_static);

    /* Payload decryption */
    uint8_t handshake_payload_plain_initiator[sizeof(payload_hs_initiator)];
    noise_decrypt_and_hash(handshake_payload_plain_initiator, ciphertext2,
                                       sizeof(ciphertext2), noise_handshake_temp_key_resp,
                                       noise_handshake_responder->hash);

    // RESPONDER: Create handshake packet for initiator

    /* set ephemeral private+public */
    memcpy(noise_handshake_responder->ephemeral_private, resp_ephemeral, CRYPTO_SECRET_KEY_SIZE);
    crypto_derive_public_key(noise_handshake_responder->ephemeral_public, resp_ephemeral);

    char ephemeral_public_print_responder[CRYPTO_PUBLIC_KEY_SIZE * 2 + 1];
    bin2hex_toupper(ephemeral_public_print_responder, sizeof(ephemeral_public_print_responder), noise_handshake_responder->ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);
    printf("Responder ephemeral public:: %s\n", ephemeral_public_print_responder);

    /* e */
    noise_mix_hash(noise_handshake_responder->hash, noise_handshake_responder->ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);

    /* ee */
    uint8_t noise_handshake_temp_key_resp2[CRYPTO_SHARED_KEY_SIZE];
    noise_mix_key(noise_handshake_responder->chaining_key, noise_handshake_temp_key_resp2, noise_handshake_responder->ephemeral_private, 
        noise_handshake_responder->remote_ephemeral);

    /* se */
    noise_mix_key(noise_handshake_responder->chaining_key, noise_handshake_temp_key_resp2, noise_handshake_responder->ephemeral_private, 
        noise_handshake_responder->remote_static);

    
    /* Nonce for payload encryption is _always_ 0 in case of ChaCha20-Poly1305 */
    uint8_t ciphertext3_hs_responder[sizeof(payload_hs_responder) + CRYPTO_MAC_SIZE];
    noise_encrypt_and_hash(ciphertext3_hs_responder,
                            payload_hs_responder, sizeof(payload_hs_responder), noise_handshake_temp_key_resp2,
                            noise_handshake_responder->hash);

    char ciphertext3_print[sizeof(ciphertext3_hs_responder) * 2 + 1];
    bin2hex_toupper(ciphertext3_print, sizeof(ciphertext3_print), ciphertext3_hs_responder, sizeof(ciphertext3_hs_responder));
    printf("Responder: HS ciphertext payload: %s\n", ciphertext3_print);

    // RESPONDER: END create handshake packet for initiator#

    // INITIATOR: Consume handshake packet from responder
    memcpy(noise_handshake_initiator->remote_ephemeral, noise_handshake_responder->ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);
    noise_mix_hash(noise_handshake_initiator->hash, noise_handshake_initiator->remote_ephemeral, CRYPTO_PUBLIC_KEY_SIZE);

    /* ee */
    uint8_t noise_handshake_temp_key_init[CRYPTO_SHARED_KEY_SIZE];
    noise_mix_key(noise_handshake_initiator->chaining_key, noise_handshake_temp_key_init, noise_handshake_initiator->ephemeral_private, 
        noise_handshake_initiator->remote_ephemeral);

    /* se */
    noise_mix_key(noise_handshake_initiator->chaining_key, noise_handshake_temp_key_init, noise_handshake_initiator->static_private, 
        noise_handshake_initiator->remote_ephemeral);

    uint8_t handshake_payload_plain_responder[sizeof(payload_hs_responder)];
    if(noise_decrypt_and_hash(handshake_payload_plain_initiator, ciphertext3_hs_responder,
                                    sizeof(ciphertext3_hs_responder), noise_handshake_temp_key_init,
                                    noise_handshake_initiator->hash) != sizeof(payload_hs_responder)) {
                                    printf("Initiator: HS decryption failed\n");
    }

    /* INITIATOR Noise Split(), nonces already set in crypto connection */
    uint8_t initiator_send_key[CRYPTO_SHARED_KEY_SIZE];
    uint8_t initiator_recv_key[CRYPTO_SHARED_KEY_SIZE];
    crypto_hkdf(initiator_send_key, CRYPTO_SHARED_KEY_SIZE, initiator_recv_key, CRYPTO_SHARED_KEY_SIZE, nullptr, 0, 
        noise_handshake_initiator->chaining_key);

    char handshake_hash_initiator_print[sizeof(noise_handshake_initiator->hash) * 2 + 1];
    bin2hex_toupper(handshake_hash_initiator_print, sizeof(handshake_hash_initiator_print), noise_handshake_initiator->hash, sizeof(noise_handshake_initiator->hash));
    printf("Initiator: final handshake hash: %s\n", handshake_hash_initiator_print);

    /* Troubleshooting info, intermediary values */
    // char initiator_send_key_print[CRYPTO_SHARED_KEY_SIZE * 2 + 1];
    // char initiator_recv_key_print[CRYPTO_SHARED_KEY_SIZE * 2 + 1];
    // bin2hex_toupper(initiator_send_key_print, sizeof(initiator_send_key_print), initiator_send_key, CRYPTO_SHARED_KEY_SIZE);
    // printf("initiator_send_key_print: %s\n", initiator_send_key_print);
    // bin2hex_toupper(initiator_recv_key_print, sizeof(initiator_recv_key_print), initiator_recv_key, CRYPTO_SHARED_KEY_SIZE);
    // printf("initiator_recv_key_print: %s\n", initiator_recv_key_print);

    uint8_t ciphertext4_transport1_initiator[sizeof(payload_transport_initiator1) + CRYPTO_MAC_SIZE];
    uint8_t nonce_chacha20_ietf[CRYPTO_NOISEIK_NONCE_SIZE] = {0};
    int32_t length = encrypt_data_symmetric_aead(initiator_send_key, nonce_chacha20_ietf, payload_transport_initiator1, sizeof(payload_transport_initiator1), ciphertext4_transport1_initiator, nullptr, 0);
    
    char ciphertext4_transport1_initiator_print[sizeof(ciphertext4_transport1_initiator) * 2 + 1];
    bin2hex_toupper(ciphertext4_transport1_initiator_print, sizeof(ciphertext4_transport1_initiator_print), ciphertext4_transport1_initiator, sizeof(ciphertext4_transport1_initiator));
    printf("Initiator: Transport1 ciphertext: (length: %d) %s\n", length, ciphertext4_transport1_initiator_print);

    /* RESPONDER Noise Split(): vice-verse keys in comparison to initiator */
    uint8_t responder_send_key[CRYPTO_SHARED_KEY_SIZE];
    uint8_t responder_recv_key[CRYPTO_SHARED_KEY_SIZE];
    crypto_hkdf(responder_recv_key, CRYPTO_SYMMETRIC_KEY_SIZE, responder_send_key, CRYPTO_SYMMETRIC_KEY_SIZE, nullptr, 0, noise_handshake_responder->chaining_key);

    char handshake_hash_responder_print[sizeof(noise_handshake_responder->hash) * 2 + 1];
    bin2hex_toupper(handshake_hash_responder_print, sizeof(handshake_hash_responder_print), noise_handshake_responder->hash, sizeof(noise_handshake_responder->hash));
    printf("Responder: final handshake hash: %s\n", handshake_hash_responder_print);

    /* Troubleshooting info, intermediary values */
    // char responder_send_key_print[CRYPTO_SHARED_KEY_SIZE * 2 + 1];
    // char responder_recv_key_print[CRYPTO_SHARED_KEY_SIZE * 2 + 1];
    // bin2hex_toupper(responder_send_key_print, sizeof(responder_send_key_print), responder_send_key, CRYPTO_SHARED_KEY_SIZE);
    // printf("responder_send_key_print: %s\n", responder_send_key_print);
    // bin2hex_toupper(responder_recv_key_print, sizeof(responder_recv_key_print), responder_recv_key, CRYPTO_SHARED_KEY_SIZE);
    // printf("responder_recv_key_print: %s\n", responder_recv_key_print);

    uint8_t ciphertext5_transport1_responder[sizeof(payload_transport_responder1) + CRYPTO_MAC_SIZE];
    int32_t length_ciphertext5_transport1_responder = encrypt_data_symmetric_aead(responder_send_key, nonce_chacha20_ietf, 
        payload_transport_responder1, sizeof(payload_transport_responder1), ciphertext5_transport1_responder, nullptr, 0);

    char ciphertext5_transport1_responder_print[sizeof(ciphertext5_transport1_responder) * 2 + 1];
    bin2hex_toupper(ciphertext5_transport1_responder_print, sizeof(ciphertext5_transport1_responder_print), ciphertext5_transport1_responder, sizeof(ciphertext5_transport1_responder));
    printf("Responder: Transport1 ciphertext: (length: %d) %s\n", length, ciphertext5_transport1_responder_print);

    sodium_increment(nonce_chacha20_ietf, CRYPTO_NOISEIK_NONCE_SIZE);
    // uint8_t nonce_chacha20_ietf_1[CRYPTO_NOISEIK_NONCE_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00,
        // 0x00, 0x01 };
    uint8_t ciphertext6_transport2_initiator[sizeof(payload_transport_initiator2) + CRYPTO_MAC_SIZE];
    int32_t ciphertext6_transport2_initiator_length = encrypt_data_symmetric_aead(initiator_send_key, nonce_chacha20_ietf, 
        payload_transport_initiator2, sizeof(payload_transport_initiator2), ciphertext6_transport2_initiator, nullptr, 0);
    
    char ciphertext6_transport2_initiator_print[sizeof(ciphertext6_transport2_initiator) * 2 + 1];
    bin2hex_toupper(ciphertext6_transport2_initiator_print, sizeof(ciphertext6_transport2_initiator_print), 
        ciphertext6_transport2_initiator, sizeof(ciphertext6_transport2_initiator));
    printf("Initiator: Transport1 ciphertext: (length: %d) %s\n", length, ciphertext6_transport2_initiator_print);

    uint8_t ciphertext7_transport2_responder[sizeof(payload_transport_responder2) + CRYPTO_MAC_SIZE];
    int32_t length_ciphertext7_transport2_responder = encrypt_data_symmetric_aead(responder_send_key, nonce_chacha20_ietf, 
        payload_transport_responder2, sizeof(payload_transport_responder2), ciphertext7_transport2_responder, nullptr, 0);

    char ciphertext7_transport2_responder_print[sizeof(ciphertext7_transport2_responder) * 2 + 1];
    bin2hex_toupper(ciphertext7_transport2_responder_print, sizeof(ciphertext7_transport2_responder_print), 
        ciphertext7_transport2_responder, sizeof(ciphertext7_transport2_responder));
    printf("Responder: Transport1 ciphertext: (length: %d) %s\n", length, ciphertext7_transport2_responder_print);


}

// static void test_endtoend(void)
// {
//     const Random *rng = system_random();
//     ck_assert(rng != nullptr);

//     // Test 100 random messages and keypairs
//     for (uint8_t testno = 0; testno < 100; testno++) {
//         uint8_t pk1[CRYPTO_PUBLIC_KEY_SIZE];
//         uint8_t sk1[CRYPTO_SECRET_KEY_SIZE];
//         uint8_t pk2[CRYPTO_PUBLIC_KEY_SIZE];
//         uint8_t sk2[CRYPTO_SECRET_KEY_SIZE];
//         uint8_t k1[CRYPTO_SHARED_KEY_SIZE];
//         uint8_t k2[CRYPTO_SHARED_KEY_SIZE];

//         uint8_t n[CRYPTO_NONCE_SIZE];

//         enum { M_SIZE = 50 };
//         uint8_t m[M_SIZE];
//         uint8_t c1[sizeof(m) + CRYPTO_MAC_SIZE];
//         uint8_t c2[sizeof(m) + CRYPTO_MAC_SIZE];
//         uint8_t c3[sizeof(m) + CRYPTO_MAC_SIZE];
//         uint8_t c4[sizeof(m) + CRYPTO_MAC_SIZE];
//         uint8_t m1[sizeof(m)];
//         uint8_t m2[sizeof(m)];
//         uint8_t m3[sizeof(m)];
//         uint8_t m4[sizeof(m)];

//         //Generate random message (random length from 10 to 50)
//         const uint16_t mlen = (random_u32(rng) % (M_SIZE - 10)) + 10;
//         rand_bytes(rng, m, mlen);
//         rand_bytes(rng, n, CRYPTO_NONCE_SIZE);

//         //Generate keypairs
//         crypto_new_keypair(rng, pk1, sk1);
//         crypto_new_keypair(rng, pk2, sk2);

//         //Precompute shared keys
//         encrypt_precompute(pk2, sk1, k1);
//         encrypt_precompute(pk1, sk2, k2);

//         ck_assert_msg(memcmp(k1, k2, CRYPTO_SHARED_KEY_SIZE) == 0, "encrypt_precompute: bad");

//         //Encrypt all four ways
//         const uint16_t c1len = encrypt_data(pk2, sk1, n, m, mlen, c1);
//         const uint16_t c2len = encrypt_data(pk1, sk2, n, m, mlen, c2);
//         const uint16_t c3len = encrypt_data_symmetric(k1, n, m, mlen, c3);
//         const uint16_t c4len = encrypt_data_symmetric(k2, n, m, mlen, c4);

//         ck_assert_msg(c1len == c2len && c1len == c3len && c1len == c4len, "cyphertext lengths differ");
//         ck_assert_msg(c1len == mlen + (uint16_t)CRYPTO_MAC_SIZE, "wrong cyphertext length");
//         ck_assert_msg(memcmp(c1, c2, c1len) == 0 && memcmp(c1, c3, c1len) == 0
//                       && memcmp(c1, c4, c1len) == 0, "crypertexts differ");

//         //Decrypt all four ways
//         const uint16_t m1len = decrypt_data(pk2, sk1, n, c1, c1len, m1);
//         const uint16_t m2len = decrypt_data(pk1, sk2, n, c1, c1len, m2);
//         const uint16_t m3len = decrypt_data_symmetric(k1, n, c1, c1len, m3);
//         const uint16_t m4len = decrypt_data_symmetric(k2, n, c1, c1len, m4);

//         ck_assert_msg(m1len == m2len && m1len == m3len && m1len == m4len, "decrypted text lengths differ");
//         ck_assert_msg(m1len == mlen, "wrong decrypted text length");
//         ck_assert_msg(memcmp(m1, m2, mlen) == 0 && memcmp(m1, m3, mlen) == 0
//                       && memcmp(m1, m4, mlen) == 0, "decrypted texts differ");
//         ck_assert_msg(memcmp(m1, m, mlen) == 0, "wrong decrypted text");
//     }
// }

// static void test_large_data(void)
// {
//     const Random *rng = system_random();
//     ck_assert(rng != nullptr);
//     uint8_t k[CRYPTO_SHARED_KEY_SIZE];
//     uint8_t n[CRYPTO_NONCE_SIZE];

//     const size_t m1_size = MAX_CRYPTO_PACKET_SIZE - CRYPTO_MAC_SIZE;
//     uint8_t *m1 = (uint8_t *)malloc(m1_size);
//     uint8_t *c1 = (uint8_t *)malloc(m1_size + CRYPTO_MAC_SIZE);
//     uint8_t *m1prime = (uint8_t *)malloc(m1_size);

//     const size_t m2_size = MAX_CRYPTO_PACKET_SIZE - CRYPTO_MAC_SIZE;
//     uint8_t *m2 = (uint8_t *)malloc(m2_size);
//     uint8_t *c2 = (uint8_t *)malloc(m2_size + CRYPTO_MAC_SIZE);

//     ck_assert(m1 != nullptr && c1 != nullptr && m1prime != nullptr && m2 != nullptr && c2 != nullptr);

//     //Generate random messages
//     rand_bytes(rng, m1, m1_size);
//     rand_bytes(rng, m2, m2_size);
//     rand_bytes(rng, n, CRYPTO_NONCE_SIZE);

//     //Generate key
//     rand_bytes(rng, k, CRYPTO_SHARED_KEY_SIZE);

//     const uint16_t c1len = encrypt_data_symmetric(k, n, m1, m1_size, c1);
//     const uint16_t c2len = encrypt_data_symmetric(k, n, m2, m2_size, c2);

//     ck_assert_msg(c1len == m1_size + CRYPTO_MAC_SIZE, "could not encrypt");
//     ck_assert_msg(c2len == m2_size + CRYPTO_MAC_SIZE, "could not encrypt");

//     const uint16_t m1plen = decrypt_data_symmetric(k, n, c1, c1len, m1prime);

//     ck_assert_msg(m1plen == m1_size, "decrypted text lengths differ");
//     ck_assert_msg(memcmp(m1prime, m1, m1_size) == 0, "decrypted texts differ");

//     free(c2);
//     free(m2);
//     free(m1prime);
//     free(c1);
//     free(m1);
// }

// static void test_large_data_symmetric(void)
// {
//     const Random *rng = system_random();
//     ck_assert(rng != nullptr);
//     uint8_t k[CRYPTO_SYMMETRIC_KEY_SIZE];

//     uint8_t n[CRYPTO_NONCE_SIZE];

//     const size_t m1_size = 16 * 16 * 16;
//     uint8_t *m1 = (uint8_t *)malloc(m1_size);
//     uint8_t *c1 = (uint8_t *)malloc(m1_size + CRYPTO_MAC_SIZE);
//     uint8_t *m1prime = (uint8_t *)malloc(m1_size);

//     ck_assert(m1 != nullptr && c1 != nullptr && m1prime != nullptr);

//     //Generate random messages
//     rand_bytes(rng, m1, m1_size);
//     rand_bytes(rng, n, CRYPTO_NONCE_SIZE);

//     //Generate key
//     new_symmetric_key(rng, k);

//     const uint16_t c1len = encrypt_data_symmetric(k, n, m1, m1_size, c1);
//     ck_assert_msg(c1len == m1_size + CRYPTO_MAC_SIZE, "could not encrypt data");

//     const uint16_t m1plen = decrypt_data_symmetric(k, n, c1, c1len, m1prime);

//     ck_assert_msg(m1plen == m1_size, "decrypted text lengths differ");
//     ck_assert_msg(memcmp(m1prime, m1, m1_size) == 0, "decrypted texts differ");

//     free(m1prime);
//     free(c1);
//     free(m1);
// }

static void increment_nonce_number_cmp(uint8_t *nonce, uint32_t num)
{
    uint32_t num1, num2;
    memcpy(&num1, nonce + (CRYPTO_NONCE_SIZE - sizeof(num1)), sizeof(num1));
    num1 = net_ntohl(num1);
    num2 = num + num1;

    if (num2 < num1) {
        for (uint16_t i = CRYPTO_NONCE_SIZE - sizeof(num1); i != 0; --i) {
            ++nonce[i - 1];

            if (nonce[i - 1] != 0) {
                break;
            }
        }
    }

    num2 = net_htonl(num2);
    memcpy(nonce + (CRYPTO_NONCE_SIZE - sizeof(num2)), &num2, sizeof(num2));
}

// static void test_increment_nonce(void)
// {
//     const Random *rng = system_random();
//     ck_assert(rng != nullptr);

//     uint32_t i;

//     uint8_t n[CRYPTO_NONCE_SIZE];

//     for (i = 0; i < CRYPTO_NONCE_SIZE; ++i) {
//         n[i] = random_u08(rng);
//     }

//     uint8_t n1[CRYPTO_NONCE_SIZE];

//     memcpy(n1, n, CRYPTO_NONCE_SIZE);

//     for (i = 0; i < (1 << 18); ++i) {
//         increment_nonce_number_cmp(n, 1);
//         increment_nonce(n1);
//         ck_assert_msg(memcmp(n, n1, CRYPTO_NONCE_SIZE) == 0, "Bad increment_nonce function");
//     }

//     for (i = 0; i < (1 << 18); ++i) {
//         const uint32_t r = random_u32(rng);
//         increment_nonce_number_cmp(n, r);
//         increment_nonce_number(n1, r);
//         ck_assert_msg(memcmp(n, n1, CRYPTO_NONCE_SIZE) == 0, "Bad increment_nonce_number function");
//     }
// }

static void test_memzero(void)
{
    uint8_t src[sizeof(test_c)];
    memcpy(src, test_c, sizeof(test_c));

    crypto_memzero(src, sizeof(src));
    size_t i;

    for (i = 0; i < sizeof(src); i++) {
        ck_assert_msg(src[i] == 0, "Memory is not zeroed");
    }
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    // test_known();
    // test_fast_known();
    test_fast_known2();
    // test_endtoend(); /* waiting up to 15 seconds */
    // test_large_data();
    // test_large_data_symmetric();
    // test_increment_nonce();
    // test_memzero();

    return 0;
}
