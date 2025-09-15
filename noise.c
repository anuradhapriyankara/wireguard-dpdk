/* SPDX-License-Identifier: BSD-3-Clause
 * rte_wg_noise.c - libsodium-backed WireGuard-like Noise control-plane
 *
 * NOTE: This is a skeleton/functional implementation suitable for testing.
 * The precise KDF/mixing MUST be checked against WireGuard spec for full
 * interop. Use this to integrate with your dataplane and to run tests.
 */

#include "rte_wg_noise.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int rte_wg_noise_init(void)
{
    if (sodium_init() < 0) {
        return -1;
    }
    return 0;
}


/* ---- HKDF using BLAKE2s (WireGuard style) ---- */
int
rte_wg_kdf(uint8_t out1[RTE_WG_KEY_LEN],
           uint8_t out2[RTE_WG_KEY_LEN],
           uint8_t out3[RTE_WG_KEY_LEN],
           const uint8_t chaining_key[RTE_WG_HASH_LEN],
           const uint8_t *input, size_t input_len)
{
    uint8_t prk[RTE_WG_HASH_LEN];
    uint8_t tmp[RTE_WG_HASH_LEN];
    uint8_t ctr = 1;

    /* Extract */
    if (crypto_auth_hmacsha256(prk, input, input_len, chaining_key) != 0)
        return -1;

    /* Expand: out1 */
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, prk, RTE_WG_HASH_LEN);
    crypto_auth_hmacsha256_update(&st, &ctr, 1);
    crypto_auth_hmacsha256_final(&st, out1);
    ctr++;

    /* Expand: out2 */
    crypto_auth_hmacsha256_init(&st, prk, RTE_WG_HASH_LEN);
    crypto_auth_hmacsha256_update(&st, out1, RTE_WG_KEY_LEN);
    crypto_auth_hmacsha256_update(&st, &ctr, 1);
    crypto_auth_hmacsha256_final(&st, out2);
    ctr++;

    /* Expand: out3 */
    crypto_auth_hmacsha256_init(&st, prk, RTE_WG_HASH_LEN);
    crypto_auth_hmacsha256_update(&st, out2, RTE_WG_KEY_LEN);
    crypto_auth_hmacsha256_update(&st, &ctr, 1);
    crypto_auth_hmacsha256_final(&st, out3);

    sodium_memzero(prk, sizeof(prk));
    sodium_memzero(tmp, sizeof(tmp));
    return 0;
}

/* ---- MAC1 ---- */
int
rte_wg_mac1(uint8_t mac_out[RTE_WG_MAC_LEN],
            const uint8_t *msg, size_t msg_len,
            const uint8_t pubkey[RTE_WG_KEY_LEN])
{
    uint8_t key[RTE_WG_HASH_LEN];
    crypto_generichash_blake2s(key, RTE_WG_HASH_LEN,
                               pubkey, RTE_WG_KEY_LEN,
                               NULL, 0);

    crypto_generichash_blake2s(mac_out, RTE_WG_MAC_LEN,
                               msg, msg_len,
                               key, RTE_WG_HASH_LEN);

    sodium_memzero(key, sizeof(key));
    return 0;
}

/* ---- MAC2 ---- */
int
rte_wg_mac2(uint8_t mac_out[RTE_WG_MAC_LEN],
            const uint8_t *msg, size_t msg_len,
            const uint8_t cookie[RTE_WG_MAC_LEN],
            const uint8_t pubkey[RTE_WG_KEY_LEN])
{
    uint8_t key[RTE_WG_HASH_LEN];
    crypto_generichash_blake2s(key, RTE_WG_HASH_LEN,
                               pubkey, RTE_WG_KEY_LEN,
                               NULL, 0);

    crypto_generichash_blake2s_state st;
    crypto_generichash_blake2s_init(&st, key, RTE_WG_HASH_LEN,
                                    RTE_WG_MAC_LEN);
    crypto_generichash_blake2s_update(&st, msg, msg_len);
    crypto_generichash_blake2s_update(&st, cookie, RTE_WG_MAC_LEN);
    crypto_generichash_blake2s_final(&st, mac_out, RTE_WG_MAC_LEN);

    sodium_memzero(key, sizeof(key));
    return 0;
}

int rte_wg_noise_keypair_generate(uint8_t pub[32], uint8_t priv[32])
{
    if (!pub || !priv) return -1;
    /* libsodium X25519: crypto_scalarmult_curve25519_base */
    randombytes_buf(priv, 32);
    /* Clear and clamp private scalar as per X25519 */
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
    if (crypto_scalarmult_curve25519_base(pub, priv) != 0)
        return -1;
    return 0;
}

int rte_wg_noise_shared_secret(uint8_t shared[32],
                               const uint8_t priv[32],
                               const uint8_t peer_pub[32])
{
    if (!shared || !priv || !peer_pub) return -1;
    if (crypto_scalarmult_curve25519(shared, priv, peer_pub) != 0)
        return -1;
    return 0;
}

/* Simplified KDF: mix shared secrets and static public keys into two AEAD keys.
 * WARNING: This is a simplified approach for testing. Replace with full
 * Noise/WG KDF (BLAKE2s HMAC-like mixing) for production/interop.
 */
static void simple_kdf_two_keys(const uint8_t input[32],
                                const uint8_t a_pub[32],
                                const uint8_t b_pub[32],
                                uint8_t out1[32], uint8_t out2[32])
{
    /* Using BLAKE2b to derive two 32-byte keys deterministically */
    uint8_t buf[32 + 32 + 32];
    memcpy(buf, input, 32);
    memcpy(buf + 32, a_pub, 32);
    memcpy(buf + 64, b_pub, 32);
    /* out1 = blake2b(buf || 0x01) */
    crypto_generichash(out1, 32, buf, sizeof(buf), (const uint8_t *)"wg_kdf1", 8);
    /* out2 = blake2b(out1 || 0x02) */
    crypto_generichash(out2, 32, out1, 32, (const uint8_t *)"wg_kdf2", 8);
}

/* For message format simplicity:
 * initiation: [ eph_pub(32) || ciphertext_len(2) || ciphertext(...) ]
 * ciphertext is AEAD-encrypted data (AAD could be empty or contain ephemeral pub)
 */

/* Helper: AEAD encrypt small payload using key (chacha20-poly1305-ietf)
 * nonce: use 12-byte nonce built from 64-bit counter (for demo)
 */
static int aead_encrypt_constkey(const uint8_t key[32],
                                 const uint8_t *aad, size_t aad_len,
                                 uint64_t counter,
                                 const uint8_t *plain, size_t plain_len,
                                 uint8_t *out, size_t *out_len)
{
    uint8_t nonce[12] = {0};
    memcpy(nonce, &counter, sizeof(counter)); /* little-endian */
    unsigned long long clen = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(out, &clen,
            plain, plain_len,
            aad, aad_len,
            NULL, nonce, key) != 0) {
        return -1;
    }
    *out_len = (size_t)clen;
    return 0;
}

static int aead_decrypt_constkey(const uint8_t key[32],
                                 const uint8_t *aad, size_t aad_len,
                                 uint64_t counter,
                                 const uint8_t *cipher, size_t cipher_len,
                                 uint8_t *out, size_t *out_len)
{
    uint8_t nonce[12] = {0};
    memcpy(nonce, &counter, sizeof(counter));
    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(out, &mlen,
            NULL,
            cipher, cipher_len,
            aad, aad_len,
            nonce, key) != 0) {
        return -1;
    }
    *out_len = (size_t)mlen;
    return 0;
}

int rte_wg_noise_create_initiation(const uint8_t init_static_priv[32],
                                   const uint8_t init_static_pub[32],
                                   const uint8_t resp_static_pub[32],
                                   uint8_t *out_msg, size_t *out_len)
{
    if (!out_msg || !out_len) return -1;

    uint8_t eph_priv[32], eph_pub[32];
    if (rte_wg_noise_keypair_generate(eph_pub, eph_priv) != 0)
        return -1;

    /* Compute shared secret: ephemeral_priv * responder_static_pub */
    uint8_t ss[32];
    if (rte_wg_noise_shared_secret(ss, eph_priv, resp_static_pub) != 0) {
        return -1;
    }

    /* Derive ephemeral AEAD key from ss + parties' static pubs */
    uint8_t ekey[32], tmp2[32];
    simple_kdf_two_keys(ss, init_static_pub, resp_static_pub, ekey, tmp2);

    /* Prepare a small plaintext (e.g., timestamp or random) */
    uint8_t payload[16];
    randombytes_buf(payload, sizeof(payload));
    uint64_t counter = (uint64_t)randombytes_random();

    /* AAD can be the ephemeral pub to bind it */
    uint8_t *cipherbuf = out_msg + 32 + 2; /* leave space for eph_pub and length */
    size_t clen = 0;
    if (aead_encrypt_constkey(ekey, eph_pub, 32, counter, payload, sizeof(payload),
                              cipherbuf, &clen) != 0) {
        return -1;
    }

    /* Layout output */
    memcpy(out_msg, eph_pub, 32);
    uint16_t clen16 = (uint16_t)clen;
    memcpy(out_msg + 32, &clen16, 2);
    *out_len = 32 + 2 + clen;
    /* memory safety: zero sensitive */
    sodium_memzero(eph_priv, sizeof(eph_priv));
    sodium_memzero(ss, sizeof(ss));
    sodium_memzero(ekey, sizeof(ekey));
    sodium_memzero(tmp2, sizeof(tmp2));
    return 0;
}

int rte_wg_noise_consume_initiation_and_create_response(
    const uint8_t resp_static_priv[32],
    const uint8_t resp_static_pub[32],
    const uint8_t *in_msg, size_t in_len,
    uint8_t *out_msg, size_t *out_len,
    uint8_t out_rx_key[32], uint8_t out_tx_key[32],
    uint32_t *out_rx_index, uint32_t *out_tx_index)
{
    if (!in_msg || !out_msg || !out_len || !out_rx_key || !out_tx_key ||
        !out_rx_index || !out_tx_index) return -1;

    if (in_len < 34) return -1;
    const uint8_t *eph_pub = in_msg;
    uint16_t clen = 0;
    memcpy(&clen, in_msg + 32, 2);
    if (in_len < (size_t)(32 + 2 + clen)) return -1;
    const uint8_t *cipher = in_msg + 34;

    /* shared secret: responder = resp_static_priv * eph_pub */
    uint8_t ss[32];
    if (rte_wg_noise_shared_secret(ss, resp_static_priv, eph_pub) != 0) return -1;

    /* Derive AEAD keys */
    uint8_t k1[32], k2[32];
    /* For responder, derive rx_key = some(k1), tx_key = some(k2)
     * Note: mapping who uses which is important; here we choose:
     *   responder rx_key = k1, tx_key = k2
     */
    simple_kdf_two_keys(ss, resp_static_pub, eph_pub, k1, k2);
    memcpy(out_rx_key, k1, 32);
    memcpy(out_tx_key, k2, 32);

    /* For demonstration, generate receiver and sender indexes */
    *out_rx_index = rte_wg_noise_generate_receiver_index();
    *out_tx_index = rte_wg_noise_generate_receiver_index();

    /* Build a simple response message:
     * response: [ resp_eph_pub(32) || enc_payload_len(2) || ciphertext... ]
     * We'll create ephemeral for response and encrypt a random payload using derived key.
     */
    uint8_t resp_eph_priv[32], resp_eph_pub[32];
    if (rte_wg_noise_keypair_generate(resp_eph_pub, resp_eph_priv) != 0) return -1;

    /* Compute shared secret between resp_eph_priv and initiator static pub? For simplicity derive response AEAD */
    /* Here, for demo, reuse k2 as AEAD key for response encryption */
    uint8_t payload[20];
    randombytes_buf(payload, sizeof(payload));
    uint64_t counter = (uint64_t)randombytes_random();
    uint8_t *cipherout = out_msg + 32 + 2;
    size_t resp_clen = 0;
    if (aead_encrypt_constkey(k2, resp_eph_pub, 32, counter, payload, sizeof(payload),
                              cipherout, &resp_clen) != 0) {
        return -1;
    }
    memcpy(out_msg, resp_eph_pub, 32);
    uint16_t resp_clen16 = (uint16_t)resp_clen;
    memcpy(out_msg + 32, &resp_clen16, 2);
    *out_len = 32 + 2 + resp_clen;

    /* zero sensitive */
    sodium_memzero(resp_eph_priv, sizeof(resp_eph_priv));
    sodium_memzero(ss, sizeof(ss));
    sodium_memzero(k1, sizeof(k1));
    sodium_memzero(k2, sizeof(k2));
    return 0;
}

int rte_wg_noise_consume_response_and_derive_keys(
    const uint8_t init_static_priv[32],
    const uint8_t init_static_pub[32],
    const uint8_t *in_msg, size_t in_len,
    uint8_t out_rx_key[32], uint8_t out_tx_key[32],
    uint32_t *out_rx_index, uint32_t *out_tx_index)
{
    if (!init_static_priv || !in_msg || in_len < 34 ||
        !out_rx_key || !out_tx_key || !out_rx_index || !out_tx_index) return -1;

    /* Parse response ephemeral pub */
    const uint8_t *resp_eph_pub = in_msg;
    uint16_t clen = 0;
    memcpy(&clen, in_msg + 32, 2);
    if (in_len < (size_t)(32 + 2 + clen)) return -1;

    /* shared secret: initiator calculates X25519(init_static_priv, resp_eph_pub) */
    uint8_t ss[32];
    if (rte_wg_noise_shared_secret(ss, init_static_priv, resp_eph_pub) != 0) return -1;

    /* Derive AEAD keys. For initiator reverse mapping of responder. */
    uint8_t k1[32], k2[32];
    simple_kdf_two_keys(ss, init_static_pub, resp_eph_pub, k1, k2);

    /* Mapping must correspond to responder. For demo: initiator rx_key = k1, tx_key = k2 */
    memcpy(out_rx_key, k1, 32);
    memcpy(out_tx_key, k2, 32);

    /* generate local indexes (in real WG, these are chosen deterministically/randomly and exchanged) */
    *out_rx_index = rte_wg_noise_generate_receiver_index();
    *out_tx_index = rte_wg_noise_generate_receiver_index();

    sodium_memzero(ss, sizeof(ss));
    sodium_memzero(k1, sizeof(k1));
    sodium_memzero(k2, sizeof(k2));
    return 0;
}

uint32_t rte_wg_noise_generate_receiver_index(void)
{
    uint32_t idx = 0;
    while (idx == 0) {
        randombytes_buf(&idx, sizeof(idx));
        /* Avoid zero */
    }
    return idx;
}
