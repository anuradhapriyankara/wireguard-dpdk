/* SPDX-License-Identifier: BSD-3-Clause
 * rte_wg_noise.c - libsodium-backed WireGuard-like Noise control-plane
 *
 * NOTE: This is a skeleton/functional implementation suitable for testing.
 * The precise KDF/mixing MUST be checked against WireGuard spec for full
 * interop. Use this to integrate with your dataplane and to run tests.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <sodium.h>
#include <inttypes.h>
#include <stdlib.h>
#include <blake2.h>

#include "noise.h"

enum { COOKIE_KEY_LABEL_LEN = 8 };
static const uint8_t mac1_key_label[COOKIE_KEY_LABEL_LEN]   = "mac1----";
static const uint8_t cookie_key_label[COOKIE_KEY_LABEL_LEN] = "cookie--";

void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}   

int rte_wg_noise_init(void)
{
    if (sodium_init() < 0) {
        return -1;
    }
    return 0;
}


/* ---------------- Blake2s helpers ---------------- */

static void blake2s_hash(uint8_t *out, size_t outlen,
                         const uint8_t *in, size_t inlen,
                         const uint8_t *key, size_t keylen)
{
    blake2s_state S;
    if (key && keylen > 0)
        blake2s_init_key(&S, outlen, key, keylen);
    else
        blake2s_init(&S, outlen);
    if (in && inlen > 0)
        blake2s_update(&S, in, inlen);
    blake2s_final(&S, out, outlen);
}

/* HMAC-like construction with BLAKE2s */
static void
hmac_blake2s(uint8_t out[BLAKE2S_HASH_SIZE],
             const uint8_t *in, size_t inlen,
             const uint8_t *key, size_t keylen)
{
    uint8_t x_key[BLAKE2S_BLOCK_SIZE];
    uint8_t i_hash[BLAKE2S_HASH_SIZE];

    memset(x_key, 0, sizeof(x_key));

    if (keylen > BLAKE2S_BLOCK_SIZE) {
        blake2s_hash(x_key, BLAKE2S_HASH_SIZE, key, keylen, NULL, 0);
    } else {
        memcpy(x_key, key, keylen);
    }

    for (size_t i = 0; i < BLAKE2S_BLOCK_SIZE; ++i) x_key[i] ^= 0x36;

    /* inner = BLAKE2s(ipad || in) */
    blake2s_state st;
    blake2s_init(&st, BLAKE2S_HASH_SIZE);
    blake2s_update(&st, x_key, BLAKE2S_BLOCK_SIZE);
    if (in && inlen) blake2s_update(&st, in, inlen);
    blake2s_final(&st, i_hash, BLAKE2S_HASH_SIZE);

    /* switch to opad */
    for (size_t i = 0; i < BLAKE2S_BLOCK_SIZE; ++i) x_key[i] ^= (0x5c ^ 0x36);

    /* outer = BLAKE2s(opad || inner) */
    blake2s_init(&st, BLAKE2S_HASH_SIZE);
    blake2s_update(&st, x_key, BLAKE2S_BLOCK_SIZE);
    blake2s_update(&st, i_hash, BLAKE2S_HASH_SIZE);
    blake2s_final(&st, i_hash, BLAKE2S_HASH_SIZE);

    memcpy(out, i_hash, BLAKE2S_HASH_SIZE);

    sodium_memzero(x_key, sizeof(x_key));
    sodium_memzero(i_hash, sizeof(i_hash));
}

/* HKDF-like KDF with BLAKE2s */
static void
kdf_blake2s(uint8_t *out1, uint8_t *out2, uint8_t *out3,
            const uint8_t *data, size_t data_len,
            const uint8_t chaining_key[RTE_WG_HASH_LEN])
{
    uint8_t secret[BLAKE2S_HASH_SIZE];
    uint8_t tmp[BLAKE2S_HASH_SIZE + 1];

    hmac_blake2s(secret, data, data_len, chaining_key, RTE_WG_HASH_LEN);

    tmp[0] = 1;
    hmac_blake2s(tmp, tmp, 1, secret, BLAKE2S_HASH_SIZE);
    if (out1) memcpy(out1, tmp, RTE_WG_KEY_LEN);

    if (out2) {
        memcpy(tmp, out1, RTE_WG_KEY_LEN);
        tmp[RTE_WG_KEY_LEN] = 2;
        hmac_blake2s(tmp, tmp, RTE_WG_KEY_LEN + 1, secret, BLAKE2S_HASH_SIZE);
        memcpy(out2, tmp, RTE_WG_KEY_LEN);
    }

    if (out3) {
        const uint8_t *src = out2 ? out2 : out1;
        memcpy(tmp, src, RTE_WG_KEY_LEN);
        tmp[RTE_WG_KEY_LEN] = 3;
        hmac_blake2s(tmp, tmp, RTE_WG_KEY_LEN + 1, secret, BLAKE2S_HASH_SIZE);
        memcpy(out3, tmp, RTE_WG_KEY_LEN);
    }

    sodium_memzero(secret, sizeof(secret));
    sodium_memzero(tmp, sizeof(tmp));
}

/* mix_hash = HASH(h || src) */
static void
mix_hash(uint8_t hash[RTE_WG_HASH_LEN], const uint8_t *src, size_t src_len)
{
    blake2s_state st;
    blake2s_init(&st, RTE_WG_HASH_LEN);
    blake2s_update(&st, hash, RTE_WG_HASH_LEN);
    blake2s_update(&st, src, src_len);
    blake2s_final(&st, hash, RTE_WG_HASH_LEN);
}

/* mix_dh: perform X25519(private, public) -> dh; then kdf(chaining_key, dh) to update ck and produce key */
static int
mix_dh(uint8_t chaining_key[RTE_WG_HASH_LEN],
       uint8_t key[RTE_WG_KEY_LEN],
       const uint8_t private[32],
       const uint8_t public[32])
{
    uint8_t dh[32];
    if (crypto_scalarmult_curve25519(dh, private, public) != 0) {
        return -1;
    }
    /* kdf: new_ck = kdf(chaining_key, dh) => outputs (ck, key) */
    uint8_t new_ck[RTE_WG_HASH_LEN];
    uint8_t out_key[RTE_WG_KEY_LEN];
    /* Kernel performs kdf(chaining_key, dh) where secret=HMAC(ck, dh) and outputs are successive hmacs,
     * here we use same helper to get two outputs */
    kdf_blake2s(new_ck, out_key, NULL, dh, sizeof(dh), chaining_key);
    memcpy(chaining_key, new_ck, RTE_WG_HASH_LEN);
    memcpy(key, out_key, RTE_WG_KEY_LEN);
    sodium_memzero(dh, sizeof(dh));
    sodium_memzero(new_ck, sizeof(new_ck));
    sodium_memzero(out_key, sizeof(out_key));
    return 0;
}

/* message_decrypt: AEAD decrypt (ChaCha20-Poly1305 IETF) with AAD=hash, nonce=0 per Noise handshake.
 * On success, mix_hash(hash, ciphertext).
 */
static int
message_decrypt(uint8_t *dst_plain, size_t *dst_len,
                const uint8_t *src_cipher, size_t src_len,
                const uint8_t key[RTE_WG_KEY_LEN],
                uint8_t hash[RTE_WG_HASH_LEN])
{
    unsigned long long mlen = 0;
    uint8_t nonce[12] = {0};

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            dst_plain, &mlen,
            NULL,
            src_cipher, src_len,
            hash, RTE_WG_HASH_LEN,
            nonce, key) != 0) {
        printf("Error!! decrypt failed in crypto_aead_chacha20poly1305_ietf_decrypt\n");
        return -1;
    }

    /* mix ciphertext (including tag) into hash */
    mix_hash(hash, src_cipher, src_len);
    *dst_len = (size_t)mlen;
    return 0;
}

/* Compute mac1 from packet and static_pub */
int wg_compute_mac1(uint8_t mac1[RTE_WG_MAC_LEN],
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t static_pub[NOISE_PUBLIC_KEY_LEN])
{
    if (msg_len < 16)
        return -1; /* malformed packet */

    uint8_t message_mac1_key[NOISE_SYMMETRIC_KEY_LEN];

    /* === Step 1: Precompute per-peer key === */
    {
        blake2s_state S;
        if (blake2s_init(&S, NOISE_SYMMETRIC_KEY_LEN) < 0)
            return -1;

        blake2s_update(&S, mac1_key_label, COOKIE_KEY_LABEL_LEN);
        blake2s_update(&S, static_pub, NOISE_PUBLIC_KEY_LEN);
        blake2s_final(&S, message_mac1_key, NOISE_SYMMETRIC_KEY_LEN);
    }

    /* === Step 2: Compute keyed BLAKE2s over message[0 .. mac1_offset) === */
    if (blake2s(mac1, msg, message_mac1_key,
                RTE_WG_MAC_LEN, msg_len, NOISE_SYMMETRIC_KEY_LEN) < 0)
        return -1;

    return 0; /* success */
}

/* Compute mac2 similarly but includes cookie appended to the input */
static void
mac2_compute(uint8_t mac_out[RTE_WG_MAC_LEN],
             const uint8_t *msg, size_t msg_len,
             const uint8_t cookie[RTE_WG_MAC_LEN],
             const uint8_t responder_static_pub[32])
{
    uint8_t key[RTE_WG_HASH_LEN];
    blake2s_hash(key, RTE_WG_HASH_LEN, responder_static_pub, 32, NULL, 0);

    blake2s_state st;
    blake2s_init(&st, RTE_WG_HASH_LEN);
    blake2s_update(&st, msg, msg_len);
    blake2s_update(&st, cookie, RTE_WG_MAC_LEN);
    blake2s_final(&st, mac_out, RTE_WG_MAC_LEN);

    //sodium_memzero(key, sizeof(key));
}

/* read little-endian u16 safely */
static int read_u16_le(const uint8_t *p, size_t remain, uint16_t *out)
{
    if (remain < 2) {
        printf("Error!! read_u16_le with insufficient data\n");
        return -1;
    }
    *out = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    return 0;
}

/*
 * Main function: consume initiation (responder side)
 *
 * - msg/msg_len: received handshake initiation bytes
 * - resp_static_priv/resp_static_pub: responder static keypair (32 bytes each)
 * - cookie_secret: optional pointer to 16-byte cookie secret for mac2 verification; pass NULL if not used
 * - cookie_len: length of cookie_secret (must be >= 16 if provided)
 * - out: filled on success
 *
 * Returns 0 on success, -1 on error.
 */
int
rte_wg_noise_handshake_consume_initiation(
    const uint8_t *msg, size_t msg_len,
    const uint8_t resp_static_priv[32], const uint8_t resp_static_pub[32],
    const uint8_t *cookie_secret, size_t cookie_len,
    struct rte_wg_handshake *out)
{
    if (!msg || !resp_static_priv || !resp_static_pub || !out) return -1;
    /* minimal sanity: ephemeral(32) + enc_static_len(2) + enc_ts_len(2) + mac1(16) = 52+ */
    if (msg_len < 52) {
        printf("Error!! msg_len too short\n");
        return -1;
    }

    struct wg_init_hdr *init_hdr = (struct wg_init_hdr *)msg;

    memcpy(out->initiator_ephemeral, init_hdr->ephemeral, 32);

    const uint8_t *mac1 = init_hdr->mac1;
    const uint8_t *mac2 = init_hdr->mac2;

    /* compute mac_area_len (len without trailing macs) */
    size_t mac_area_len = msg_len - (mac2 ? 32 : 16);

    /* verify mac1 */
    uint8_t calc1[RTE_WG_MAC_LEN];
    /*mac1 = BLAKE2s(message_without_macs, key = mac1_key) where mac1_key = BLAKE2s("mac1----", responder_static_pubkey)*/
    wg_compute_mac1(calc1, msg, mac_area_len, resp_static_pub);

    if (sodium_memcmp(calc1, mac1, RTE_WG_MAC_LEN) != 0) {
    
        /* mac1 mismatch */
        printf("Error!! mac1 mismatch\n");
        print_hex("expected mac1", mac1, RTE_WG_MAC_LEN);
        print_hex("calculated mac1", calc1, RTE_WG_MAC_LEN);
        return -1;
    }
    else {
        //printf("mac1 verified\n");
    }


    // MAC2 verification omitted for simplicity; will be implemeneted later
    /* if mac2 present, require cookie_secret and verify */
    /*if (mac2) { 
        if (!cookie_secret || cookie_len < RTE_WG_MAC_LEN) {
            printf("Error!! mac2 present but no valid cookie_secret\n");
            return -1;
        }
        uint8_t calc2[RTE_WG_MAC_LEN];
        mac2_compute(calc2, msg, mac_area_len, cookie_secret, resp_static_pub);
        if (sodium_memcmp(calc2, mac2, RTE_WG_MAC_LEN) != 0) {
            sodium_memzero(calc2, sizeof(calc2));
            printf("Error!! mac2 mismatch\n");
            return -1;
        }
        sodium_memzero(calc2, sizeof(calc2));
    }*/ 


    /* --- handshake transcript init --- */
    /* handshake_name and prologue used by kernel: use exact constants to match kernel */
    const uint8_t handshake_name[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    const uint8_t identifier_name[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";

    uint8_t chaining_key[RTE_WG_HASH_LEN];
    uint8_t h[RTE_WG_HASH_LEN];

    /* ck = HASH(handshake_name) */
    blake2s_hash(chaining_key, RTE_WG_HASH_LEN,
                               handshake_name, sizeof(handshake_name)-1,
                               NULL, 0);

    /* h = HASH(ck || identifier_name) */
    {
        blake2s_state st;
        blake2s_init(&st, RTE_WG_HASH_LEN);
        blake2s_update(&st, chaining_key, RTE_WG_HASH_LEN);
        blake2s_update(&st, identifier_name, sizeof(identifier_name)-1);
        blake2s_final(&st, h, RTE_WG_HASH_LEN);

    }

    /* mix_hash(h, initiator_ephemeral) */
    mix_hash(h, out->initiator_ephemeral, 32);

    /* kdf(chaining_key, ephemeral_pub) step kernel does (we implement via kdf_blake2s) */
    {
        uint8_t tmp_ck[RTE_WG_HASH_LEN];
        /* kernel updates chaining_key with kdf(chaining_key, ephemeral_pub) -> new ck */
        kdf_blake2s(tmp_ck, NULL, NULL, out->initiator_ephemeral, 32, chaining_key);
        memcpy(chaining_key, tmp_ck, RTE_WG_HASH_LEN);
        sodium_memzero(tmp_ck, sizeof(tmp_ck));
    }

    /* DH(eph_i, static_r) -> mix_dh: updates chaining_key and yields temp_k */
    uint8_t temp_k[RTE_WG_KEY_LEN];
    if (mix_dh(chaining_key, temp_k, resp_static_priv, out->initiator_ephemeral) != 0) {
        sodium_memzero(temp_k, sizeof(temp_k));
        printf("Error!! mix_dh failed\n");
        return -1;
    }

    /* decrypt enc_static using temp_k with AAD = h and nonce=0 */
    uint8_t dec_static[32];
    size_t dec_len = 0;
    if (message_decrypt(dec_static, &dec_len, init_hdr->enc_static, sizeof(init_hdr->enc_static), temp_k, h) != 0) {
        sodium_memzero(temp_k, sizeof(temp_k));
        printf("Error!! decrypting enc_static failed\n");
        return -1;
    }
    if (dec_len != 32) {
        sodium_memzero(temp_k, sizeof(temp_k));
        printf("Error!! decrypting enc_static wrong length\n");
        return -1;
    }
    memcpy(out->initiator_static, dec_static, 32);

    /* mix_dh(static_i, static_r) */
    uint8_t temp_k2[RTE_WG_KEY_LEN];
    if (mix_dh(chaining_key, temp_k2, dec_static, resp_static_priv) != 0) {
        sodium_memzero(temp_k, sizeof(temp_k));
        sodium_memzero(temp_k2, sizeof(temp_k2));
        printf("Error!! mix_dh 2 failed\n");
        return -1;
    }

    /* If PSK present, kernel calls mix_psk() here. Omitted unless you support PSK. */

    /* decrypt timestamp/cookie field with temp_k2 and AAD = h */
    uint8_t dec_ts[256];
    size_t dec_ts_len = 0;
    if (message_decrypt(dec_ts, &dec_ts_len, init_hdr->enc_ts, sizeof(init_hdr->enc_ts), temp_k2, h) != 0) {
        sodium_memzero(temp_k, sizeof(temp_k));
        sodium_memzero(temp_k2, sizeof(temp_k2));
        printf("Error!! decrypting enc_ts failed\n");
        return -1;
    }

    /* Caller should perform timestamp/replay checks based on dec_ts content if desired.
     * (kernel uses TAI64N timestamp checks) */

    /* Fill output ck and h */
    memcpy(out->ck, chaining_key, RTE_WG_HASH_LEN);
    memcpy(out->h, h, RTE_WG_HASH_LEN);

    /* derive handshake symmetric keys (k_enc/k_dec) using kdf(chaining_key, NULL) -> outputs */
    {
        uint8_t k1[RTE_WG_KEY_LEN], k2[RTE_WG_KEY_LEN];
        kdf_blake2s(k1, k2, NULL, NULL, 0, chaining_key);
        /* Kernel ordering defines which is enc/dec depending on role; responder typically uses different mapping.
         * For responder: k_enc = k1, k_dec = k2 (this mapping must match create_response/consume_response usage).
         */
        memcpy(out->k_enc, k1, RTE_WG_KEY_LEN);
        memcpy(out->k_dec, k2, RTE_WG_KEY_LEN);
        sodium_memzero(k1, sizeof(k1));
        sodium_memzero(k2, sizeof(k2));
    }

    /* sender_index present in kernel initiation message before macs; if present parse it.
     * In the kernel's struct message_handshake_initiation, sender index is at offset 0 (or included).
     * Our simplified parser earlier didn't extract it; if your wire format includes sender_index, extract and store it.
     */
    out->sender_index = 0; /* set by caller if they parse sender_index elsewhere */

    /* wipe temps */
    sodium_memzero(temp_k, sizeof(temp_k));
    sodium_memzero(temp_k2, sizeof(temp_k2));
    sodium_memzero(dec_static, sizeof(dec_static));
    sodium_memzero(dec_ts, sizeof(dec_ts));
    sodium_memzero(chaining_key, sizeof(chaining_key));
    sodium_memzero(h, sizeof(h));
    return 0;
}

/* Small test main (optional)
 * Compile with -DTEST_WG_CONSUME to enable a skeleton test harness; otherwise omit.
 */
#ifdef TEST_WG_CONSUME
int main(void)
{
    if (sodium_init() < 0) { fprintf(stderr, "libsodium init failed\n"); return 1; }
    /* This test is illustrative only; it won't run real handshake without valid message bytes. */
    printf("rte_wg_noise_handshake_consume_initiation compiled OK\n");
    return 0;
}
#endif

