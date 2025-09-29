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
#include <string.h>
#include <endian.h>   // for htole32 (Linux/glibc)

#include "noise.h"

enum { COOKIE_KEY_LABEL_LEN = 8 };
static const uint8_t mac1_key_label[COOKIE_KEY_LABEL_LEN]   = "mac1----";
static const uint8_t cookie_key_label[COOKIE_KEY_LABEL_LEN] = "cookie--";

/* handshake_name and prologue used by kernel: use exact constants to match kernel */
const uint8_t handshake_name[37] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const uint8_t identifier_name[34] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
uint8_t handshake_init_hash[NOISE_HASH_LEN];
uint8_t handshake_init_chaining_key[NOISE_HASH_LEN];


void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
} 

static inline uint32_t to_le32(uint32_t v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return v;
#else
    return ((v & 0xff) << 24) |
           ((v & 0xff00) << 8) |
           ((v & 0xff0000) >> 8) |
           ((v >> 24) & 0xff);
#endif
}

size_t wg_resp_hdr_serialize(const struct wg_resp_hdr *hdr, uint8_t *out_buf) {
    uint8_t *p = out_buf;

    // type
    *p++ = hdr->type;

    // reserved_zero
    memcpy(p, hdr->reserved_zero, sizeof(hdr->reserved_zero));
    p += sizeof(hdr->reserved_zero);

    // sender_index (convert to little endian)
    uint32_t sender_le = htole32(hdr->sender_index);
    memcpy(p, &sender_le, sizeof(sender_le));
    p += sizeof(sender_le);

    // sender_index (convert to little endian)
    uint32_t receiver_le = htole32(hdr->receiver_index);
    memcpy(p, &receiver_le, sizeof(receiver_le));
    p += sizeof(receiver_le);

    // ephemeral
    memcpy(p, hdr->ephemeral, NOISE_PUBLIC_KEY_LEN);
    p += NOISE_PUBLIC_KEY_LEN;

    // encrypted_nothing
    memcpy(p, hdr->encrypted_nothing, noise_encrypted_len(0));
    p += noise_encrypted_len(0);

    // mac1
    memcpy(p, hdr->mac1, sizeof(hdr->mac1));
    p += sizeof(hdr->mac1);

    // mac2
    memcpy(p, hdr->mac2, sizeof(hdr->mac2));
    p += sizeof(hdr->mac2);

    return p - out_buf; // total length written
}

/* ---------------- Blake2s helpers ---------------- */

static void blake2s_hash(uint8_t *out, size_t outlen,
                         const uint8_t *in, size_t inlen,
                         const uint8_t *key, size_t keylen)
{
    blake2s_state S;
    blake2s_init(&S, outlen);
    if(key && keylen > 0)
        blake2s_update(&S, key, keylen);
    if (in && inlen > 0)
        blake2s_update(&S, in, inlen);
    blake2s_final(&S, out, outlen);
}

int rte_wg_noise_init(void)
{
    if (sodium_init() < 0) {
        return -1;
    }

    /* ck = HASH(handshake_name) */
    blake2s_hash(handshake_init_chaining_key, NOISE_HASH_LEN,
                               handshake_name, sizeof(handshake_name),
                               NULL, 0);

    /* h = HASH(ck || identifier_name) */
    /*Confirmed identical outputs with kernel code*/
    {
        blake2s_state st;
        blake2s_init(&st, NOISE_HASH_LEN);
        blake2s_update(&st, handshake_init_chaining_key, NOISE_HASH_LEN);
        blake2s_update(&st, identifier_name, sizeof(identifier_name));
        blake2s_final(&st, handshake_init_hash, NOISE_HASH_LEN);

    }
    return 0;
}

/* HMAC-like construction with BLAKE2s */
/*Function verified with kernel code*/
static void
hmac_blake2s(uint8_t out[BLAKE2S_HASH_SIZE],
             const uint8_t *in, size_t inlen,
             const uint8_t *key, size_t keylen)
{
    uint8_t x_key[BLAKE2S_BLOCK_SIZE]; //May need aligning?
    uint8_t i_hash[BLAKE2S_HASH_SIZE];

    memset(x_key, 0, sizeof(x_key)); //Done at initialization on kernel code
    blake2s_state st;
    if (keylen > BLAKE2S_BLOCK_SIZE) {
        //blake2s_hash(x_key, BLAKE2S_HASH_SIZE, key, keylen, NULL, 0); // Done with 3 Step blake hash on kernel code
        blake2s_init(&st, BLAKE2S_HASH_SIZE); //New blake2s hash state created, on the kernel code it is reused
        blake2s_update(&st, key, keylen);
        blake2s_final(&st, x_key, BLAKE2S_HASH_SIZE);
    } else {
        memcpy(x_key, key, keylen);
    }

    for (size_t i = 0; i < BLAKE2S_BLOCK_SIZE; ++i) x_key[i] ^= 0x36; //XOR Operation, same a kernel code

    /* inner = BLAKE2s(ipad || in) */
    //blake2s_state st; //New blake2s hash state created, on the kernel code it is reused from previous step
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
//kdf_blake2s(tmp_ck, NULL, NULL, out->initiator_ephemeral, 32, chaining_key);
/*Function verified with kernel code*/
static void
kdf_blake2s(uint8_t *out1, uint8_t *out2, uint8_t *out3,
            const uint8_t *data, size_t data_len,
            const uint8_t chaining_key[RTE_WG_HASH_LEN])
{
    uint8_t secret[BLAKE2S_HASH_SIZE];
    uint8_t tmp[BLAKE2S_HASH_SIZE + 1]; //Output buffer

    hmac_blake2s(secret, data, data_len, chaining_key, RTE_WG_HASH_LEN);

    tmp[0] = 1;
    hmac_blake2s(tmp, tmp, 1, secret, BLAKE2S_HASH_SIZE);
    if (out1) memcpy(out1, tmp, RTE_WG_KEY_LEN);

    if (out2) {
        memcpy(tmp, out1, RTE_WG_KEY_LEN); //Why do this?
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
/*Function verified with kernel code*/
static void
mix_hash(uint8_t hash[NOISE_HASH_LEN], const uint8_t *src, size_t src_len)
{
    blake2s_state st;
    blake2s_init(&st, NOISE_HASH_LEN);
    blake2s_update(&st, hash, NOISE_HASH_LEN);
    blake2s_update(&st, src, src_len);
    blake2s_final(&st, hash, NOISE_HASH_LEN);
}

static void mix_psk(uint8_t chaining_key[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN],
		    uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
		    const uint8_t psk[NOISE_SYMMETRIC_KEY_LEN])
{
	uint8_t temp_hash[NOISE_HASH_LEN];

	kdf_blake2s(chaining_key, temp_hash, key, psk, NOISE_SYMMETRIC_KEY_LEN, chaining_key);
	mix_hash(hash, temp_hash, NOISE_HASH_LEN);
	sodium_memzero(temp_hash, NOISE_HASH_LEN);
}

/* mix_dh: perform X25519(private, public) -> dh; then kdf(chaining_key, dh) to update ck and produce key */
/*Checked with kernel code*/
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
    if (key){
        memcpy(key, out_key, RTE_WG_KEY_LEN);
    }
    sodium_memzero(dh, sizeof(dh));
    sodium_memzero(new_ck, sizeof(new_ck));
    sodium_memzero(out_key, sizeof(out_key));
    return 0;
}

/* mix_dh: perform X25519(private, public) -> dh; then kdf(chaining_key, dh) to update ck and produce key */
/*Checked with kernel code*/
static int
mix_precomputed_dh(uint8_t chaining_key[RTE_WG_HASH_LEN],
       uint8_t key[RTE_WG_KEY_LEN],
       const uint8_t private[32],
       const uint8_t public[32])
{
    /* kdf: new_ck = kdf(chaining_key, dh) => outputs (ck, key) */
    uint8_t new_ck[RTE_WG_HASH_LEN];
    uint8_t out_key[RTE_WG_KEY_LEN];
    /* Kernel performs kdf(chaining_key, dh) where secret=HMAC(ck, dh) and outputs are successive hmacs,
     * here we use same helper to get two outputs */
    kdf_blake2s(new_ck, out_key, NULL, private, sizeof(private), chaining_key);
    memcpy(chaining_key, new_ck, RTE_WG_HASH_LEN);
    memcpy(key, out_key, RTE_WG_KEY_LEN);
    sodium_memzero(new_ck, sizeof(new_ck));
    sodium_memzero(out_key, sizeof(out_key));
    return 0;
}

static void handshake_init(uint8_t chaining_key[NOISE_HASH_LEN],
			   uint8_t hash[NOISE_HASH_LEN],
			   const uint8_t remote_static[NOISE_PUBLIC_KEY_LEN])
{
	memcpy(hash, handshake_init_hash, NOISE_HASH_LEN);
	memcpy(chaining_key, handshake_init_chaining_key, NOISE_HASH_LEN);
	mix_hash(hash, remote_static, NOISE_PUBLIC_KEY_LEN);
}

static int message_encrypt(uint8_t *dst_ciphertext, const uint8_t *src_plaintext,
			    size_t src_len, uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
			    uint8_t hash[NOISE_HASH_LEN])
{
	// chacha20poly1305_encrypt(dst_ciphertext, src_plaintext, src_len, hash,
	// 			 NOISE_HASH_LEN,
	// 			 0 /* Always zero for Noise_IK */, key);

    unsigned long long mlen = 0;
    uint8_t nonce[12] = {0};

    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            dst_ciphertext, &mlen,
            src_plaintext, src_len,
            hash, NOISE_HASH_LEN,
            NULL,
            nonce, key) != 0) {
        printf("Error!! encrypt failed in crypto_aead_chacha20poly1305_ietf_encrypt\n");
        return -1;
    }


	mix_hash(hash, dst_ciphertext, mlen);
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

static void message_ephemeral(uint8_t ephemeral_dst[NOISE_PUBLIC_KEY_LEN],
			      const uint8_t ephemeral_src[NOISE_PUBLIC_KEY_LEN],
			      uint8_t chaining_key[NOISE_HASH_LEN],
			      uint8_t hash[NOISE_HASH_LEN])
{
	if (ephemeral_dst != ephemeral_src)
		memcpy(ephemeral_dst, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
	mix_hash(hash, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
	kdf_blake2s(chaining_key, NULL, NULL, ephemeral_src, NOISE_HASH_LEN, chaining_key);
}

/* Compute mac1 from packet and static_pub */
int compute_mac1(uint8_t mac1[RTE_WG_MAC_LEN],
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t static_pub[NOISE_PUBLIC_KEY_LEN])
{
    if (msg_len < 16)
        return -1; /* malformed packet */

    uint8_t message_mac1_key[NOISE_SYMMETRIC_KEY_LEN];

    /* === Step 1: Precompute per-peer key === */
    blake2s_hash(message_mac1_key, NOISE_SYMMETRIC_KEY_LEN,
                 static_pub, NOISE_PUBLIC_KEY_LEN,
                 mac1_key_label, COOKIE_KEY_LABEL_LEN);

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

    uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
	uint8_t chaining_key[NOISE_HASH_LEN];
	uint8_t hash[NOISE_HASH_LEN];
	uint8_t s[NOISE_PUBLIC_KEY_LEN];
	uint8_t e[NOISE_PUBLIC_KEY_LEN];
	uint8_t t[NOISE_TIMESTAMP_LEN];
	uint64_t initiation_consumption;
    
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
    compute_mac1(calc1, msg, mac_area_len, resp_static_pub);

    if (sodium_memcmp(calc1, mac1, RTE_WG_MAC_LEN) != 0) {
    
        /* mac1 mismatch */
        printf("Error!! mac1 mismatch\n");
        // print_hex("expected mac1", mac1, RTE_WG_MAC_LEN);
        // print_hex("calculated mac1", calc1, RTE_WG_MAC_LEN);
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



    /* Handled by handshake_init in kernel code */
    handshake_init(chaining_key, hash, resp_static_pub);

    /* e */
    message_ephemeral(e, out->initiator_ephemeral, chaining_key, hash);

    /* es */
    if (mix_dh(chaining_key, key, resp_static_priv, e) != 0) {
        printf("Error!! mix_dh failed\n");
        return -1;
    }

    /* decrypt enc_static using temp_k with AAD = h and nonce=0 */
    /* s */
    size_t s_len = 0;
    if (message_decrypt(s, &s_len, init_hdr->enc_static, sizeof(init_hdr->enc_static), key, hash) != 0) {
        printf("Error!! decrypting enc_static failed\n");
        return -1;
    }
    if (s_len != 32) {
        printf("Error!! decrypting enc_static wrong length\n");
        return -1;
    }

    /* We should look for the peer in hashtable here */
    memcpy(out->initiator_static, s, 32); //Eventual goal is to decrypt and store the initiator static key

    /* same as mix_precomputed_dh but without precomputed key */
    /* ss */
    if (mix_dh(chaining_key, key, resp_static_priv, s) != 0) {
        printf("Error!! mix_dh 2 failed\n");
        return -1;
    }

    /* If PSK present, kernel calls mix_psk() here. Omitted unless you support PSK. */

    /* {t}*/
    /* decrypt timestamp/cookie field with temp_k2 and AAD = h */
    size_t t_len = 0;
    if (message_decrypt(t, &t_len, init_hdr->enc_ts, sizeof(init_hdr->enc_ts), key, hash) != 0) {
        printf("Error!! decrypting enc_ts failed\n");
        return -1;
    }

    /* Caller should perform timestamp/replay checks based on dec_ts content if desired.
     * (kernel uses TAI64N timestamp checks) */

    /* Fill output ck and h */
    memcpy(out->chaining_key, chaining_key, RTE_WG_HASH_LEN);
    memcpy(out->hash, hash, RTE_WG_HASH_LEN);
    memcpy(out->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);

    /* derive handshake symmetric keys (k_enc/k_dec) using kdf(handshake_init_chaining_key, NULL) -> outputs */
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
    out->sender_index = init_hdr->sender_index;
    out->state = HANDSHAKE_CONSUMED_INITIATION;

    /* wipe temps */
    //sodium_memzero(temp_k, sizeof(temp_k));
    sodium_memzero(key, sizeof(key));
    sodium_memzero(s, sizeof(s));
    sodium_memzero(t, sizeof(t));
    sodium_memzero(chaining_key, sizeof(chaining_key));
    sodium_memzero(hash, sizeof(hash));
    return 0;
}

int wg_noise_handshake_create_response(struct wg_resp_hdr *resp_hdr, size_t msg_len,
    const uint8_t resp_static_priv[32], const uint8_t resp_static_pub[32],
    const uint8_t peer_static_pub[32], const uint8_t *cookie_secret, size_t cookie_len,
    struct rte_wg_handshake *handshake)
{
	uint8_t key[NOISE_SYMMETRIC_KEY_LEN];

	/* We need to wait for crng _before_ taking any locks, since
	 * curve25519_generate_secret uses get_random_bytes_wait.
	 */
	//wait_for_random_bytes();

	// down_read(&handshake->static_identity->lock);
	// down_write(&handshake->lock);

    sodium_memzero(handshake->preshared_key, NOISE_SYMMETRIC_KEY_LEN); //PSK not supported in this example

	if (handshake->state != HANDSHAKE_CONSUMED_INITIATION)
		goto out;

	resp_hdr->type = MESSAGE_HANDSHAKE_RESPONSE;
	resp_hdr->sender_index = handshake->sender_index; /* from initiation */

	/* e */

    if(crypto_box_keypair(resp_hdr->ephemeral, handshake->ephemeral_private)>0){
        printf("Error!! crypto_box_keypair failed\n");
        goto out;
    }
	message_ephemeral(resp_hdr->ephemeral,
			  resp_hdr->ephemeral, handshake->chaining_key,
			  handshake->hash);

    // print_hex("resp chaining_key", handshake->chaining_key, NOISE_HASH_LEN);
    // print_hex("resp hash", handshake->hash, NOISE_HASH_LEN);

	/* ee */
	if (mix_dh(handshake->chaining_key, NULL, handshake->ephemeral_private,
		    handshake->remote_ephemeral)!= 0)
		goto out;
    
    print_hex("resp chaining_key after ee", handshake->chaining_key, NOISE_HASH_LEN);

	/* se */
	if (mix_dh(handshake->chaining_key, NULL, handshake->ephemeral_private,
		    peer_static_pub)!= 0)
		goto out;
    
    print_hex("resp chaining_key after se", handshake->chaining_key, NOISE_HASH_LEN);
	/* psk */
	mix_psk(handshake->chaining_key, handshake->hash, key,
		handshake->preshared_key);
        
    print_hex("peer static pub", peer_static_pub, NOISE_PUBLIC_KEY_LEN);
    print_hex("resp ephemeral pub", resp_hdr->ephemeral, NOISE_PUBLIC_KEY_LEN);    
    print_hex("resp chaining_key after psk", handshake->chaining_key, NOISE_HASH_LEN);
    print_hex("resp hash after psk", handshake->hash, NOISE_HASH_LEN);
    print_hex("resp key after psk", key, NOISE_SYMMETRIC_KEY_LEN);

	/* {} */
	message_encrypt(resp_hdr->encrypted_nothing, NULL, 0, key, handshake->hash);

	// dst->sender_index = wg_index_hashtable_insert(
	// 	handshake->entry.peer->device->index_hashtable,
	// 	&handshake->entry);
    resp_hdr->sender_index = handshake->sender_index+1; //Temporary measure to avoid zero sender index
    resp_hdr->receiver_index = handshake->sender_index; 

    uint8_t resp_bytes[sizeof(struct wg_resp_hdr) - 32]; //msg_len - macs
    // size_t resp_bytes_len = wg_resp_hdr_serialize(resp_hdr, resp_bytes);
    
    

    memset(resp_hdr->mac2, 0, RTE_WG_MAC_LEN); //mac2 omitted for simplicity; implement if you support cookies
    memset(resp_hdr->reserved_zero, 0, sizeof(resp_hdr->reserved_zero));
    uint8_t mac1_tmp[RTE_WG_MAC_LEN];
    memcpy(resp_bytes, resp_hdr, sizeof(struct wg_resp_hdr) - 32);
    /* mac1 */
    if (compute_mac1(mac1_tmp, resp_bytes, sizeof(struct wg_resp_hdr) - 32,
                     peer_static_pub) != 0)
        goto out;
    
   
    memcpy(resp_hdr->mac1, mac1_tmp, RTE_WG_MAC_LEN);
     print_hex("mac1", resp_hdr->mac1, RTE_WG_MAC_LEN);
    /* mac2 */
    /* mac2 omitted for simplicity; implement if you support cookies */

	handshake->state = HANDSHAKE_CREATED_RESPONSE;
	
    return 1;

out:
	// up_write(&handshake->lock);
	// up_read(&handshake->static_identity->lock);
	sodium_memzero(key, NOISE_SYMMETRIC_KEY_LEN);
	return -1;
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

