/* SPDX-License-Identifier: BSD-3-Clause
 * rte_wg_noise.h - WireGuard-like Noise API for DPDK control-plane
 *
 * Public control-plane API to perform Noise handshakes and derive session keys.
 * Uses libsodium for crypto primitives.
 */

#ifndef _RTE_WG_NOISE_H_
#define _RTE_WG_NOISE_H_

#include <stdint.h>
#include <stddef.h>

/* Sizes (WireGuard/kernel constants) */
#define RTE_WG_HASH_LEN 32    /* BLAKE2s hash size */
#define RTE_WG_KEY_LEN 32
#define RTE_WG_MAC_LEN 16
#define BLAKE2S_BLOCK_SIZE 64
#define BLAKE2S_HASH_SIZE 32


enum noise_lengths {
	NOISE_PUBLIC_KEY_LEN = 32,//CURVE25519_KEY_SIZE,
	NOISE_SYMMETRIC_KEY_LEN = 32,//CHACHA20POLY1305_KEY_SIZE,
	NOISE_TIMESTAMP_LEN = sizeof(uint64_t) + sizeof(uint32_t),
	NOISE_AUTHTAG_LEN = 16,//CHACHA20POLY1305_AUTHTAG_SIZE,
	NOISE_HASH_LEN = 32//BLAKE2S_HASH_SIZE
};

#define noise_encrypted_len(plain_len) ((plain_len) + NOISE_AUTHTAG_LEN)

enum message_type {
	MESSAGE_INVALID = 0,
	MESSAGE_HANDSHAKE_INITIATION = 1,
	MESSAGE_HANDSHAKE_RESPONSE = 2,
	MESSAGE_HANDSHAKE_COOKIE = 3,
	MESSAGE_DATA = 4
};

enum noise_handshake_state {
	HANDSHAKE_ZEROED,
	HANDSHAKE_CREATED_INITIATION,
	HANDSHAKE_CONSUMED_INITIATION,
	HANDSHAKE_CREATED_RESPONSE,
	HANDSHAKE_CONSUMED_RESPONSE
};

/* Handshake result struct filled by the function */
struct rte_wg_handshake {
    enum noise_handshake_state state;
    uint32_t sender_index;
    uint8_t ephemeral_private[NOISE_PUBLIC_KEY_LEN];
    uint8_t ephemeral_public[NOISE_PUBLIC_KEY_LEN];
    uint8_t remote_ephemeral[NOISE_PUBLIC_KEY_LEN];
    uint8_t preshared_key[NOISE_SYMMETRIC_KEY_LEN]; //optional
    uint8_t initiator_ephemeral[32];
    uint8_t initiator_static[32];
    uint8_t chaining_key[RTE_WG_HASH_LEN];
    uint8_t hash[RTE_WG_HASH_LEN];
    uint8_t k_enc[RTE_WG_KEY_LEN];
    uint8_t k_dec[RTE_WG_KEY_LEN];
};

/* WireGuard handshake initiation header */
struct __attribute__((packed))wg_init_hdr {
    uint8_t type;
    uint8_t reserved_zero[3];
    uint32_t sender_index;
    uint8_t ephemeral[NOISE_PUBLIC_KEY_LEN];
    uint8_t enc_static[noise_encrypted_len(NOISE_PUBLIC_KEY_LEN)];
    uint8_t enc_ts[noise_encrypted_len(NOISE_TIMESTAMP_LEN)];
    uint8_t mac1[16];
    uint8_t mac2[16];
};

struct __attribute__((packed)) wg_resp_hdr {
    uint8_t type;
    uint8_t reserved_zero[3];
    uint32_t sender_index;
    uint32_t receiver_index;
    uint8_t ephemeral[NOISE_PUBLIC_KEY_LEN];
    uint8_t encrypted_nothing[noise_encrypted_len(0)];
    uint8_t mac1[16];
    uint8_t mac2[16];
};

#ifdef __cplusplus
extern "C" {
#endif

void print_hex(const char *label, const uint8_t *data, size_t len);

size_t wg_resp_hdr_serialize(const struct wg_resp_hdr *hdr, uint8_t *out_buf);

/* initialize libsodium; call once at startup from control-plane */
int rte_wg_noise_init(void);

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
    struct rte_wg_handshake *out);



#ifdef __cplusplus
}
#endif

#endif /* _RTE_WG_NOISE_H_ */
