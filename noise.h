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

#define RTE_WG_NOISE_PUBKEY_LEN 32
#define RTE_WG_NOISE_PRIVKEY_LEN 32
#define RTE_WG_NOISE_SYMM_KEY_LEN 32  /* AEAD key length */
#define RTE_WG_NOISE_MAX_HANDSHAKE_MSG 512
#define RTE_WG_HASH_LEN   32
#define RTE_WG_KEY_LEN    32
#define RTE_WG_MAC_LEN    16

#ifdef __cplusplus
extern "C" {
#endif

/* initialize libsodium; call once at startup from control-plane */
int rte_wg_noise_init(void);

/* Generate static long-term keypair (Curve25519)
 * pub and priv must be 32 bytes buffers.
 */
int rte_wg_noise_keypair_generate(uint8_t pub[RTE_WG_NOISE_PUBKEY_LEN],
                                  uint8_t priv[RTE_WG_NOISE_PRIVKEY_LEN]);

/* Derive raw shared secret via X25519:
 * shared = X25519(priv, peer_pub)   (32 bytes)
 */
int rte_wg_noise_shared_secret(uint8_t shared[32],
                               const uint8_t priv[32],
                               const uint8_t peer_pub[32]);

/* Create a handshake initiation message (initiator -> responder).
 * - init_static_priv / init_static_pub: initiator static keypair (long-term).
 * - resp_static_pub: responder static public key (must be known).
 * - out_msg: buffer to receive handshake message bytes; out_len returns length.
 *
 * The message format is simplified: [eph_pub (32)] [enc_static_ephemeral...].
 * For testing, we encrypt a small payload (timestamp or random) using AEAD with
 * ephemeral-derived key.
 */
int rte_wg_noise_create_initiation(const uint8_t init_static_priv[32],
                                   const uint8_t init_static_pub[32],
                                   const uint8_t resp_static_pub[32],
                                   uint8_t *out_msg, size_t *out_len);

/* Consume an initiation on responder side, produce response message and derived
 * shared secrets:
 * - resp_static_priv: responder long-term private key
 * - in_msg: incoming initiation
 * - out_msg: response message to send back to initiator
 * - out_len: length of response message
 * - out_rx_key, out_tx_key: 32-byte symmetric AEAD keys to install into dataplane
 * - out_rx_index, out_tx_index: indexes (32-bit) to be used by dataplane
 *
 * Note: out_rx_key is the key that the responder will use to decrypt traffic
 *       that the initiator will send (and vice versa).
 */
int rte_wg_noise_consume_initiation_and_create_response(
    const uint8_t resp_static_priv[32],
    const uint8_t resp_static_pub[32], /* optional, used in KDF */
    const uint8_t *in_msg, size_t in_len,
    uint8_t *out_msg, size_t *out_len,
    uint8_t out_rx_key[32], uint8_t out_tx_key[32],
    uint32_t *out_rx_index, uint32_t *out_tx_index);

/* Consume a response on initiator side:
 * - init_static_priv: initiator static private key
 * - in_msg: incoming response (from responder)
 * - out_rx_key/out_tx_key: session keys to install into dataplane
 * - out_rx_index/out_tx_index: receiver indices to install
 */
int rte_wg_noise_consume_response_and_derive_keys(
    const uint8_t init_static_priv[32],
    const uint8_t init_static_pub[32],
    const uint8_t *in_msg, size_t in_len,
    uint8_t out_rx_key[32], uint8_t out_tx_key[32],
    uint32_t *out_rx_index, uint32_t *out_tx_index);

/* Utility: generate random receiver index (non-zero) */
uint32_t rte_wg_noise_generate_receiver_index(void);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_WG_NOISE_H_ */
