/* SPDX-License-Identifier: BSD-3-Clause
 * rte_wg.h
 *
 * DPDK-style WireGuard dataplane public API (enqueue/dequeue model).
 *
 * Responsibilities:
 *  - Provide fast-path encrypt/decrypt for WireGuard transport packets.
 *  - Maintain per-peer replay state, crypto session handles, and allowed-IPs map.
 *  - Expose create/destroy/config APIs for user-plane to populate (handshakes, timers, key rotation).
 *
 * Notes:
 *  - This header intentionally keeps control-plane responsibilities out of the dataplane.
 *  - User-plane (control) is expected to perform Noise handshakes and install session keys
 *    into the dataplane with rte_wg_peer_create()/rte_wg_peer_update_keys().
 */

#ifndef _RTE_WG_H_
#define _RTE_WG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

/* Version */
#define RTE_WG_VERSION_MAJOR 0
#define RTE_WG_VERSION_MINOR 1
#define RTE_WG_VERSION_PATCH 0

/* Error codes (negative) */
enum rte_wg_err {
	RTE_WG_OK = 0,
	RTE_WG_ERR_NOMEM = -1,
	RTE_WG_ERR_EXIST = -2,
	RTE_WG_ERR_NOTFOUND = -3,
	RTE_WG_ERR_INVALID = -4,
	RTE_WG_ERR_AGAIN = -5,
	RTE_WG_ERR_RANGE = -6,
	RTE_WG_ERR_FAULT = -7,
};

/* Address family */
enum rte_wg_af {
	RTE_WG_AF_INET = 4,
	RTE_WG_AF_INET6 = 6
};

/* Maximum sizes */
#define RTE_WG_PUBKEY_LEN 32
#define RTE_WG_PRIVKEY_LEN 32
#define RTE_CHACHA20POLY1305_KEY_SIZE 32
#define RTE_NOISE_SYMMETRIC_KEY_LEN RTE_CHACHA20POLY1305_KEY_SIZE
#define RTE_WG_COOKIE_LEN 16
#define RTE_WG_MAX_PEER_ALLOWED_IPS 128
#define RTE_WG_MAX_PEERS 4096

/* Replay window size (must match WireGuard semantics) */
#define RTE_WG_REPLAY_WINDOW 64

/* Opaque handles */
struct rte_wg_ctx;        /* dataplane context */
struct rte_wg_peer;       /* per-peer state / SA */

/* Crypto-session handle: opaque to dataplane library.
 * E.g. this can be a pointer to a cryptodev session, or user supplied ctx. */
typedef void *rte_wg_crypto_session_t;

/* Stats structure */
struct rte_wg_stats {
	uint64_t pkt_enc;        /* packets encrypted (outbound) */
	uint64_t pkt_dec;        /* packets decrypted (inbound) */
	uint64_t bytes_enc;
	uint64_t bytes_dec;
	uint64_t pkt_dropped_bad_mac;
	uint64_t pkt_dropped_replay;
	uint64_t pkt_dropped_no_peer;
	uint64_t pkt_dropped_bad_format;
	uint64_t pkt_queued;     /* queued for crypto */
	uint64_t pkt_dequeued;   /* dequeued after crypto */
};

/* Peer config provided by user-plane when creating a peer */
struct rte_wg_peer_conf {
	/* public identity key of the remote peer (32 bytes) */
	uint8_t pubkey[RTE_WG_PUBKEY_LEN];

	/* preshared key (optional) - 32 bytes; all-zero if unused */
	uint8_t preshared_key[RTE_WG_PRIVKEY_LEN];

	/* local/remote IP endpoints (optional, used for encapsulation metadata)
	 * If endpoint unspecified, dataplane can still operate if user-plane supplies it
	 * when sending. */
	union {
		struct { uint32_t ip4; uint16_t port; } v4;
		struct { uint8_t ip6[16]; uint16_t port; } v6;
	} endpoint;
	int endpoint_af; /* 0 = none, RTE_WG_AF_INET or RTE_WG_AF_INET6 */

	/* Optional opaque pointer for user-plane's private data. Stored verbatim. */
	void *user_data;

	/* Per-peer queue sizes (0 = use ctx defaults) */
	uint16_t tx_ring_size;
	uint16_t rx_ring_size;

	/* Optional pointer to a pre-created crypto session handle for encryption (outbound).
	 * If NULL, dataplane must be able to create a session via a provided factory
	 * or user-plane will supply sessions later via rte_wg_peer_update_crypto(). */
	rte_wg_crypto_session_t encrypt_session;

	/* Optional pointer to pre-created crypto session for decryption (inbound). */
	rte_wg_crypto_session_t decrypt_session;
};

/* Peer key material structure (only symmetric session keys necessary for dataplane).
 * User-plane will derive and provide these after Noise handshake. */
struct rte_wg_peer_keys {
	/* AEAD key used to encrypt outbound WG data (32 bytes for ChaCha20-Poly1305) */
	uint8_t tx_key[32];

	/* AEAD key used to decrypt inbound WG data (32 bytes) */
	uint8_t rx_key[32];

	/* Initial packet counters / nonces (64-bit counters) */
	uint64_t tx_counter;
	uint64_t rx_counter;

	/* Optional preshared key (32 bytes) if used */
	uint8_t preshared_key[RTE_WG_PRIVKEY_LEN];
};

/* Allowed IP entry */
struct rte_wg_allowed_ip {
	/* family: RTE_WG_AF_INET or RTE_WG_AF_INET6 */
	int family;
	/* For IPv4, store network as uint32_t + prefix length */
	union {
		uint32_t ip4;
		uint8_t ip6[16];
	} addr;
	uint8_t prefixlen;
};

/* Configuration for creating rte_wg_ctx */
struct rte_wg_config {
	/* name for debugging/logging (null-terminated) */
	const char *name;

	/* default rings (if peers use 0 for tx_ring_size/rx_ring_size) */
	uint16_t default_tx_ring_size;
	uint16_t default_rx_ring_size;

	/* maximum peers allowed (library may cap) */
	uint32_t max_peers;

	/* pointer to user-supplied function that creates crypto session
	 * if dataplane chooses to allocate them. Optional. If NULL, user-plane
	 * must provide rte_wg_peer_conf.encrypt_session/decrypt_session.
	 *
	 * The factory receives 'keys' and must return an opaque session pointer
	 * or NULL on error. */
	rte_wg_crypto_session_t (*crypto_session_create)(
		const struct rte_wg_peer_keys *keys,
		const struct rte_wg_peer_conf *pconf,
		void *factory_ctx);

	void *crypto_session_ctx;

	/* mempool used to allocate mbufs for internal operations (optional) */
	struct rte_mempool *mbuf_pool;

	/* Flags (reserved) */
	uint32_t flags;
};

/* Public API - Context lifecycle */

/* Create a WireGuard dataplane context.
 * Returns pointer on success or NULL on error (errno-style not set). */
struct rte_wg_ctx *
rte_wg_ctx_create(const struct rte_wg_config *cfg);

/* Destroy context and free all resources. Peers must be removed first. */
void
rte_wg_ctx_destroy(struct rte_wg_ctx *ctx);

/* Return library version */
void
rte_wg_version(int *major, int *minor, int *patch);

/* Peer management */

/* Create a peer (install SA metadata). The dataplane will create and return
 * an opaque peer handle. User-plane must call rte_wg_peer_update_keys() after
 * creation to install derived session keys (or pass sessions via conf). */
struct rte_wg_peer *
rte_wg_peer_create(struct rte_wg_ctx *ctx,
                   const struct rte_wg_peer_conf *conf);

/* Remove a peer and free associated resources.
 * Returns RTE_WG_OK or negative error. */
int
rte_wg_peer_remove(struct rte_wg_ctx *ctx, struct rte_wg_peer *peer);

/* Update symmetric session keys for a peer (called after Noise handshake,
 * key rotation, rekey, etc.). This installs tx/rx AEAD keys and initial counters.
 * The call may atomically swap keys. */
int
rte_wg_peer_update_keys(struct rte_wg_peer *peer,
                        const struct rte_wg_peer_keys *keys);

/* Update or set the crypto session handles (if user-plane manages cryptodev sessions).
 * Passing NULL removes the session and instructs dataplane to use crypto factory.
 * Returns RTE_WG_OK or negative error. */
int
rte_wg_peer_update_crypto(struct rte_wg_peer *peer,
                          rte_wg_crypto_session_t encrypt_session,
                          rte_wg_crypto_session_t decrypt_session);

/* Allowed-IP management */

/* Add an allowed-ip entry for a peer. Returns RTE_WG_OK or negative error.
 * The allowed ip is used by encrypt path to select peer for an outbound inner IP. */
int
rte_wg_allowedip_add(struct rte_wg_ctx *ctx,
                     struct rte_wg_peer *peer,
                     const struct rte_wg_allowed_ip *allowed);

/* Remove allowed-ip entry. Returns RTE_WG_OK or negative. */
int
rte_wg_allowedip_remove(struct rte_wg_ctx *ctx,
                        struct rte_wg_peer *peer,
                        const struct rte_wg_allowed_ip *allowed);

/* Lookup peer by destination IP (used by outbound path). Returns peer pointer
 * or NULL if no match. Caller must not free peer. */
struct rte_wg_peer *
rte_wg_allowedip_lookup(struct rte_wg_ctx *ctx,
                        const void *addr, /* pointer to uint32_t for v4 or uint8_t[16] for v6 */
                        int family);

/* Optional helper to flush all allowed-ips of a peer */
int
rte_wg_allowedip_clear(struct rte_wg_ctx *ctx, struct rte_wg_peer *peer);

/* Enqueue/Dequeue model - Outbound (Encryption) */

/* Enqueue a burst of inner packets for encryption and encapsulation.
 *
 * - mbufs[] point to rte_mbufs that hold the *inner* IP packets (L3 payload).
 * - For each mbuf, dataplane will:
 *     1) Use allowed-ips to select a peer (unless user specified a peer via mbuf metadata).
 *     2) Build WireGuard payload and UDP encapsulation in the mbuf (or in new mbuf).
 *     3) Submit crypto AEAD encrypt job (sync or async depending on implementation).
 *     4) Queue the output into an internal TX ring for dequeue.
 *
 * Returns number of mbufs successfully accepted into the dataplane (0..nb_mbufs).
 * On failure, remaining mbufs are untouched and caller must handle them.
 */
uint16_t
rte_wg_encrypt_enqueue(struct rte_wg_ctx *ctx,
                       struct rte_mbuf *mbufs[], uint16_t nb_mbufs);

/* Dequeue a burst of encrypted/encapsulated mbufs ready for transmission.
 * The mbufs returned are fully-formed UDP/IP datagrams and are ready for
 * rte_eth_tx_burst on the appropriate port/queue (user determines egress).
 *
 * Returns number of mbufs dequeued (0..nb_mbufs). */
uint16_t
rte_wg_encrypt_dequeue(struct rte_wg_ctx *ctx,
                       struct rte_mbuf *mbufs[], uint16_t nb_mbufs);

/* Enqueue/Dequeue model - Inbound (Decryption) */

/* Enqueue a burst of received mbufs containing UDP datagrams (WireGuard wire format).
 * For each mbuf, dataplane will:
 *   1) Parse WG header, find peer (by index/public key/endpoint).
 *   2) Submit AEAD decrypt job.
 *   3) Validate anti-replay and MACs.
 *   4) On success, produce an inner packet mbuf to be returned via dequeue.
 *
 * Returns number of mbufs accepted for processing (0..nb_mbufs). */
uint16_t
rte_wg_decrypt_enqueue(struct rte_wg_ctx *ctx,
                       struct rte_mbuf *mbufs[], uint16_t nb_mbufs);

/* Dequeue a burst of decrypted inner packets (rte_mbufs) ready for further
 * processing (IPv4/IPv6 stack, forwarding, or application).
 * Returns number of mbufs dequeued (0..nb_mbufs). */
uint16_t
rte_wg_decrypt_dequeue(struct rte_wg_ctx *ctx,
                       struct rte_mbuf *mbufs[], uint16_t nb_mbufs);

/* Polling helper: the dataplane may need to poll the crypto backend to complete
 * outstanding operations. This function allows the application to pump completions.
 * It is safe to call periodically in main loop.
 *
 * Returns number of operations completed. */
uint32_t
rte_wg_poll(struct rte_wg_ctx *ctx);

/* Per-peer / context stats */

/* Fill the stats structure for a given context (aggregated) */
int
rte_wg_stats_get(struct rte_wg_ctx *ctx, struct rte_wg_stats *st);

/* Fill per-peer stats (if peer is NULL, return error). */
int
rte_wg_peer_stats_get(struct rte_wg_peer *peer, struct rte_wg_stats *st);

/* Reset statistics counters for context or peer */
int
rte_wg_stats_reset(struct rte_wg_ctx *ctx);
int
rte_wg_peer_stats_reset(struct rte_wg_peer *peer);

/* Utility helpers */

/* Convert human-readable IPv4 dotted quad to uint32 (network byte order) */
static inline uint32_t
rte_wg_ipv4_str_to_u32(const char *s);

/* Convert IPv6 textual to 16-byte array (caller supplies buf[16]). */
static inline int
rte_wg_ipv6_str_to_bytes(const char *s, uint8_t buf[16]);

/* Example usage (pseudo):
 *
 * struct rte_wg_config cfg = { .name = "wgdp0", .default_tx_ring_size = 1024, ... };
 * ctx = rte_wg_ctx_create(&cfg);
 * peer = rte_wg_peer_create(ctx, &peer_conf);
 * rte_wg_peer_update_keys(peer, &keys_after_noise);
 * rte_wg_allowedip_add(ctx, peer, &allowed);
 *
 * // dataplane main loop:
 * nb_rx = rte_eth_rx_burst(..., rx_pkts, MAX_BURST);
 * accept = rte_wg_decrypt_enqueue(ctx, rx_pkts, nb_rx);
 * .... rte_wg_poll(ctx); ...
 * out_nb = rte_wg_decrypt_dequeue(ctx, decoded_pkts, MAX_BURST);
 * // forward decoded_pkts...
 *
 * // outbound:
 * ret = rte_wg_encrypt_enqueue(ctx, inner_pkts, nb_in);
 * rte_wg_poll(ctx);
 * nb_enc = rte_wg_encrypt_dequeue(ctx, enc_pkts, MAX_BURST);
 * rte_eth_tx_burst(..., enc_pkts, nb_enc);
 */

/* Thread-safety and lcore model:
 *  - The library is designed for high-throughput datapath. Use lcore-sharding
 *    of peers or single-writer semantics to avoid locks:
 *      * Creation/removal of peers should be serialized by user-plane.
 *      * rte_wg_encrypt_/decrypt_enqueue/_dequeue can be called concurrently
 *        from multiple lcores, but behavior depends on implementation.
 *  - Implementations may restrict certain APIs to be called from control-plane only.
 */

#ifdef __cplusplus
}
#endif

#endif /* _RTE_WG_H_ */
