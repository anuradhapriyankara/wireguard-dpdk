/* SPDX-License-Identifier: BSD-3-Clause
 * rte_wg.c - Minimal skeleton implementation of DPDK-style WireGuard dataplane
 * with peer hash and LPM-based Allowed-IPs lookup integrated into enqueue paths.
 *
 * NOTE: This file is a minimal skeleton for development and testing only.
 *  - encrypt_enqueue expects inner IP packet (L3 first) in mbuf.
 *  - decrypt_enqueue expects mbuf data to be WireGuard UDP payload and
 *    the first 4 bytes to be receiver index (u32 network-order).
 * Replace these assumptions with full parsing when implementing production code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_byteorder.h>

#include <sodium.h>

#include "rte_wg.h"


/* For testing only — WG transport header (simplified) */
struct wg_transport_hdr {
    uint32_t type;     /* WG_PKT_DATA */
    uint32_t receiver; /* receiver index */
    uint64_t counter;  /* packet counter */
    uint8_t nonce[12]; /* AEAD nonce */
} __attribute__((packed));

struct noise_symmetric_key {
	uint8_t key[RTE_NOISE_SYMMETRIC_KEY_LEN];
	uint64_t birthdate;
	bool is_valid;
};

/* Internal definitions */

struct rte_wg_peer {
	uint8_t pubkey[RTE_WG_PUBKEY_LEN];
	struct rte_wg_stats stats;
	struct noise_symmetric_key tx_key;
	uint64_t tx_counter;
	uint32_t tx_index;  /* peer’s receiver index for outbound */
	struct noise_symmetric_key rx_key;
	uint64_t rx_counter;
	uint32_t rx_index;  /* my receiver index for inbound */
	/* TODO: keys, replay window, crypto sessions, allowed-ips metadata */
};

struct rte_wg_ctx {
	const char *name;
	uint32_t max_peers;
	uint32_t nb_peers;

	struct rte_hash *peer_hash;             /* pubkey -> peer */
	struct rte_wg_peer **peer_store;        /* indexed peers */

	struct rte_lpm  *lpm4;                  /* IPv4 AllowedIPs */
	struct rte_lpm6 *lpm6;                  /* IPv6 AllowedIPs */

	struct rte_wg_stats stats;
};

/* ---- Helpers ---- */

static int
ctx_peer_id_of(struct rte_wg_ctx *ctx, struct rte_wg_peer *peer)
{
	if (!ctx || !peer)
		return -1;
	for (uint32_t i = 0; i < ctx->nb_peers; i++) {
		if (ctx->peer_store[i] == peer)
			return (int)i;
	}
	return -1;
}

/* ---- Context lifecycle ---- */

struct rte_wg_ctx *
rte_wg_ctx_create(const struct rte_wg_config *cfg)
{
	if (sodium_init() < 0) {
    	rte_exit(EXIT_FAILURE, "libsodium init failed\n");
	}
	
	struct rte_wg_ctx *ctx;
	char namebuf[64];

	if (!cfg)
		return NULL;

	ctx = rte_zmalloc(NULL, sizeof(*ctx), 0);
	if (!ctx)
		return NULL;

	ctx->name = cfg->name ? strdup(cfg->name) : strdup("wgctx");
	ctx->max_peers = cfg->max_peers ? cfg->max_peers : RTE_WG_MAX_PEERS;
	ctx->nb_peers = 0;

	ctx->peer_store = rte_zmalloc(NULL,
	                              sizeof(struct rte_wg_peer *) * ctx->max_peers, 0);
	if (!ctx->peer_store) {
		rte_free(ctx);
		return NULL;
	}

	/* Create peer hash */
	{
		struct rte_hash_parameters hash_params = {0};
		hash_params.name = ctx->name;
		hash_params.entries = ctx->max_peers;
		hash_params.key_len = RTE_WG_PUBKEY_LEN;
		hash_params.hash_func = rte_jhash;
		hash_params.hash_func_init_val = 0;
		hash_params.socket_id = rte_socket_id();
		ctx->peer_hash = rte_hash_create(&hash_params);
		if (!ctx->peer_hash) {
			rte_free(ctx->peer_store);
			rte_free((void *)ctx->name);
			rte_free(ctx);
			return NULL;
		}
	}

	/* Create IPv4 LPM */
	snprintf(namebuf, sizeof(namebuf), "%s_lpm4", ctx->name);
	{
		struct rte_lpm_config lpm4_cfg;
		memset(&lpm4_cfg, 0, sizeof(lpm4_cfg));
		lpm4_cfg.max_rules = ctx->max_peers * 8;
		lpm4_cfg.number_tbl8s = 256;
		lpm4_cfg.flags = 0;
		ctx->lpm4 = rte_lpm_create(namebuf, rte_socket_id(), &lpm4_cfg);
		if (!ctx->lpm4) {
			rte_hash_free(ctx->peer_hash);
			rte_free(ctx->peer_store);
			rte_free((void *)ctx->name);
			rte_free(ctx);
			printf("Failed to create lpm4\n");
			return NULL;
		}

	}

	/* Create IPv6 LPM */
	snprintf(namebuf, sizeof(namebuf), "%s_lpm6", ctx->name);
	{
		struct rte_lpm6_config lpm6_cfg;
		memset(&lpm6_cfg, 0, sizeof(lpm6_cfg));
		lpm6_cfg.max_rules = ctx->max_peers * 8;
		lpm6_cfg.number_tbl8s = 256;
		lpm6_cfg.flags = 0;
		ctx->lpm6 = rte_lpm6_create(namebuf, rte_socket_id(), &lpm6_cfg);
		if (!ctx->lpm6) {
			rte_lpm_free(ctx->lpm4);
			rte_hash_free(ctx->peer_hash);
			rte_free(ctx->peer_store);
			rte_free((void *)ctx->name);
			rte_free(ctx);
			return NULL;
		}
	}

	memset(&ctx->stats, 0, sizeof(ctx->stats));
	return ctx;
}

void
rte_wg_ctx_destroy(struct rte_wg_ctx *ctx)
{
	if (!ctx)
		return;
	for (uint32_t i = 0; i < ctx->nb_peers; i++) {
		if (ctx->peer_store[i])
			rte_free(ctx->peer_store[i]);
	}

	if (ctx->peer_hash)
		rte_hash_free(ctx->peer_hash);
	if (ctx->lpm4)
		rte_lpm_free(ctx->lpm4);
	if (ctx->lpm6)
		rte_lpm6_free(ctx->lpm6);
	if (ctx->peer_store)
		rte_free(ctx->peer_store);
	if (ctx->name)
		free((void *)ctx->name);

	rte_free(ctx);
}

void
rte_wg_version(int *major, int *minor, int *patch)
{
	if (major) *major = RTE_WG_VERSION_MAJOR;
	if (minor) *minor = RTE_WG_VERSION_MINOR;
	if (patch) *patch = RTE_WG_VERSION_PATCH;
}

/* ---- Peer management ---- */

struct rte_wg_peer *
rte_wg_peer_create(struct rte_wg_ctx *ctx,
                   const struct rte_wg_peer_conf *conf)
{
	if (!ctx || !conf || ctx->nb_peers >= ctx->max_peers)
		return NULL;

	struct rte_wg_peer *peer = rte_zmalloc(NULL, sizeof(*peer), 0);
	if (!peer)
		return NULL;

	memcpy(peer->pubkey, conf->pubkey, RTE_WG_PUBKEY_LEN);

	int ret = rte_hash_add_key_data(ctx->peer_hash, peer->pubkey, peer);
	if (ret < 0) {
		rte_free(peer);
		return NULL;
	}

	ctx->peer_store[ctx->nb_peers++] = peer;
	return peer;
}

int
rte_wg_peer_remove(struct rte_wg_ctx *ctx, struct rte_wg_peer *peer)
{
	if (!ctx || !peer)
		return RTE_WG_ERR_INVALID;

	int ret = rte_hash_del_key(ctx->peer_hash, peer->pubkey);
	if (ret < 0)
		return RTE_WG_ERR_NOTFOUND;

	/* Remove from peer_store (linear search) */
	for (uint32_t i = 0; i < ctx->nb_peers; i++) {
		if (ctx->peer_store[i] == peer) {
			ctx->peer_store[i] = ctx->peer_store[--ctx->nb_peers];
			break;
		}
	}

	rte_free(peer);
	return RTE_WG_OK;
}

int
rte_wg_peer_update_keys(struct rte_wg_peer *peer,
                        const struct rte_wg_peer_keys *keys)
{
	(void)peer; (void)keys;
	/* TODO: install tx/rx keys into crypto sessions */
	return RTE_WG_OK;
}

int
rte_wg_peer_update_crypto(struct rte_wg_peer *peer,
                          rte_wg_crypto_session_t encrypt_session,
                          rte_wg_crypto_session_t decrypt_session)
{
	(void)peer; (void)encrypt_session; (void)decrypt_session;
	/* TODO: update crypto session handles */
	return RTE_WG_OK;
}

/* ---- Allowed-IP management ---- */

int
rte_wg_allowedip_add(struct rte_wg_ctx *ctx,
                     struct rte_wg_peer *peer,
                     const struct rte_wg_allowed_ip *allowed)
{
	if (!ctx || !peer || !allowed)
		return RTE_WG_ERR_INVALID;

	int peer_id = ctx_peer_id_of(ctx, peer);
	if (peer_id < 0)
		return RTE_WG_ERR_NOTFOUND;

	if (allowed->family == RTE_WG_AF_INET) {
		/* IPv4: assume allowed->addr.ip4 in network byte order */
		uint32_t ip4 = allowed->addr.ip4;
		/* rte_lpm_add expects IP in host byte order */
		uint32_t ip4_host = rte_be_to_cpu_32(ip4);
		if (rte_lpm_add(ctx->lpm4, ip4_host, allowed->prefixlen, (uint32_t)peer_id) < 0)
			return RTE_WG_ERR_RANGE;
	} else if (allowed->family == RTE_WG_AF_INET6) {
		/* IPv6: store as 16-byte array */
		if (rte_lpm6_add(ctx->lpm6, allowed->addr.ip6, allowed->prefixlen, (uint32_t)peer_id) < 0)
			return RTE_WG_ERR_RANGE;
	} else {
		return RTE_WG_ERR_INVALID;
	}
	return RTE_WG_OK;
}

int
rte_wg_allowedip_remove(struct rte_wg_ctx *ctx,
                        struct rte_wg_peer *peer,
                        const struct rte_wg_allowed_ip *allowed)
{
	if (!ctx || !peer || !allowed)
		return RTE_WG_ERR_INVALID;

	int peer_id = ctx_peer_id_of(ctx, peer);
	if (peer_id < 0)
		return RTE_WG_ERR_NOTFOUND;

	if (allowed->family == RTE_WG_AF_INET) {
		uint32_t ip4 = allowed->addr.ip4;
		uint32_t ip4_host = rte_be_to_cpu_32(ip4);
		if (rte_lpm_delete(ctx->lpm4, ip4_host, allowed->prefixlen) < 0)
			return RTE_WG_ERR_NOTFOUND;
	} else if (allowed->family == RTE_WG_AF_INET6) {
		if (rte_lpm6_delete(ctx->lpm6, allowed->addr.ip6, allowed->prefixlen) < 0)
			return RTE_WG_ERR_NOTFOUND;
	} else {
		return RTE_WG_ERR_INVALID;
	}
	return RTE_WG_OK;
}

struct rte_wg_peer *
rte_wg_allowedip_lookup(struct rte_wg_ctx *ctx,
                        const void *addr, int family)
{
	if (!ctx || !addr)
		return NULL;

	int peer_id = -1;
	if (family == RTE_WG_AF_INET) {
		/* addr points to network-order uint32_t */
		uint32_t ip4_n = *(const uint32_t *)addr;
		uint32_t ip4_host = rte_be_to_cpu_32(ip4_n);
		if (rte_lpm_lookup(ctx->lpm4, ip4_host, &peer_id) < 0)
			return NULL;
	} else if (family == RTE_WG_AF_INET6) {
		if (rte_lpm6_lookup(ctx->lpm6, addr, &peer_id) < 0)
			return NULL;
	} else {
		return NULL;
	}

	if (peer_id < 0 || (uint32_t)peer_id >= ctx->nb_peers)
		return NULL;

	return ctx->peer_store[peer_id];
}

int
rte_wg_allowedip_clear(struct rte_wg_ctx *ctx, struct rte_wg_peer *peer)
{
	(void)ctx; (void)peer;
	/* TODO: iterate rules and delete all matching entries for peer */
	return RTE_WG_OK;
}

/* ---- Enqueue / Dequeue with peer mapping integration ---- */

/* Helper: Extract IP version from L3 packet first byte.
 * Returns 4 or 6, or 0 on error */
static inline int
ip_version_from_mbuf(struct rte_mbuf *m, uint8_t **hdr_out)
{
	uint8_t *ptr = rte_pktmbuf_mtod(m, uint8_t *);
	if (!ptr || rte_pktmbuf_pkt_len(m) < 1)
		return 0;
	*hdr_out = ptr;
	return (ptr[0] >> 4) & 0x0F;
}

/* Compact accepted mbufs to front */
static inline uint16_t
compact_accepted(struct rte_mbuf **mbufs, uint16_t nb, uint16_t accepted_mask[])
{
	uint16_t j = 0;
	for (uint16_t i = 0; i < nb; i++) {
		if (accepted_mask[i]) {
			mbufs[j++] = mbufs[i];
		} else {
			/* the caller decides whether to free the packet or not; here we free it */
			rte_pktmbuf_free(mbufs[i]);
		}
	}
	return j;
}

/* ENCRYPT enqueue: classify inner IP -> peer via LPM.
 * Accept and attach peer to mbuf (mbuf->dynfield1 stores peer pointer).
 * Returns number of mbufs accepted (compacted to front). */
uint16_t
rte_wg_encrypt_enqueue(struct rte_wg_ctx *ctx,
                       struct rte_mbuf *mbufs[], uint16_t nb_mbufs)
{
	if (!ctx || nb_mbufs == 0)
		return 0;

	uint16_t accepted_mask[nb_mbufs];
	memset(accepted_mask, 0, sizeof(accepted_mask));
	uint16_t accepted = 0;

	for (uint16_t i = 0; i < nb_mbufs; i++) {
		struct rte_mbuf *m = mbufs[i];
		uint8_t *hdr;
		struct rte_wg_peer *peer = NULL;
		int ver = ip_version_from_mbuf(m, &hdr);
		if (ver == 4) {
			/* IPv4 header: dst IP at bytes 16..19 (network order) */
			if (rte_pktmbuf_pkt_len(m) < 20) {
				ctx->stats.pkt_dropped_bad_format++;
				continue;
			}
			uint32_t dst_n;
			memcpy(&dst_n, hdr + 16, sizeof(dst_n));
			peer = rte_wg_allowedip_lookup(ctx, &dst_n, RTE_WG_AF_INET);
			if (!peer) {
				ctx->stats.pkt_dropped_no_peer++;
				continue;
			}
			/* attach peer to mbuf via dynfield1 */
			//m->dynfield2 = (uintptr_t)peer;
		} else if (ver == 6) {
			/* IPv6 header: dst IP at bytes 24..39 (network order) */
			if (rte_pktmbuf_pkt_len(m) < 40) {
				ctx->stats.pkt_dropped_bad_format++;
				continue;
			}
			uint8_t dst6[16];
			memcpy(dst6, hdr + 24, 16);
			peer = rte_wg_allowedip_lookup(ctx, dst6, RTE_WG_AF_INET6);
			if (!peer) {
				ctx->stats.pkt_dropped_no_peer++;
				continue;
			}
			//m->dynfield2 = (uintptr_t)peer;

		} else {
			ctx->stats.pkt_dropped_bad_format++;
			continue;
		}

		if(peer){
			/* For testing only: forge WG transport header and AEAD encrypt */
			/* Allocate space for WG header + ciphertext */
			size_t inner_len = rte_pktmbuf_pkt_len(m);
			size_t hdr_len = sizeof(struct wg_transport_hdr);
			size_t max_len = hdr_len + inner_len + crypto_aead_chacha20poly1305_ietf_ABYTES;

			if (rte_pktmbuf_prepend(m, hdr_len) == NULL) {
				rte_pktmbuf_free(m);
				ctx->stats.pkt_dropped_bad_format++;
				continue;
			}

			uint8_t *pkt = rte_pktmbuf_mtod(m, uint8_t *);
			struct wg_transport_hdr *hdr = (struct wg_transport_hdr *)pkt;

			/* Fill WG transport header */
			hdr->type = rte_cpu_to_le_32(4); /* WG_PKT_DATA */
			hdr->receiver = rte_cpu_to_le_32(1); /* demo receiver index */
			hdr->counter = rte_cpu_to_le_64(peer->tx_counter++);
			memset(hdr->nonce, 0, sizeof(hdr->nonce));
			memcpy(hdr->nonce, &hdr->counter, sizeof(uint64_t)); /* nonce from counter */

			/* AEAD encrypt in place */
			unsigned long long clen;
			uint8_t *ciphertext = pkt + hdr_len;
			const uint8_t *plaintext = pkt + hdr_len; /* inner packet originally */
			size_t plaintext_len = inner_len;

			if (crypto_aead_chacha20poly1305_ietf_encrypt(
					ciphertext, &clen,
					plaintext, plaintext_len,
					pkt, hdr_len,     /* AAD = WG header */
					NULL, hdr->nonce, peer->tx_key.key) != 0) {
				/* encryption failed */
				rte_pktmbuf_free(m);
				continue;
			}

			/* Adjust mbuf data length */
			rte_pktmbuf_pkt_len(m) = hdr_len + clen;
			rte_pktmbuf_data_len(m) = hdr_len + clen;

			peer->stats.pkt_queued++;
			ctx->stats.pkt_queued++;
			accepted_mask[i] = 1;
			accepted++;
		}



	}

	/* compact accepted mbufs to front and return nb accepted */
	uint16_t nb_accepted = compact_accepted(mbufs, nb_mbufs, accepted_mask);
	return nb_accepted;
}

/* ENCRYPT dequeue: placeholder (crypto not implemented).
 * For now, do nothing; in real implementation, would dequeue encrypted pkts. */
uint16_t
rte_wg_encrypt_dequeue(struct rte_wg_ctx *ctx,
                       struct rte_mbuf *mbufs[], uint16_t nb_mbufs)
{
	(void)ctx; (void)mbufs; (void)nb_mbufs;
	/* TODO: return encrypted/encapsulated mbufs ready for transmission */
	return 0;
}

/* DECRYPT enqueue: expects mbuf data pointing to WireGuard payload (UDP payload).
 * This skeleton expects first 4 bytes to be receiver index (u32, network order).
 * It maps the receiver index to ctx->peer_store[index] and attaches peer to mbuf.
 *
 * Returns nb accepted (compacts to front), frees rejected mbufs.
 */
uint16_t
rte_wg_decrypt_enqueue(struct rte_wg_ctx *ctx,
                       struct rte_mbuf *mbufs[], uint16_t nb_mbufs)
{
	if (!ctx || nb_mbufs == 0)
		return 0;

	uint16_t accepted_mask[nb_mbufs];
	memset(accepted_mask, 0, sizeof(accepted_mask));
	uint16_t accepted = 0;

	for (uint16_t i = 0; i < nb_mbufs; i++) {
		struct rte_mbuf *m = mbufs[i];
		uint8_t *pkt = rte_pktmbuf_mtod(m, uint8_t *);
        size_t pktlen = rte_pktmbuf_pkt_len(m);
		
		if (pktlen < sizeof(struct wg_transport_hdr) +
                      crypto_aead_chacha20poly1305_ietf_ABYTES) {
			ctx->stats.pkt_dropped_bad_format++;
			continue;
		}

        struct wg_transport_hdr *hdr = (struct wg_transport_hdr *)pkt;
        size_t hdr_len = sizeof(*hdr);

		uint32_t idx_n;
		memcpy(&idx_n, rte_pktmbuf_mtod(m, void *), sizeof(idx_n));
		uint32_t idx = rte_be_to_cpu_32(idx_n);
		if (idx >= ctx->nb_peers) {
			ctx->stats.pkt_dropped_no_peer++;
			continue;
		}

		struct rte_wg_peer *peer = ctx->peer_store[idx];
		if (!peer) {
			ctx->stats.pkt_dropped_no_peer++;
			continue;
		}

        /* Ciphertext region */
        uint8_t *ciphertext = pkt + hdr_len;
        size_t clen = pktlen - hdr_len;
        size_t mlen = clen - crypto_aead_chacha20poly1305_ietf_ABYTES;

        /* Decrypt into same mbuf region (in place) */
        unsigned long long outlen = 0;
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
                ciphertext, &outlen,
                NULL,
                ciphertext, clen,
                pkt, hdr_len,          /* AAD = WG header */
                hdr->nonce, peer->rx_key.key) != 0) {
            /* authentication failed */
            rte_pktmbuf_free(m);
            continue;
        }

        /* Move decrypted inner packet to start of mbuf (strip WG header) */
        memmove(pkt, ciphertext, outlen);

        rte_pktmbuf_pkt_len(m) = outlen;
        rte_pktmbuf_data_len(m) = outlen;

		/* attach peer pointer via dynfield1 */
		//m->dynfield2 = (uintptr_t)peer;
		peer->stats.pkt_queued++;
		ctx->stats.pkt_queued++;
		accepted_mask[i] = 1;
		accepted++;
	}

	uint16_t nb_accepted = compact_accepted(mbufs, nb_mbufs, accepted_mask);
	return nb_accepted;
}

/* DECRYPT dequeue: placeholder, real decrypt/completion poll should populate inner packets */
uint16_t
rte_wg_decrypt_dequeue(struct rte_wg_ctx *ctx,
                       struct rte_mbuf *mbufs[], uint16_t nb_mbufs)
{
	(void)ctx; (void)mbufs; (void)nb_mbufs;
	/* TODO: return decrypted inner packets */
	return 0;
}

/* Polling: stub */
uint32_t
rte_wg_poll(struct rte_wg_ctx *ctx)
{
	(void)ctx;
	/* TODO: poll crypto backend for completions and finish work */
	return 0;
}

/* ---- Stats ---- */

int
rte_wg_stats_get(struct rte_wg_ctx *ctx, struct rte_wg_stats *st)
{
	if (!ctx || !st)
		return RTE_WG_ERR_INVALID;
	*st = ctx->stats;
	return RTE_WG_OK;
}

int
rte_wg_peer_stats_get(struct rte_wg_peer *peer, struct rte_wg_stats *st)
{
	if (!peer || !st)
		return RTE_WG_ERR_INVALID;
	*st = peer->stats;
	return RTE_WG_OK;
}

int
rte_wg_stats_reset(struct rte_wg_ctx *ctx)
{
	if (!ctx)
		return RTE_WG_ERR_INVALID;
	memset(&ctx->stats, 0, sizeof(ctx->stats));
	return RTE_WG_OK;
}

int
rte_wg_peer_stats_reset(struct rte_wg_peer *peer)
{
	if (!peer)
		return RTE_WG_ERR_INVALID;
	memset(&peer->stats, 0, sizeof(peer->stats));
	return RTE_WG_OK;
}

/* ---- Utility stubs ---- */

static inline uint32_t
rte_wg_ipv4_str_to_u32(const char *s)
{
	(void)s;
	/* TODO: implement IPv4 parser */
	return 0;
}

static inline int
rte_wg_ipv6_str_to_bytes(const char *s, uint8_t buf[16])
{
	(void)s; (void)buf;
	/* TODO: implement IPv6 parser */
	return -1;
}
