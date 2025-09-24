/* SPDX-License-Identifier: BSD-3-Clause
 * main.c - Simple test harness for rte_wg skeleton
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <sodium.h> 

#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include "rte_wg.h"
#include "noise.h"


#define NB_MBUF 1024

const char* server_pubkey = "5KhJ21Og8zKXcj350DFOJQ/FZgR/HqIJFVRPFODkbAg=";
const char* server_privkey = "YIZaR9jZP/0HRTc0ROidcWnega5+i3doUyVXpYqSvnw=";

uint8_t server_privkey_bin[32];
uint8_t server_pubkey_bin[32];

int decode_base64_key(const char *base64_input, uint8_t *output, size_t output_size) {
    // Try all possible variant values
    if (sodium_base642bin(output, output_size, base64_input, strlen(base64_input),
                            NULL, NULL, NULL, sodium_base64_VARIANT_ORIGINAL) == 0) {
        return 0;
    }
    return -1;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    uint8_t out_pkt[512];
    
    printf("Packet captured: %d bytes\n", h->len);

    struct rte_wg_handshake wg_handshake;

    int ret = rte_wg_noise_handshake_consume_initiation(
        bytes+42, h->len-42,  // Skip Ethernet+IP+UDP headers
        server_privkey_bin, server_pubkey_bin,
        NULL, 0,
        &wg_handshake);

    if(ret != 0) {
        printf("Handshake processing failed\n");
        return;
    }

    printf("Handshake processed. Derived keys:\n");
    printf("Sender Index: %u\n", wg_handshake.sender_index);
    printf("Initiator Ephemeral: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", wg_handshake.initiator_ephemeral[i]);
    }
    printf("\n");
    printf("Initiator Static: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", wg_handshake.initiator_static[i]);
    }
    printf("\n");
    printf("CK: ");
    for (int i = 0; i < RTE_WG_HASH_LEN; i++) {
        printf("%02x", wg_handshake.ck[i]);
    }
    printf("\n");
    printf("H: ");
    for (int i = 0; i < RTE_WG_HASH_LEN; i++) {
        printf("%02x", wg_handshake.h[i]);
    }
    printf("\n");
    printf("K_ENC: ");
    for (int i = 0; i < RTE_WG_KEY_LEN; i++) {
        printf("%02x", wg_handshake.k_enc[i]);
    }
    printf("\n");
    printf("K_DEC: ");
    for (int i = 0; i < RTE_WG_KEY_LEN; i++) {
        printf("%02x", wg_handshake.k_dec[i]);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    int ret;

    /* Initialize EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_panic("Cannot init EAL\n");
    }

    rte_wg_noise_init();

    printf("Decoding base64 keys...\n");

    if (decode_base64_key(server_pubkey, server_pubkey_bin, 32) == 0) {
        printf("Server public key decoded successfully! Key: ");
        for(int i=0; i<32; i++) {
            printf("%02x", server_pubkey_bin[i]);
        }
        printf("\n");
    } else {
        printf("Failed to decode key with any variant\n");
    }

    if (decode_base64_key(server_privkey, server_privkey_bin, 32) == 0) {
        printf("Server private key decoded successfully! Key: ");
        for(int i=0; i<32; i++) {
            printf("%02x", server_privkey_bin[i]);
        }
        printf("\n");
    } else {
        printf("Failed to decode key with any variant\n");
    }

    /* Create mempool */
    struct rte_mempool *mp = rte_pktmbuf_pool_create("MBUF_POOL",
                        NB_MBUF, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                        0);
    if (!mp) {
        rte_panic("Cannot create mbuf pool\n");
    }

    /* Create WireGuard context */
    struct rte_wg_config cfg = {
        .name = "wg0",
        .max_peers = 16,
    };
    struct rte_wg_ctx *ctx = rte_wg_ctx_create(&cfg);
    if (!ctx) {
        rte_panic("wg_ctx_create failed\n");
    }

    /* Add peer with pubkey = all zeros */
    uint8_t pk[RTE_WG_PUBKEY_LEN] = {0};
    struct rte_wg_peer_conf pconf = {
        .pubkey = pk,
    };
    struct rte_wg_peer *peer = rte_wg_peer_create(ctx, &pconf);
    if (!peer) {
        rte_panic("peer_create failed\n");
    }

    /* Add allowed IPv4 subnet 10.0.0.0/24 */
    struct rte_wg_allowed_ip aip;
    aip.family = RTE_WG_AF_INET;
    aip.addr.ip4 = htonl(0x0a000000); /* 10.0.0.0 */
    aip.prefixlen = 24;
    if (rte_wg_allowedip_add(ctx, peer, &aip) != RTE_WG_OK) {
        rte_panic("allowedip_add failed\n");
    }

    /* Allocate a packet and forge IPv4 header with dst=10.0.0.42 */
    struct rte_mbuf *m = rte_pktmbuf_alloc(mp);
    if (!m) {
        rte_panic("mbuf alloc failed\n");
    }

    uint8_t *data = rte_pktmbuf_append(m, 20); /* minimal IPv4 header */
    memset(data, 0, 20);
    data[0] = 0x45; /* Version=4, IHL=5 */
    uint32_t dst = htonl(0x0a00002a); /* 10.0.0.42 */
    memcpy(data + 16, &dst, 4);

    /* Test encrypt enqueue */
    struct rte_mbuf *arr[1] = {m};
    uint16_t nb_ok = rte_wg_encrypt_enqueue(ctx, arr, 1);
    printf("encrypt_enqueue accepted=%u\n", nb_ok);

    // if (nb_ok > 0) {
    //     struct rte_wg_peer *attached =
    //         (struct rte_wg_peer *)(uintptr_t)arr[0]->dynfield2;
    //     printf("Packet attached to peer=%p (ctx peer=%p)\n", attached, peer);
    // }



    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("dummy0", BUFSIZ, 1, 1000, errbuf);
    
    if (handle == NULL) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return 1;
    }
    
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);

    /* Cleanup */
    rte_wg_ctx_destroy(ctx);
    rte_mempool_free(mp);

    return 0;
}
