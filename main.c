/* SPDX-License-Identifier: BSD-3-Clause
 * main.c - Simple test harness for rte_wg skeleton
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include "rte_wg.h"


#define NB_MBUF 1024

char *server_pubkey = "5KhJ21Og8zKXcj350DFOJQ/FZgR/HqIJFVRPFODkbAg=";
char *server_privkey = "YIZaR9jZP/0HRTc0ROidcWnega5+i3doUyVXpYqSvnw=";

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    printf("Packet captured: %d bytes\n", h->len);
}

main(int argc, char **argv)
{
    int ret;

    /* Initialize EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_panic("Cannot init EAL\n");
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

    /* Cleanup */
    rte_wg_ctx_destroy(ctx);
    rte_mempool_free(mp);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("dummy0", BUFSIZ, 1, 1000, errbuf);
    
    if (handle == NULL) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return 1;
    }
    
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);

    return 0;
}
