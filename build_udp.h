#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>

/**
 * Build a UDP response packet.
 *
 * @param rx_buf       Incoming packet (raw bytes)
 * @param rx_len       Length of incoming packet
 * @param udp_payload  UDP payload for the response
 * @param udp_len      Length of UDP payload
 * @param tx_len       Output: length of created response packet
 * @return             Newly allocated response packet buffer (must be freed with rte_free)
 */
int build_udp_response(const uint8_t *rx_buf, size_t rx_len,
                       const uint8_t *udp_payload, size_t udp_len,
                       uint8_t *tx_pkt, size_t *tx_len)
{
    // Pointers to input headers
    const struct rte_ether_hdr *rx_eth;
    const struct rte_ipv4_hdr *rx_ip;
    const struct rte_udp_hdr  *rx_udp;

    // Parse RX packet
    rx_eth = (const struct rte_ether_hdr *)rx_buf;
    rx_ip  = (const struct rte_ipv4_hdr *)(rx_eth + 1);
    rx_udp = (const struct rte_udp_hdr *)(rx_ip + 1);

    // Allocate buffer for TX packet
    *tx_len = sizeof(struct rte_ether_hdr) +
              sizeof(struct rte_ipv4_hdr) +
              sizeof(struct rte_udp_hdr) +
              udp_len;

    uint8_t *tx_buf = tx_pkt;//rte_malloc(NULL, *tx_len, 0);
    // if (!tx_buf)
    //     return -1;

    struct rte_ether_hdr *tx_eth = (struct rte_ether_hdr *)tx_buf;
    struct rte_ipv4_hdr  *tx_ip  = (struct rte_ipv4_hdr *)(tx_eth + 1);
    struct rte_udp_hdr   *tx_udp = (struct rte_udp_hdr *)(tx_ip + 1);
    uint8_t *tx_payload = (uint8_t *)(tx_udp + 1);

    // Ethernet header
    rte_ether_addr_copy(&rx_eth->src_addr, &tx_eth->dst_addr);
    rte_ether_addr_copy(&rx_eth->dst_addr, &tx_eth->src_addr);
    tx_eth->ether_type = rx_eth->ether_type;

    print_hex("Response Ethernet Header", (uint8_t *)tx_buf, sizeof(struct rte_ether_hdr));

    // IPv4 header
    *tx_ip = *rx_ip; // copy everything, then adjust
    tx_ip->src_addr = rx_ip->dst_addr;
    tx_ip->dst_addr = rx_ip->src_addr;//rte_cpu_to_be_32(RTE_IPV4(10,0,0,2));//
    tx_ip->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
                                           sizeof(struct rte_udp_hdr) +
                                           udp_len);
    tx_ip->hdr_checksum = 0;
    tx_ip->hdr_checksum = rte_ipv4_cksum(tx_ip);

    // UDP header
    tx_udp->src_port = rx_udp->dst_port;
    tx_udp->dst_port = rx_udp->src_port;
    tx_udp->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + udp_len);
    tx_udp->dgram_cksum = 0;

    // Copy payload
    rte_memcpy(tx_payload, udp_payload, udp_len);

    // Compute UDP checksum (includes pseudo-header)
    tx_udp->dgram_cksum = rte_ipv4_udptcp_cksum(tx_ip, tx_udp);

    // tx_pkt = tx_buf;
    // printf("Built UDP response packet of length %zu bytes\n", *tx_len);
    // print_hex("Response UDP Header", (uint8_t *)tx_pkt, *tx_len);

    return 0;
}
