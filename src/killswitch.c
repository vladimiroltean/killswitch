// SPDX-License-Identifier: GPL-2.0
/* Copyright 2022 NXP */
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/types.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>

static void usage(const char *prog_name)
{
	fprintf(stderr, "Usage: %s <ifname>\n", prog_name);
}

static int ifname_copy(char *dst, const char *src)
{
	if (strlen(src) >= IFNAMSIZ) {
		fprintf(stderr,
			"Interface name \"%s\" too large, please limit to %d bytes\n",
			src, IFNAMSIZ);
		return -ERANGE;
	}

	strcpy(dst, src);

	return 0;
}

/**
 * ether_addr_copy - Copy an Ethernet address
 * @dst: Pointer to a six-byte array Ethernet address destination
 * @src: Pointer to a six-byte array Ethernet address source
 *
 * Please note: dst & src must both be aligned to u16.
 */
static inline void ether_addr_copy(unsigned char *dst, const unsigned char *src)
{
	*(__u32 *)dst = *(const __u32 *)src;
	*(__u16 *)(dst + 4) = *(const __u16 *)(src + 4);
}

/**
 * ether_addr_to_u64 - Convert an Ethernet address into a u64 value.
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return a u64 value of the address
 */
static __u64 ether_addr_to_u64(const unsigned char addr[ETH_ALEN])
{
	__u64 u = 0;
	int i;

	for (i = 0; i < ETH_ALEN; i++)
		u = u << 8 | addr[i];

	return u;
}

/**
 * u64_to_ether_addr - Convert a u64 to an Ethernet address.
 * @u: u64 to convert to an Ethernet MAC address
 * @addr: Pointer to a six-byte array to contain the Ethernet address
 */
static void u64_to_ether_addr(__u64 u, unsigned char addr[ETH_ALEN])
{
	int i;

	for (i = ETH_ALEN - 1; i >= 0; i--) {
		addr[i] = u & 0xff;
		u = u >> 8;
	}
}

/**
 * is_multicast_ether_addr - Determine if the Ethernet address is a multicast.
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is a multicast address.
 * By definition the broadcast address is also a multicast address.
 */
static inline bool is_multicast_ether_addr(const unsigned char addr[ETH_ALEN])
{
	unsigned char a = addr[0];

	return a & 0x01;
}

static void mac_addr_next(unsigned char addr[ETH_ALEN])
{
	__u64 u = ether_addr_to_u64(addr);

	u++;
	u64_to_ether_addr(u, addr);
	if (is_multicast_ether_addr(addr))
		addr[0]++;
}

/* Inspired by arp_create() in the Linux kernel */
static size_t arp_prepare(unsigned char *buf, size_t len)
{
	struct ethhdr *eth = (struct ethhdr *)buf;
	struct arphdr *arp = (struct arphdr *)(eth + 1);
	unsigned char src_ip[] = {192, 168, 0, 1};
	unsigned char dst_ip[] = {192, 168, 0, 2};
	unsigned char *arp_ptr;

	memset(buf, 0, len);

	eth->h_proto = htons(ETH_P_ARP);
	arp->ar_hrd = htons(ARPHRD_ETHER);
	arp->ar_pro = htons(ETH_P_IP);
	arp->ar_hln = ETH_ALEN;
	arp->ar_pln = 4;
	arp->ar_op = htons(ARPOP_REQUEST);

	arp_ptr = (unsigned char *)(arp + 1);

	/* Leave src_hw unpopulated for now */
	arp_ptr += ETH_ALEN;
	memcpy(arp_ptr, &src_ip, 4);
	arp_ptr += 4;

	/* Target MAC address is 00:00:00:00:00:00 */
	arp_ptr += ETH_ALEN;
	memcpy(arp_ptr, &dst_ip, 4);
	arp_ptr += 4;

	return arp_ptr - buf;
}

static ssize_t arp_send(int fd, unsigned char *buf, size_t len,
			struct sockaddr_ll *l2,
			unsigned char mac_da[ETH_ALEN],
			unsigned char mac_sa[ETH_ALEN])
{
	struct ethhdr *eth = (struct ethhdr *)buf;
	struct arphdr *arp = (struct arphdr *)(eth + 1);
	unsigned char *arp_ptr;
	ssize_t err;

	ether_addr_copy(eth->h_dest, mac_da);
	ether_addr_copy(eth->h_source, mac_sa);

	arp_ptr = (unsigned char *)(arp + 1);
	ether_addr_copy(arp_ptr, mac_sa);

	ether_addr_copy(l2->sll_addr, mac_da);

	err = sendto(fd, buf, len, 0, (struct sockaddr *)l2, sizeof(*l2));
	if (err < 0)
		return -errno;

	return 0;
}

static int sk_addr_create_l2(struct sockaddr_ll *l2, __u16 ethertype,
			     const char if_name[IFNAMSIZ])
{
	int ifindex = if_nametoindex(if_name);

	if (!ifindex) {
		fprintf(stderr, "Could not determine ifindex of %s\n", if_name);
		return -errno;
	}

	l2->sll_protocol = htons(ethertype);
	l2->sll_ifindex = ifindex;
	l2->sll_halen = ETH_ALEN;
	l2->sll_family = AF_PACKET;
	/* Leave sll_addr unpopulated for now */

	return 0;
}

static int sk_open_l2(__u16 ethertype, const char if_name[IFNAMSIZ])
{
	int fd, err;

	fd = socket(PF_PACKET, SOCK_RAW, htons(ethertype));
	if (fd < 0) {
		perror("Failed to create PF_PACKET socket");
		goto err_socket;
	}

	/* Bind to device */
	err = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, if_name, IFNAMSIZ - 1);
	if (err < 0) {
		fprintf(stderr, "Failed to bind L2 socket to device %s: %m",
			if_name);
		goto err_setsockopt;
	}

	return fd;

err_setsockopt:
	close(fd);
err_socket:
	return -errno;
}

int main(int argc, char *argv[])
{
	unsigned char mac_da[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	unsigned char mac_sa[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
	char if_name[IFNAMSIZ];
	struct sockaddr_ll l2;
	unsigned char buf[60];
	size_t len;
	int fd;

	if (argc != 2) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (ifname_copy(if_name, argv[1]))
		exit(EXIT_FAILURE);

	if (sk_addr_create_l2(&l2, ETH_P_ARP, if_name))
		exit(EXIT_FAILURE);

	fd = sk_open_l2(ETH_P_ARP, if_name);
	if (fd < 0)
		exit(EXIT_FAILURE);

	len = arp_prepare(buf, 60);

	while (1) {
		if (arp_send(fd, buf, len, &l2, mac_da, mac_sa)) {
			close(fd);
			exit(EXIT_FAILURE);
		}

		mac_addr_next(mac_sa);
	}

	close(fd);

	return 0;
}
