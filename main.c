#ifndef LIBNET_LIL_ENDIAN
#define LIBNET_LIL_ENDIAN 1		// Little Endian
#endif

#include <pcap.h>			// pcap*()
#include <stdint.h>			// uintN_t
#include <arpa/inet.h>			// ntoh?()
#include <stdio.h>			// printf()
#include <string.h>			// strcpy()
#include <netinet/in_systm.h>		// ETH/IP/TCP header
#include <libnet/libnet-macros.h>	// ETH/IP/TCP header
#include <libnet/libnet-headers.h>	// ETH/IP/TCP header

#define PAYLOAD_MAX	16
#define ETH_ADDRSTRLEN	18

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test eth0\n");
}

char* ether_ntop(uint8_t *src, uint8_t *dst, int size) {
	static const char fmt[] = "%02X:%02X:%02X:%02X:%02X:%02X";
	char tmp[sizeof "FF:FF:FF:FF:FF:FF"];
	if(sprintf(tmp, fmt, src[0],src[1],src[2],src[3],src[4],src[5])>size)
		return (NULL);
	strcpy(dst, tmp);
	return (dst);
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	while(1) {
		puts("");
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		printf("\n[ Packet ]\n%u Bytes captured", header->caplen);

		struct libnet_ethernet_hdr *eth = (struct libnet_ethernet_hdr*)packet;
		uint8_t eth_buf[ETH_ADDRSTRLEN];
		printf("\nSource MAC\t: %s",ether_ntop(eth->ether_shost, eth_buf, ETH_ADDRSTRLEN));
		printf("\nDestination MAC\t: %s",ether_ntop(eth->ether_dhost, eth_buf, ETH_ADDRSTRLEN));
		if(ntohs(eth->ether_type) != ETHERTYPE_IP) continue;

		struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
		uint8_t ip_buf[INET_ADDRSTRLEN];
		printf("\nSource IP\t: %s",inet_ntop(AF_INET, &ip->ip_src, ip_buf, INET_ADDRSTRLEN));
		printf("\nDestination IP\t: %s",inet_ntop(AF_INET, &ip->ip_dst, ip_buf, INET_ADDRSTRLEN));
		if(ip->ip_p != IPPROTO_TCP) continue;

		int ip_len = (ip->ip_hl) << 2;
		struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr*)((uint8_t*)ip + ip_len);
		printf("\nSource Port\t: %u",ntohs(tcp->th_sport));
		printf("\nDestination Port: %u",ntohs(tcp->th_dport));
		int tcp_len = (tcp->th_off) << 2;

		int pay_len = ntohs(ip->ip_len) - ip_len - tcp_len;
		if(pay_len <= 0) continue;
		else if(pay_len > PAYLOAD_MAX) pay_len=PAYLOAD_MAX;

		uint8_t *payload = (uint8_t*)tcp + tcp_len;
		puts("\n[ Payload ]");
		for(int i=0; i<pay_len; i++) printf("%02X ", payload[i]);
	}
	pcap_close(handle);
	return 0;
}

