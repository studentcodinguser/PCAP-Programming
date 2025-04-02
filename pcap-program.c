#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#define SNAP_LEN 1518

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct ether_header *eth_header;
    const struct ip *ip_header;
    const struct tcphdr *tcp_header;
    const char *payload;

    int ethernet_size = sizeof(struct ether_header);
    eth_header = (struct ether_header*) packet;

    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
        return;

    ip_header = (struct ip*)(packet + ethernet_size);
    int ip_header_len = ip_header->ip_hl * 4;
    if (ip_header->ip_p != IPPROTO_TCP)
        return;

    tcp_header = (struct tcphdr*)(packet + ethernet_size + ip_header_len);
    int tcp_header_len = tcp_header->th_off * 4;
    int total_headers_size = ethernet_size + ip_header_len + tcp_header_len;
    int payload_size = header->caplen - total_headers_size;
    payload = (char *)(packet + total_headers_size);

    printf("\n--- TCP Packet ---\n");
    printf("Ethernet: Src MAC: %02x:%02x:%02x:%02x:%02x:%02x, Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
           eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5],
           eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
           eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    printf("IP: Src IP: %s, Dst IP: %s\n", inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));
    printf("TCP: Src Port: %d, Dst Port: %d\n", ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));

    if (payload_size > 0) {
        printf("Message (first 32 bytes or less): ");
        for (int i = 0; i < payload_size && i < 32; i++) {
            if (isprint(payload[i])) putchar(payload[i]);
            else putchar('.');
        }
        printf("\n");
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 2;
    }

    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    pcap_loop(handle, 0, got_packet, NULL);
    pcap_close(handle);
    return 0;
}
