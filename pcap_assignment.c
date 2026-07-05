#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define ETH_LEN 14

struct ethheader {
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
};

struct ipheader {
    unsigned char iph_ihl:4, iph_ver:4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
};

struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int tcp_seq;
    u_int tcp_ack;
    u_char tcp_offx2;
    u_char tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)

void print_mac(u_char *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_data(const u_char *data, int size)
{
    int i;

    if (size <= 0) {
        printf("No HTTP Message\n");
        return;
    }

    for (i = 0; i < size; i++) {
        if (isprint(data[i]) || data[i] == '\n' || data[i] == '\r' || data[i] == '\t')
            printf("%c", data[i]);
        else
            printf(".");
    }
    printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth;
    struct ipheader *ip;
    struct tcpheader *tcp;

    int ip_header_len;
    int tcp_header_len;
    int ip_total_len;
    int data_len;
    int real_len;

    const u_char *data;

    eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) != 0x0800)
        return;

    ip = (struct ipheader *)(packet + ETH_LEN);

    if (ip->iph_protocol != IPPROTO_TCP)
        return;

    ip_header_len = ip->iph_ihl * 4;

    tcp = (struct tcpheader *)(packet + ETH_LEN + ip_header_len);
    tcp_header_len = TH_OFF(tcp) * 4;

    ip_total_len = ntohs(ip->iph_len);

    data = packet + ETH_LEN + ip_header_len + tcp_header_len;
    data_len = ip_total_len - ip_header_len - tcp_header_len;

    real_len = header->caplen - ETH_LEN - ip_header_len - tcp_header_len;
    if (data_len > real_len)
        data_len = real_len;

    printf("\n================ Packet ================\n");

    printf("[Ethernet Header]\n");
    printf("src mac : ");
    print_mac(eth->ether_shost);
    printf("\n");

    printf("dst mac : ");
    print_mac(eth->ether_dhost);
    printf("\n");

    printf("\n[IP Header]\n");
    printf("src ip  : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("dst ip  : %s\n", inet_ntoa(ip->iph_destip));
    printf("ip header length : %d\n", ip_header_len);

    printf("\n[TCP Header]\n");
    printf("src port : %d\n", ntohs(tcp->tcp_sport));
    printf("dst port : %d\n", ntohs(tcp->tcp_dport));
    printf("tcp header length : %d\n", tcp_header_len);

    printf("\n[HTTP Message]\n");
    print_data(data, data_len);

    printf("========================================\n");
}

int main(int argc, char *argv[])
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;

    struct bpf_program fp;
    char filter_exp[] = "tcp";

    if (argc == 2) {
        dev = argv[1];
    } else {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            printf("device error: %s\n", errbuf);
            return 1;
        }
    }

    printf("Device: %s\n", dev);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("pcap_open_live error: %s\n", errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("pcap_compile error\n");
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        printf("pcap_setfilter error\n");
        pcap_close(handle);
        return 1;
    }

    printf("Start sniffing TCP packets...\n");
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
