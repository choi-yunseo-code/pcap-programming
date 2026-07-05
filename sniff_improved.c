#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

#include "myheader.h"

void print_mac(const u_char *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}

void got_packet(u_char *args,
                const struct pcap_pkthdr *header,
                const u_char *packet)
{
    if (header->caplen < sizeof(struct ethheader))
        return;

    struct ethheader *eth = (struct ethheader *)packet;

    /* IPv4가 아니면 무시 */
    if (ntohs(eth->ether_type) != 0x0800)
        return;

    if (header->caplen <
        sizeof(struct ethheader) + sizeof(struct ipheader))
        return;

    struct ipheader *ip = (struct ipheader *)
        (packet + sizeof(struct ethheader));

    /* TCP가 아니면 무시 */
    if (ip->iph_protocol != IPPROTO_TCP)
        return;

    int ip_header_len = ip->iph_ihl * 4;

    if (ip_header_len < 20)
        return;

    if (header->caplen <
        sizeof(struct ethheader) + ip_header_len +
        sizeof(struct tcpheader))
        return;

    struct tcpheader *tcp = (struct tcpheader *)
        (packet + sizeof(struct ethheader) + ip_header_len);

    int tcp_header_len = TH_OFF(tcp) * 4;

    if (tcp_header_len < 20)
        return;

    printf("\n========================================\n");

    printf("[Ethernet Header]\n");
    printf("Src MAC: ");
    print_mac(eth->ether_shost);
    printf("\n");

    printf("Dst MAC: ");
    print_mac(eth->ether_dhost);
    printf("\n");

    printf("[IP Header]\n");
    printf("Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Dst IP: %s\n", inet_ntoa(ip->iph_destip));

    printf("[TCP Header]\n");
    printf("Src Port: %u\n", ntohs(tcp->tcp_sport));
    printf("Dst Port: %u\n", ntohs(tcp->tcp_dport));

    int ip_total_len = ntohs(ip->iph_len);
    int payload_len =
        ip_total_len - ip_header_len - tcp_header_len;

    size_t payload_offset =
        sizeof(struct ethheader) +
        ip_header_len +
        tcp_header_len;

    if (payload_len <= 0 || payload_offset >= header->caplen)
        return;

    /* 실제 캡처된 길이를 넘어가지 않도록 제한 */
    size_t captured_payload_len =
        header->caplen - payload_offset;

    if ((size_t)payload_len > captured_payload_len)
        payload_len = captured_payload_len;

    const u_char *payload = packet + payload_offset;

    /* 평문 HTTP의 일반적인 포트만 출력 */
    if (ntohs(tcp->tcp_sport) == 80 ||
        ntohs(tcp->tcp_dport) == 80) {
        printf("[HTTP Message]\n");
        fwrite(payload, 1, payload_len, stdout);
        printf("\n");
    }
}

int main(void)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";

    handle = pcap_open_live(
        "eth0", BUFSIZ, 1, 1000, errbuf
    );

    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live error: %s\n", errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0,
                     PCAP_NETMASK_UNKNOWN) == -1) {
        pcap_perror(handle, "pcap_compile error");
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        pcap_perror(handle, "pcap_setfilter error");
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }

    printf("TCP packet capture started on eth0...\n");

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}
