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

    if (ip_header_len 
