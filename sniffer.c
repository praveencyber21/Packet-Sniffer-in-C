#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// Process packet
void process_packet(unsigned char *, int);

// Print a packet into a file
void print_ip_header(unsigned char *, int);
void print_icmp_packet(unsigned char *, int);
void print_igmp_packet(unsigned char *, int);
void print_tcp_packet(unsigned char *, int);
void print_udp_packet(unsigned char *, int);

// Display a packet in console
void display_packet(unsigned char *, int);

static size_t packet_count = 1;
struct sockaddr_in source, dest;
FILE *logfile;

int main(int argc, char const *argv[])
{
    int sockfd, data_received;
    struct sockaddr saddr;
    socklen_t addrlen = sizeof(saddr);

    logfile = fopen("log.txt", "w");
    if (logfile == NULL)
        perror("File");

    unsigned char *buffer = (unsigned char *)malloc(65536);
    // Socket creation
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("[!] Socket error");
        exit(EXIT_FAILURE);
    }
    printf("[*] Packet sniffer started...\n");

    while (1)
    {
        data_received = recvfrom(sockfd, buffer, 65536, 0, &saddr, &addrlen);

        if (data_received < 0)
        {
            perror("[!] Recevfrom error");
            exit(EXIT_FAILURE);
        }

        display_packet(buffer, 65536);
        process_packet(buffer, 65536);
    }
    close(sockfd);
    free(buffer);

    return 0;
}

void process_packet(unsigned char *buffer, int size)
{
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    struct ethhdr *ethh = (struct ethhdr *)(buffer);

    switch (iph->protocol)
    {
    case 1:
        // print_icmp_packet(buffer, size);
        break;
    case 2:
        // print_igmp_packet(buffer, size);
        break;
    case 6:

        print_tcp_packet(buffer, size);
        break;
    case 17:

        print_udp_packet(buffer, size);
        break;
    }
}
void display_packet(unsigned char *buffer, int size)
{
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    // Source address
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    // Destination address
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    // Check protocol (TCP, UDP, ICMP, IGMP)
    if (iph->protocol == 6)
    {
        // GREEN
        printf("\033[32m%ld\t%s\t%s\t\t%s\t\tTCP\n", packet_count++, __TIME__, inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));
    }
    else if (iph->protocol == 17)
    {
        // YELLOW
        printf("\033[33m%ld\t%s\t%s\t\t%s\t\tUDP\n", packet_count++, __TIME__, inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));
    }
    else if (iph->protocol == 1)
    {
        // RED
        printf("\033[31m%ld\t%s\t%s\t\t%s\t\tICMP\n", packet_count++, __TIME__, inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));
    }
    else if (iph->protocol == 2)
    {
        // PURPLE
        printf("\033[35m%ld\t%s\t%s\t\t%s\t\tIGMP\n", packet_count++, __TIME__, inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));
    }
    else
    {
        // CYAN
        printf("\033[36m%ld\t%s\t%s\t\t%s\t\tOTHER\n", packet_count++, __TIME__, inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));
    }
}
void print_ip_header(unsigned char *buffer, int size)
{
    // logfile = fopen("log.txt", "a");
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr)); // Skip ethernet header
    iphdrlen = iph->ihl * 4;                                              // IP header length

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(logfile, "\n");
    fprintf(logfile, "IP HEADER\n");
    fprintf(logfile, "    |-IP Version          :%d\n", (unsigned int)iph->version);
    fprintf(logfile, "    |-IP Header Length    :%d DWORDS or %d Bytes\n", (unsigned int)iph->ihl, (unsigned int)(iph->ihl * 4));
    fprintf(logfile, "    |-Type of Service     :%d\n", (unsigned int)iph->tos);
    fprintf(logfile, "    |-IP Total Length     :%d Bytes(size of packet)\n", ntohs(iph->tot_len));
    fprintf(logfile, "    |-Identification      :%d\n", ntohs(iph->id));
    fprintf(logfile, "    |-TTL                 :%d\n", (unsigned int)iph->ttl);
    fprintf(logfile, "    |-Protocol            :%d\n", (unsigned int)iph->protocol);
    fprintf(logfile, "    |-Checksum            :%d\n", ntohs(iph->check));
    fprintf(logfile, "    |-Source IP           :%s\n", inet_ntoa(source.sin_addr));
    fprintf(logfile, "    |-Destination IP      :%s\n", inet_ntoa(dest.sin_addr));
}
void print_icmp_packet(unsigned char *buffer, int size)
{
}

void print_tcp_packet(unsigned char *buffer, int size)
{

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr)); // Skip Ethernet header
    iphdrlen = iph->ihl * 4;                                              // IP header length

    struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));

    fprintf(logfile, "\n");
    fprintf(logfile, "****************************** TCP HEADER ******************************\n");

    print_ip_header(buffer, size);

    fprintf(logfile, "\n");
    fprintf(logfile, "TCP HEADER\n");
    fprintf(logfile, "    |-Source port             :%d\n", ntohs(tcph->source));
    fprintf(logfile, "    |-Destination port        :%d\n", ntohs(tcph->dest));
    fprintf(logfile, "    |-Sequence Number         :%u\n", ntohl(tcph->seq));
    fprintf(logfile, "    |-Acknowledge Number      :%u\n", ntohl(tcph->ack_seq));
    fprintf(logfile, "    |-Header Length           :%d DWORDS or %d BYTES\n", (unsigned int)tcph->doff, (unsigned int)(tcph->doff * 4));
    fprintf(logfile, "    |-Urgent flag             :%d\n", (unsigned int)tcph->urg);
    fprintf(logfile, "    |-Acknowledgement flag    :%d\n", (unsigned int)tcph->ack);
    fprintf(logfile, "    |-Push flag               :%d\n", (unsigned int)tcph->psh);
    fprintf(logfile, "    |-Reset flag              :%d\n", (unsigned int)tcph->rst);
    fprintf(logfile, "    |-Synchronise flag        :%d\n", tcph->syn);
    fprintf(logfile, "    |-Window                  :%d\n", ntohs(tcph->window));
    fprintf(logfile, "    |-Checksum                :%d\n", ntohs(tcph->check));
    fprintf(logfile, "    |-Urgent pointer          :%d\n", tcph->urg_ptr);
    fprintf(logfile, "\n");
    fprintf(logfile, "\n########################################################################");
}

void print_udp_packet(unsigned char *buffer, int size)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct udphdr *udph = (struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));

    fprintf(logfile, "\n");
    fprintf(logfile, "****************************** UDP HEADER ******************************\n");

    print_ip_header(buffer, size);

    fprintf(logfile, "UDP HEADER\n");
    fprintf(logfile, "    |-Source port         :%d\n", ntohs(udph->source));
    fprintf(logfile, "    |-Destination port    :%d\n", ntohs(udph->dest));
    fprintf(logfile, "    |-UDP Length          :%d\n", ntohs(udph->len));
    fprintf(logfile, "    |-UDP Checksum        :%d\n", ntohs(udph->check));

    fprintf(logfile, "\n");
}
