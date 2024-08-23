#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// Process packet
void process_packet(unsigned char *, int);

// Print a packet into a file
void print_icmp_packet(unsigned char *, int);
void print_igmp_packet(unsigned char *, int);
void print_tcp_packet(unsigned char *, int);
void print_udp_packet(unsigned char *, int);

// Display a packet in console
void display_packet(unsigned char *, int);

static size_t packet_count = 1;
int main(int argc, char const *argv[])
{
    int sockfd, data_received;
    struct sockaddr saddr;
    socklen_t addrlen = sizeof(saddr);

    unsigned char *buffer = (unsigned char *)malloc(65536);
    // Socket creation
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("[!] Socket error");
        exit(EXIT_FAILURE);
    }
    printf("[*] Socket created\n");

    while (1)
    {
        data_received = recvfrom(sockfd, buffer, 65536, 0, &saddr, &addrlen);

        if (data_received < 0)
        {
            perror("[!] Recevfrom error");
            exit(EXIT_FAILURE);
        }

        display_packet(buffer, 65536);
        // process_packet(buffer, 65536);
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

    // Source and destination struction
    struct sockaddr_in source, dest;

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
        printf("\033[35m%ld\t%s\t%s\t%s\t\tIGMP\n", packet_count++, __TIME__, inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));
    }
    else
    {
        // CYAN
        printf("\033[36m%ld\t%s\t%s\t\t%s\t\tOTHER\n", packet_count++, __TIME__, inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));
    }
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

    // Source and Destination address
    struct sockaddr_in source, dest;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    printf("%s\t%s\t%s\tTCP\n", __TIME__, inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));
}

void print_udp_packet(unsigned char *buffer, int size)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct udphdr *udph = (struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));

    struct sockaddr_in source, dest;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    printf("%s\t%s\t%s\tUDP\n", __TIME__, inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));
}
