#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define SIZE 1486
/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

/* UDP Header */
struct udpheader
{
  u_int16_t udp_sport;           /* source port */
  u_int16_t udp_dport;           /* destination port */
  u_int16_t udp_ulen;            /* udp length */
  u_int16_t udp_sum;             /* udp checksum */
};

void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

int main(){
	char buffer[SIZE];
	memset(buffer, 0, SIZE);
	struct ipheader *ip = (struct ipheader *) buffer;
	struct udpheader *udp = (struct udpheader *) (buffer+sizeof(struct ipheader));
	char *data = buffer + sizeof(struct ipheader) + sizeof(struct udpheader);
	const char *msg = "Spoofed IP packet for Ex. 2.2A!\n";
	int data_len = strlen(msg);
	strncpy (data, msg, data_len);
	udp->udp_sport = htons(12345);
	udp->udp_dport = htons(53333);
	udp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
	udp->udp_sum =  0;
	ip->iph_ver = 4;
	ip->iph_ihl = 5;
	ip->iph_ttl = 20;
	ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
	ip->iph_destip.s_addr = inet_addr("192.168.1.24");
	ip->iph_protocol = IPPROTO_UDP; 
	ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct udpheader) + data_len);
	send_raw_ip_packet (ip);
	return 0;
}
