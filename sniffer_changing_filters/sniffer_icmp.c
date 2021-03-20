#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/ip.h>
/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};
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
/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) == 0x0800) {
    struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
    printf("src: %s\n", inet_ntoa(ip->iph_sourceip));  
    printf("dst: %s\n", inet_ntoa(ip->iph_destip));  
}
}
int main()
{

pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "icmp and (host 8.8.4.4 or 8.8.8.8)";
bpf_u_int32 net;
// Step 1: Open live pcap session on NIC 
handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
if(handle==NULL){
printf("Failed pcap_open_live function!\n");
exit(1);
}
// Step 2: Compile filter_exp into BPF psuedo-code
pcap_compile(handle, &fp, filter_exp, 0, net);
// Step 3: Setting a filter
pcap_setfilter(handle, &fp);
// Step 4: Capture packets
pcap_loop(handle, -1, got_packet, NULL);
pcap_close(handle); //Close the handle
return 0;
}

