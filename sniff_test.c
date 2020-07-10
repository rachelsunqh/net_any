#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
typedef int t_sniffer;
typedef u_int8_t	u8;
typedef u_int16_t	u16;
typedef u_int32_t	u32;
struct ptp_pack {
	u8	MsgType:4;
	u8	TranSpec:4;
	u8	VerPTP:4;
	u8	recv0:4;
	u16	MsgLength;
	u8	DomainNumber;
	u8	Reserved;
	u16	FlagField;
	u32	CorrectionField;
	u32	recv1;
	u32	SourcePortIdentity0;
	u16	SourcePortIdentity1;
	u16	SEquenceID;
	u8	ControlField;
	u8	LogMsgInterval;
	u8	data[0];
};
struct ptp_MsgType{
	u8 index;
	char *name;
};

struct ptp_MsgType  ptp_type_name[] = {
	{0x00,"Sync"},
	{0x01,"Delay_Req"},
	{0x02,"Pdelay_Req"},
	{0x03,"Pdelay_Resp"},
	{0x04,"resv"},
	{0x05,"resv"},
	{0x06,"resv"},
	{0x07,"resv"},
	{0x08,"Follow_Up"},
	{0x09,"Delay_Resp"},
	{0x0a,"Pdelay_Resp_Follow_Up"},
	{0x0b,"Announce"},
	{0x0c,"Signaling"},
	{0x0d,"Management"},
};

	
void ProcessPacket(unsigned char *buffer,int size,t_sniffer *sniffer)
{
//	unsigned short eth_type = *((unsigned short *)(buffer + 6 + 6));
	//buffer = buffer + 6 + 6;
//	struct iphdr *iph = (struct iphdr *)buffer;
#if 0
	printf("dest   mac %02x:%02x:%02x:%02x:%02x:%02x  ",*buffer,*(buffer + 1),*(buffer +2),*(buffer + 3),*(buffer +4),*(buffer + 5));
	printf("source mac %02x:%02x:%02x:%02x:%02x:%02x  ",*(buffer + 6),*(buffer + 7),*(buffer +8),*(buffer + 9),*(buffer +10),*(buffer + 11));
	printf("eth_type = 0x%04x\n",ntohs(*((unsigned short *)(buffer + 12))));
#endif
	struct ptp_pack *pack = NULL;
	int i = 0;

	if(ntohs(*((unsigned short *)(buffer + 12))) == 0x88f7){
		printf("ptp packet: ");
		printf("dmac %02x:%02x:%02x:%02x:%02x:%02x  ",*buffer,*(buffer + 1),*(buffer +2),*(buffer + 3),*(buffer +4),*(buffer + 5));
		printf("smac %02x:%02x:%02x:%02x:%02x:%02x  ",*(buffer + 6),*(buffer + 7),*(buffer +8),*(buffer + 9),*(buffer +10),*(buffer + 11));
		pack = (struct ptp_pack *)(buffer + 14);
		printf("\n\tpack_type:%s\n",ptp_type_name[pack->MsgType].name);
		printf("\tranSpec:%s\n",pack->TranSpec ? "IEEE 8.2.1as" : "IEEE 1588");
		printf("\tVerPTP:v%d\n",pack->VerPTP);
		printf("\tMsgLength:%d\n",ntohs(pack->MsgLength));
		printf("\tDomainNumber:%d\n",pack->DomainNumber);
		printf("\tFlagField:0x%x\n",ntohs(pack->FlagField));
		printf("\tCorrectionField:0x%x\n",ntohl(pack->CorrectionField));
		printf("\tSourcePortIdentity0:0x%x\n",ntohl(pack->SourcePortIdentity0));
		printf("\tSourcePortIdentity1:0x%x\n",ntohs(pack->SourcePortIdentity1));
		printf("\tSEquenceID:0x%x\n",ntohs(pack->SEquenceID));
		printf("\tControlField:0x%x\n",pack->ControlField);
		printf("\tLogMsgInterval:0x%x\n",pack->LogMsgInterval);
		printf("\tdata:\n\t\t");
		for(i = 0;i < (ntohs(pack->MsgLength) - sizeof(struct ptp_pack));i++){
			printf("%02x ",*(buffer + 14 + sizeof(struct ptp_pack) + i));
			if(!((i + 1) % 20)){
				printf("\n\t\t");
			}	
		}
		printf("\n");

#if 0
struct ptp_pack {
	u8	MsgType:4;
	u8	TranSpec:4;
	u8	VerPTP:4;
	u8	recv0:4;
	u16	MsgLength;
	u8	DomainNumber;
	u8	Reserved;
	u16	FlagField;
	u32	CorrectionField;
	u32	recv1;
	u32	SourcePortIdentity0;
	u16	SourcePortIdentity1;
	u16	SEquenceID;
	u8	ControlField;
	u8	LogMsgInterval;
	u8	data[0];
};
#endif
	}
}


int main(void)
{
	int sd = 0,res = 0,saddr_size = 0,data_size = 0;
	struct sockaddr saddr;
	unsigned char *buffer = NULL;
	t_sniffer sniffer;
	fd_set fd_read;

	buffer = malloc(sizeof(unsigned char *) * 65536);
	if(!buffer){
		//return -ENOMEM;
		return -1;
	}

	sd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if(sd < 0){
		return -1;
	}

	while(1){
		FD_ZERO(&fd_read);
		FD_SET(0,&fd_read);
		FD_SET(sd,&fd_read);

		res = select(sd + 1,&fd_read,NULL,NULL,NULL);
		if(res < 0){
		//	close(sd);
			continue;
		}else {
			if(FD_ISSET(0,&fd_read)){
				continue;
			}else if(FD_ISSET(sd,&fd_read)){
				saddr_size = sizeof(saddr);
				//errno = 0;
				data_size = recvfrom(sd,buffer,65536,0,&saddr,(socklen_t *)&saddr_size);
				if(0 >= data_size){
					perror("recvfrom():");	
					continue;
				}
				ProcessPacket(buffer,data_size,&sniffer);
			}
		}
	}
	
	close(sd);
	return 0;
}
