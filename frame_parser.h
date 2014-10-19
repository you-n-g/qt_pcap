#ifndef QT_PCAP_FRAME_PARSER
#define QT_PCAP_FRAME_PARSER 

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>



// ether related

class EtherHeaderParser {
public:
    EtherHeaderParser(const bpf_u_int32 len, const u_char* packet);
    uint16_t get_type();
    u_char* get_ether_shost();
    u_char* get_ether_dhost();
    u_char* get_next_layer_frame_pointer();
    bpf_u_int32 get_next_layer_frame_length();
    static void print_mac_address(u_char*);
private:
    struct ether_header * eptr;
    bpf_u_int32 len;
};


class IpHeaderParser {
public:
    IpHeaderParser(const bpf_u_int32 len, const u_char* packet);
    //u_char* get_next_layer_frame_pointer();
    //bpf_u_int32 get_next_layer_frame_length();
    unsigned int get_version();
    u_short get_ip_len();
    u_int32_t get_saddr();
    u_int32_t get_daddr();
    void print_hex_content();
    static void print_ip_address(u_int32_t);
private:
    struct ip * iptr;
    bpf_u_int32 len;
};

#endif
