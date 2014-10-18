#include "frame_parser.h"


// EtherHeaderParser
EtherHeaderParser::EtherHeaderParser(const bpf_u_int32 len, const u_char* packet){
    this->len = len;
    eptr = (struct ether_header *) packet;
}

uint16_t EtherHeaderParser::get_type() {
    return ntohs(eptr->ether_type);
}

u_char* EtherHeaderParser::get_ether_shost() {
    return eptr->ether_shost;
}

u_char* EtherHeaderParser::get_ether_dhost() {
    return eptr->ether_dhost;
}

u_char* EtherHeaderParser::get_next_layer_frame_pointer() {
    return (u_char *) eptr + sizeof(struct ether_header); 
}

bpf_u_int32 EtherHeaderParser::get_next_layer_frame_length(){
    return len - sizeof(struct ether_header) - ETHER_CRC_LEN;
}

void EtherHeaderParser::print_mac_address(u_char * ptr) {
    for (int i = ETHER_ADDR_LEN; i > 0; --i)
        printf("%02X%s", *ptr++, (i > 1) ? ":" : "\n");
}


// IpHeaderParser
IpHeaderParser::IpHeaderParser(const bpf_u_int32 len, const u_char* frame_ptr){
    this->len = len;
    iptr = (struct ip *) frame_ptr;
}

unsigned int IpHeaderParser::get_version() {
    return iptr->ip_v;
}

u_short IpHeaderParser::get_ip_len() {
    return ntohs(iptr->ip_hl);
}

u_int32_t IpHeaderParser::get_saddr() {
    return ntohl(iptr->ip_src.s_addr);
}

u_int32_t IpHeaderParser::get_daddr() {
    return ntohl(iptr->ip_dst.s_addr);
}


void IpHeaderParser::print_ip_address(u_int32_t u_int_ip) {
    for (int i = 3; i >= 0; --i)
        printf("%u%s", (u_int_ip &  (0xff << (i * 8))) >> (i * 8), i ? "." : "");
}

void IpHeaderParser::print_hex_content() {
    printf("\n----------BEGIN--------");
    u_char * ptr;
    ptr = (u_char *) iptr;
    for (u_int i = 0; i < len; ++i) {
        if ((i) % 4 == 0) printf("  ");
        if ((i) % 16 == 0) printf("\n");
        printf("%02x ", *ptr++);
    }
    printf("\n----------END  --------\n");
}

