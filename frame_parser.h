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
#include <QtCore>


// ether related

class EtherHeaderParser {
public:
    EtherHeaderParser(const bpf_u_int32 len, const u_char* packet);
    uint16_t get_type();
    QString get_qstring_type();
    u_char* get_ether_shost();
    u_char* get_ether_dhost();
    u_char* get_next_layer_frame_pointer();
    bpf_u_int32 get_next_layer_frame_length();
    static QString byte_to_mac_addr(u_char*);
private:
    struct ether_header * eptr;
    bpf_u_int32 len;
};

// ARP related

struct __attribute__((__packed__)) arp_header
{
  u_int16_t htype;
  u_int16_t ptype;
  u_int8_t hlen;
  u_int8_t plen;
  u_int16_t oper;
  u_char sha[6];
  struct in_addr spa;
  u_char tha[6];
  struct in_addr tpa;
};

class ARPHeaderParser {
public:
    ARPHeaderParser(const bpf_u_int32 len, const u_char* ptr);
    u_int16_t get_uint_htype();
    QString get_qstring_htype();
    u_int16_t get_uint_ptype();
    QString get_qstring_ptype();
    u_int8_t get_hsize(){return aptr->hlen;}
    u_int8_t get_psize(){return aptr->plen;}
    u_int16_t get_uint_oper(){return ntohs(aptr->oper);}
    QString get_qstring_oper();
    QString get_sha(){return EtherHeaderParser::byte_to_mac_addr(aptr->sha);}
    QString get_spa(){return inet_ntoa(aptr->spa);}
    QString get_tha(){return EtherHeaderParser::byte_to_mac_addr(aptr->tha);}
    QString get_tpa(){return inet_ntoa(aptr->tpa);}
private:
    struct arp_header * aptr;
    bpf_u_int32 len;
};


class IpHeaderParser {
public:
    IpHeaderParser(const bpf_u_int32 len, const u_char* packet);
    unsigned int get_version() { return iptr->ip_v; }
    u_int16_t get_header_len(){return iptr->ip_hl;}
    u_int16_t get_header_byte_len(){return get_header_len() * 4;}
    u_short get_def() { return iptr->ip_tos;}
    u_int16_t get_total_length() { return ntohs(iptr->ip_len);}
    u_int16_t get_id() { return ntohs(iptr->ip_id);}
    u_int16_t get_offset() { return ntohs(iptr->ip_off) & IP_OFFMASK;}
    bool is_rf_set() { return ntohs(iptr->ip_off) & IP_RF;}
    bool is_df_set() { return ntohs(iptr->ip_off) & IP_DF;}
    bool is_mf_set() { return ntohs(iptr->ip_off) & IP_MF;}
    u_int8_t get_ttl() { return iptr->ip_ttl;}
    u_int8_t get_uint_protocol() { return iptr->ip_p;}
    QString get_qstring_protocol();
    u_int16_t get_checksum() { return ntohs(iptr->ip_sum);}
    u_int32_t get_uint_saddr(){return ntohl(iptr->ip_src.s_addr);}
    QString get_qstring_saddr(){return inet_ntoa(iptr->ip_src);}
    u_int32_t get_daddr(){return ntohl(iptr->ip_dst.s_addr);}
    QString get_qstring_daddr(){return inet_ntoa(iptr->ip_dst);}

    u_char *get_next_layer_frame_pointer();
    bpf_u_int32 get_next_layer_frame_length();
    void print_hex_content();
    static void print_ip_address(u_int32_t);
private:
    struct ip * iptr;
    bpf_u_int32 len;
};


// UDP related
struct udp_header
{
  u_int16_t src_port;
  u_int16_t dst_port;
  u_int16_t len;
  u_int16_t checksum;
};

class UDPHeaderParser {
public:
    UDPHeaderParser(const bpf_u_int32 len, const u_char* packet);

private:
    udp_header *uptr;
    bpf_u_int32 len;
};


//  PackParser
class PackParser {

public:
    PackParser(const QByteArray &qba);
    EtherHeaderParser *ehp=NULL;
    IpHeaderParser *ihp=NULL;
    ARPHeaderParser *ahp=NULL;
    UDPHeaderParser *uhp=NULL;
    QByteArray qba;
    const QString & get_highest_protocol();
    QString * to_hex_qstring(bool with_space=true, bool with_linebreak=true);
    QString * to_ascii_qstring(bool with_space=true, bool with_linebreak=true);
    static bool isPrintable(char c);

private:
    QString highest_protocol;
};

#endif
