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
    QString get_description(){return QString("Ethernet II, Src: %0 , Dst: %1").arg(
                                         EtherHeaderParser::byte_to_mac_addr(get_ether_shost())).arg(
                                         EtherHeaderParser::byte_to_mac_addr(get_ether_dhost()));}
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
    QString get_description() {return QString("Address Resolution Protocol (%0)").arg(get_qstring_oper());}
private:
    struct arp_header * aptr;
    bpf_u_int32 len;
};

#define IP_ICMP 1u
#define IP_TCP 6u
#define IP_UDP 17u

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
    QString get_description(){return QString("Internet Protocol Version 4, Src: %1 , Dst: %2")
      .arg(get_qstring_saddr()).arg(get_qstring_daddr());}
private:
    struct ip * iptr;
    bpf_u_int32 len;
};


//icmp
struct icmp_header
{
  u_int8_t icmp_type;
  u_int8_t icmp_code;
  u_int16_t icmp_chksum;
  u_int16_t icmp_id;
  u_int16_t icmp_seq;
};

class ICMPHeaderParser {
public:
    ICMPHeaderParser(const bpf_u_int32 len, const u_char* ptr);
    u_int8_t get_code() {return iptr->icmp_code;}
    u_int8_t get_uint_type() {return iptr->icmp_type;}
    QString get_qstring_type();
    u_int16_t get_checksum() {return ntohs(iptr->icmp_chksum);}
    u_int16_t get_id() {return ntohs(iptr->icmp_id);}
    u_int16_t get_seq() {return ntohs(iptr->icmp_seq);}
    QString get_description() {return QString("Internet Control Message Protocol");}
private:
    icmp_header *iptr;
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
    UDPHeaderParser(const bpf_u_int32 len, const u_char* ptr);
    int get_src_port() {return ntohs(uptr->src_port);}
    int get_dst_port() {return ntohs(uptr->dst_port);}
    int get_len() {return ntohs(uptr->len);}
    u_int16_t get_checksum() {return ntohs(uptr->checksum);}
    QString get_description() {return QString("User Datagram Protocol, Src Port: %1 , Dst Port: %2"
                                              ).arg(get_src_port()).arg(get_dst_port()); }

private:
    udp_header *uptr;
    bpf_u_int32 len;
};

// TCP
struct tcp_header
{
  u_int16_t src_port;		/* source port */
  u_int16_t dst_port;		/* destination port */
  u_int32_t tcp_seq;		/* sequence number */
  u_int32_t tcp_ack;		/* acknowledgement number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
  u_int8_t tcp_reserved:4,	/* (unused) */
    tcp_off:4;			/* data offset */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
  u_int8_t tcp_off:4, tcp_reserved:4;
#endif
  u_int8_t th_flags;
#define TH_FIN	0x01
#define TH_SYN	0x02
#define TH_RST	0x04
#define TH_PSH	0x08
#define TH_ACK	0x10
#define TH_URG	0x20
  u_int16_t th_win;		/* window */
  u_int16_t th_sum;		/* checksum */
  u_int16_t th_urp;		/* urgent pointer */
};

class TCPHeaderParser {
public:
    TCPHeaderParser(const bpf_u_int32 len, const u_char* ptr);
    int get_src_port() {return ntohs(tptr->src_port);}
    int get_dst_port() {return ntohs(tptr->dst_port);}
    u_int32_t get_tcp_seq() {return ntohl(tptr->tcp_seq);}
    u_int32_t get_tcp_ack() {return ntohl(tptr->tcp_ack);}
    int get_header_len() {return tptr->tcp_off * 4;}
    bool is_FIN_set() {return TH_FIN & tptr->th_flags;}
    bool is_SYN_set() {return TH_SYN & tptr->th_flags;}
    bool is_RST_set() {return TH_RST & tptr->th_flags;}
    bool is_PSH_set() {return TH_PSH & tptr->th_flags;}
    bool is_ACK_set() {return TH_ACK & tptr->th_flags;}
    bool is_URG_set() {return TH_URG & tptr->th_flags;}
    u_int16_t get_window_size() {return ntohs(tptr->th_win);}
    u_int16_t get_checksum() {return ntohs(tptr->th_sum);}
    u_int16_t get_urp() {return ntohs(tptr->th_urp);}
    QString get_description() {return QString(
    "Transmission Control Protocol, Src Port: %0, Dst Port: %1, Seq: %2, Ack: %3")
    .arg(get_src_port()).arg(get_dst_port()).arg(get_tcp_seq()).arg(get_tcp_ack()); }
private:
    tcp_header *tptr;
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
    TCPHeaderParser *thp=NULL;
    ICMPHeaderParser *ichp=NULL;
    QByteArray qba;
    const QString & get_highest_protocol();
    QString * to_hex_qstring(bool with_space=true, bool with_linebreak=true);
    QString * to_ascii_qstring(bool with_space=true, bool with_linebreak=true);
    static bool isPrintable(char c);
    QString get_description();
    QString get_source() {return ihp == NULL? EtherHeaderParser::byte_to_mac_addr(ehp->get_ether_shost()):ihp->get_qstring_saddr();}
    QString get_destination() { return ihp == NULL? EtherHeaderParser::byte_to_mac_addr(ehp->get_ether_dhost()):ihp->get_qstring_daddr();}
private:
    QString highest_protocol;
};

#endif
