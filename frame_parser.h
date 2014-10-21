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
    u_char* get_ether_shost();
    u_char* get_ether_dhost();
    u_char* get_next_layer_frame_pointer();
    bpf_u_int32 get_next_layer_frame_length();
    static QString byte_to_mac_addr(u_char*);
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


class PackParser {

public:
    PackParser(const QByteArray &qba);
    EtherHeaderParser * ehp;
    IpHeaderParser * ihp;
    QByteArray qba;
    const QString & get_highest_protocol();
    QString * to_hex_qstring(bool with_space=true, bool with_linebreak=true);
    QString * to_ascii_qstring(bool with_space=true, bool with_linebreak=true);
    static bool isPrintable(char c);

private:
    QString highest_protocol;
};

#endif
