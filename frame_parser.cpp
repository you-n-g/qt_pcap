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

QString EtherHeaderParser::byte_to_mac_addr(u_char * ptr) {
    QString str;
    char buffer[10];
    for (int i = ETHER_ADDR_LEN; i > 0; --i) {
        sprintf(buffer, "%02X%s", *ptr++, (i > 1) ? ":" : "");
        str.append(buffer);
    }
    return str;
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


// Pack Parser

PackParser::PackParser(const QByteArray &qba) {
    this->qba = qba;
    ehp = new EtherHeaderParser(qba.length(), (const u_char *)qba.constData());
    if (ehp->get_type() == ETHERTYPE_IP) {
        highest_protocol = "IP";
        ihp = new IpHeaderParser(ehp->get_next_layer_frame_length(), ehp->get_next_layer_frame_pointer());
    }
    else if (ehp->get_type() == ETHERTYPE_ARP) {
        highest_protocol = "ARP";
        qDebug("Ethernet type hex:%x dec:%d is an ARP packet\n", ehp->get_type(), ehp->get_type());
    }
    else {
        highest_protocol = "UNKNOWN";
        qDebug("Ethernet type %x not IP, ARP", ehp->get_type());
    }
};

const QString & PackParser::get_highest_protocol(){
    return highest_protocol;
}

QString *PackParser::to_hex_qstring(bool with_space, bool with_linebreak)
{
    QString * hex_qstring = new QString();
    for (int i = 0; i < qba.length(); ++i) {
        hex_qstring->append(QString().sprintf("%02X", (u_int8_t)qba.at(i)));
        if (with_space) {
            hex_qstring->append(" ");
            if ((i + 1) % 4 == 0)
                hex_qstring->append(" ");
        }
        if (with_linebreak && (i + 1) % 16 == 0) {
            while (hex_qstring->endsWith(' ')) hex_qstring->chop(1);
            hex_qstring->append("\n");
        }
    }
    return hex_qstring;
}

QString *PackParser::to_ascii_qstring(bool with_space, bool with_linebreak)
{
    QString * ascii_qstring = new QString();
    for (int i = 0; i < qba.length(); ++i) {
        ascii_qstring->append(PackParser::isPrintable(qba.at(i)) ? qba.at(i) : '.');
        if (with_space) {
            if ((i + 1) % 4 == 0)
                ascii_qstring->append(" ");
        }
        if (with_linebreak && (i + 1) % 16 == 0) {
            while (ascii_qstring->endsWith(' ')) ascii_qstring->chop(1);
            ascii_qstring->append("\n");
        }
    }
    return ascii_qstring;
}

bool PackParser::isPrintable(char c)
{if ((c > 48) && (c < 126)) return true; else return false; }
