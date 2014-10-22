#include "frame_parser.h"


// EtherHeaderParser
EtherHeaderParser::EtherHeaderParser(const bpf_u_int32 len, const u_char* packet){
    this->len = len;
    eptr = (struct ether_header *) packet;
}

uint16_t EtherHeaderParser::get_type() {
    return ntohs(eptr->ether_type);
}

QString EtherHeaderParser::get_string_type()
{

    if (get_type() == ETHERTYPE_IP) {
        return "IP";
    }
    else if (get_type() == ETHERTYPE_ARP) {
        return "ARP";
    }
    return "UNKNOWN";
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

QString IpHeaderParser::get_qstring_protocol()
{
    switch (get_uint_protocol()) {
        case 1u:
            return "ICMP";
        case 6u:
            return "TCP";
        case 17u:
            return "UDP";
        default:
            return "UNKNOWN";
    }
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
        ahp = new ARPHeaderParser(ehp->get_next_layer_frame_length(), ehp->get_next_layer_frame_pointer());
        qDebug("Ethernet type hex:%x dec:%d is an ARP packet\n", ehp->get_type(), ehp->get_type());
    }
    else {
        highest_protocol = "UNKNOWN";
        qDebug("Ethernet type %x not IP, ARP", ehp->get_type());
    }
}

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


// ARP related
ARPHeaderParser::ARPHeaderParser(const bpf_u_int32 len, const u_char *packet)
{
    this->len = len;
    aptr = (struct arp_header *) packet;
}

u_int16_t ARPHeaderParser::get_uint_htype()
{
    return ntohs(aptr->htype);
}

QString ARPHeaderParser::get_qstring_htype()
{
    switch (get_uint_htype()) {
        case 1u:
            return QString("Ethernet");
        default:
            return QString("Other");
    }
}

uint16_t ARPHeaderParser::get_uint_ptype() {
    return ntohs(aptr->ptype);
}

QString ARPHeaderParser::get_qstring_ptype()
{

    if (get_uint_ptype() == ETHERTYPE_IP) {
        return "IP";
    }
    return "UNKNOWN";
}

QString ARPHeaderParser::get_qstring_oper()
{
   switch (get_uint_oper()) {
    case 1u:
       return QString("Request");
    case 2u:
       return QString("Reply");
    case 3u:
       return QString("Request Reverse");
    case 4u:
       return QString("Reply Reverse");
    case 5u:
       return QString("DRARP Request");
    case 6u:
       return QString("DRARP Reply");
    case 7u:
       return QString("DRARP Error");
    case 8u:
       return QString("InARP Request");
    case 9u:
       return QString("InARP Reply");
    default:
       return QString("Other");
   }
}
