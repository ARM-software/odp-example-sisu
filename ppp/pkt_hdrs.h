/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _PKT_HDRS_H
#define _PKT_HDRS_H

#include <stdint.h>
#include <assert.h>
#include <arpa/inet.h>

extern uint16_t pkt_chk_sum(const void *ptr, uint32_t nbytes);

//For ppp_packet.protocol()
enum ppp_frametype_enum
{
    PPP_FRAMETYPE_ANY    = 0x0000,
    PPP_FRAMETYPE_NOTDIX = 0x07FF, //Ethernet type/length field < 0x600
    PPP_FRAMETYPE_IPV4   = 0x0800,
    PPP_FRAMETYPE_ARP    = 0x0806,
    PPP_FRAMETYPE_VLAN   = 0x8100,
    PPP_FRAMETYPE_IPV6   = 0x86DD
};

#define MAXADDRLEN 8 //Some networks use 64-bit MAC addresses
#define MAC48LEN 6

struct ethhdr
{
    uint8_t dstaddr[MAC48LEN];
    uint8_t srcaddr[MAC48LEN];
    uint16_t frametype;
    inline bool is_unicast() const
    {
	return (dstaddr[0] & 1) == 0;//First bit on wire must be zero
    }
};

struct vlantag
{
    uint16_t vlan_tci;//15:13 user priority, 12 CFI, 11:0 VLAN-id
    uint16_t frametype;

//Helper functions
    inline uint32_t get_vlanid() const
    {
	return ntohs(vlan_tci) & 0xFFFU;
    }
    inline uint32_t get_priority() const
    {
	return ntohs(vlan_tci) >> 13U;
    }
};

enum ppp_ipproto_enum
{
    PPP_IPPROTO_ICMP = 0x01,
    PPP_IPPROTO_IGMP = 0x02,
    PPP_IPPROTO_IPINIP = 0x04,
    PPP_IPPROTO_TCP  = 0x06,
    PPP_IPPROTO_UDP  = 0x11,
    PPP_IPPROTO_GRE  = 0x2F,
    PPP_IPPROTO_ESP  = 0x32,
    PPP_IPPROTO_AH   = 0x33,
    PPP_IPPROTO_SCTP = 0x84
};

#define IP_FRAG_RESV 0x8000  //Reserved fragment flag
#define IP_FRAG_DONT 0x4000  //Don't fragment flag
#define IP_FRAG_MORE 0x2000  //More fragments following flag
#define IP_FRAG_MASK 0x1fff  //Mask for fragment offset bits

struct udphdr;
struct tcphdr;
struct icmphdr;

struct ipv4hdr
{
    uint8_t  vers_hlen;//#0
    uint8_t  tos;//#1
    uint16_t total_len;//#2
    uint16_t id;//#4
    uint16_t fraginfo;//#6
    uint8_t  ttl;//#8
    ppp_ipproto_enum ip_proto:8;//#9
    uint16_t hchecksum;//#10
    uint32_t src_addr;//#12
    uint32_t dst_addr;//#16

//Helper functions
    inline uint32_t hdr_size() const
    {
	return (vers_hlen & 0xfU) << 2U;
    }
    inline uint32_t hdr_version() const
    {
	return vers_hlen >> 4U;
    }

    inline bool is_frag() const
    {
	return (fraginfo & htons(IP_FRAG_MORE | IP_FRAG_MASK)) != 0;
    }
    inline bool frag_dont() const
    {
	return (fraginfo & htons(IP_FRAG_DONT)) != 0;
    }
    inline bool frag_more() const
    {
	return (fraginfo & htons(IP_FRAG_MORE)) != 0;
    }
    inline uint16_t frag_offset() const
    {
	return (uint16_t)((ntohs(fraginfo) & IP_FRAG_MASK) * 8U);
    }
    inline void set_frag_offset(uint16_t off)
    {
	fraginfo = htons((ntohs(fraginfo) & ~IP_FRAG_MASK) | (off / 8U));
    }
    inline void set_frag_more(bool more)
    {
	if (more)
	{
	    //Set more flag
	    fraginfo |= htons(IP_FRAG_MORE);
	}
	else
	{
	    //Clear more flag
	    fraginfo &= ~htons(IP_FRAG_MORE);
	}
    }

    //Return size of IP payload
    inline uint16_t payload_len() const
    {
	uint32_t tl = ntohs(total_len);
	uint32_t hs = hdr_size();
	return tl >= hs ? tl - hs : 0;
    }
    //Return pointer to IP payload
    inline unsigned char *payload_ptr() const
    {
	return (unsigned char *)this + hdr_size();
    }
    //Return pointer to IP payload when UDP
    inline udphdr *get_udphdr() const
    {
	assert(ip_proto == PPP_IPPROTO_UDP);
	return (udphdr *)((char *)this + hdr_size());
    }
    //Return pointer to IP payload when TCP
    inline tcphdr *get_tcphdr() const
    {
	assert(ip_proto == PPP_IPPROTO_TCP);
	return (tcphdr *)((char *)this + hdr_size());
    }
    //Return pointer to IP payload when ICMP
    inline icmphdr *get_icmphdr() const
    {
	assert(ip_proto == PPP_IPPROTO_ICMP);
	return (icmphdr *)((char *)this + hdr_size());
    }

    uint16_t checksum() const;
    void update_checksum()
    {
	hchecksum = 0;
	hchecksum = checksum();
    }
    void update_checksum_incr()
    {
	//Increment checksum high byte
	uint32_t sum = hchecksum + htons(0x100);
	//Fold into 16 bits for ones complement operation
	hchecksum = sum + (sum >> 16);
    }
    void copy_to(void *dst) const;
    void copy_from(const void *src);
};
#define IPv4HDR_MIN_SIZE 20
#define IPv4HDR_MAX_SIZE 60

struct udphdr
{
    uint16_t src_port;//#0
    uint16_t dst_port;//#2
    uint16_t length;//#4  //Length of UDP header + payload
    uint16_t chksum;//#6

//Helper functions
    inline uint32_t hdr_size() const
    {
	return sizeof(struct udphdr);
    }
    //Return size of UDP payload
    inline uint32_t payload_len() const
    {
	return ntohs(length) - hdr_size();
    }
    //Return pointer to UDP payload
    inline unsigned char *payload_ptr() const
    {
	return (unsigned char *)this + hdr_size();
    }
    //Compute UDP checksum, IPv4 header must precede UDP header, payload may be
    //separate
    uint16_t checksum(const unsigned char *payload) const;
};

struct tcphdr
{
    uint16_t src_port;//#0
    uint16_t dst_port;//#2
    uint32_t seqno;//#4
    uint32_t ackno;//#8
    uint16_t flags;//#12
    uint16_t winsz;//#14
    uint16_t chksum;//#16
    uint16_t urgptr;//#18
    //Variable length options may follow as defined by data offset in flags

//Helper functions
    inline uint32_t data_offset() const
    {
	return ntohs(flags) >> 12U;
    }
    inline uint32_t hdr_size() const
    {
	//hdr_size() should not be called with an invalid data offset
	assert(data_offset() >= 5U);
	return 4U * data_offset();
    }
    inline unsigned char *payload_ptr() const
    {
	return (unsigned char *)this + hdr_size();
    }
    //Compute TCP checksum, IPv4 header must precede TCP header, payload may be
    //separate
    uint16_t checksum(const unsigned char *payload, uint32_t payload_len) const;
};

#define TCP_FLAG_FIN 0x0001
#define TCP_FLAG_SYN 0x0002
#define TCP_FLAG_RST 0x0004
#define TCP_FLAG_PSH 0x0008
#define TCP_FLAG_ACK 0x0010
#define TCP_FLAG_URG 0x0020
#define TCP_FLAG_ECE 0x0040
#define TCP_FLAG_CWR 0x0080
#define TCP_FLAG_NS  0x0100
#define TCP_FLAG_RS0 0x0200 //Reserved
#define TCP_FLAG_RS1 0x0400 //Reserved
#define TCP_FLAG_RS2 0x0800 //Reserved
#define TCP_DATA_OFF 0xF000 //Data offset in 32-bit words


struct icmphdr //This is really the echo/echor header
{
    uint8_t  type;      //ICMP type
    uint8_t  code;      //ICMP code
    uint16_t chksum;    //ICMP message checksum
    uint16_t ident;     //ICMP echo identifier
    uint16_t seqno;     //ICMP echo sequence number
    //More data may follow

    inline uint16_t checksum(uint32_t length) const
    {
	return pkt_chk_sum(this, length);
    }
};

#define ICMPPKT_MINSIZE 8 //Minimum size

#define ICMP_TYPE_ECHOR 0
#define ICMP_TYPE_DESTINATION_UNREACHABLE 3
#define ICMP_TYPE_REDIRECT_MESSAGE 5
#define ICMP_TYPE_ECHO 8
#define ICMP_TYPE_TIME_EXCEEDED 11
#define ICMP_TYPE_PARAMETER_PROBLEM 12

#define ICMP_CODE_ECHO 0
#define ICMP_CODE_ECHOR 0

struct arppkt
{
    uint16_t hw_type;
    uint16_t prot_type;
    uint8_t  hw_addr_len;
    uint8_t  prot_addr_len;
    uint16_t opcode;
    //Sender and target addr's are swapped when a request becomes a response
    uint8_t  snd_hw_addr[6]; //48-bit Ethernet address
    uint8_t  snd_ip_addr[4]; //32-bit IPv4 address
    uint8_t  tgt_hw_addr[6]; //48-bit Ethernet address
    uint8_t  tgt_ip_addr[4]; //32-bit IPv4 address
};
#define ARPPKT_SIZE 28
#define ARP_OPCODE_REQUEST 1
#define ARP_OPCODE_RESPONSE 2
#define ARP_HWTYPE_ETH 1

#endif
