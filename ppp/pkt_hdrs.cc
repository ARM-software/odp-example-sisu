/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#if defined(__aarch64__)
#include <arm_neon.h>
#define VECTOR_CSUM
#endif

#include "compiler.h"
#include "pkt_hdrs.h"

#ifdef VECTOR_CSUM
// Return checksum in memory order (which may be network order)
uint16_t pkt_chk_sum(const void *ptr, uint32_t nbytes)
{
	const uint16_t *hptr = (const uint16_t *)ptr;
	uint32_t i;
	uint32_t nquads = (nbytes >> 3), nhalfs = (nbytes & 0x06) >> 1, trailing = (nbytes & 0x01);
	uint32x4_t vector_sum = {0,0,0,0};
	uint32_t sum = 0;

	//printf("nquads: %u, nhalfs: %u, trailing: %u\n", nquads, nhalfs, trailing);

	for (i = 0; i < nquads; i++) {
		uint16x4_t tmp = vld1_u16(hptr);
		vector_sum = vaddw_u16(vector_sum, tmp);
		hptr += 4;
	}
	sum = vaddvq_u32(vector_sum);

	// Add any trailing halfs
	for (i = 0; i < nhalfs; i++) {
		sum += *hptr++;
	}

	// Add any trailing odd byte
	if (trailing)
		sum += (*(uint8_t *)hptr);

	// Fold 32-bit sum to 16 bits
	do {
		sum = (sum & 0xffff) + (sum >> 16);
	} while ((sum >> 16) != 0);

	return (uint16_t)sum;
}
#else
// Return checksum in memory order (which may be network order)
uint16_t pkt_chk_sum(const void *ptr, uint32_t nbytes)
{
	const uint16_t *hptr = (const uint16_t *)ptr;
	uint32_t nhalfs;
	uint32_t sum = 0;

	// Sum all halfwords, assume misaligned accesses are handled in HW
	for (nhalfs = nbytes >> 1; nhalfs != 0; nhalfs--) {
		sum += *hptr++;
	}

	// Add any trailing odd byte
	if ((nbytes & 0x01) != 0) {
		sum += *(uint8_t *)hptr;
	}

	// Fold 32-bit sum to 16 bits
	do {
		sum = (sum & 0xffff) + (sum >> 16);
	} while ((sum >> 16) != 0);

	return (uint16_t)sum;
}
#endif

uint16_t ipv4hdr::checksum() const
{
    return ~pkt_chk_sum(this, hdr_size());
}

uint16_t udphdr::checksum(const unsigned char *data) const
{
    const uint16_t *udphdr = (const uint16_t *)this;
    uint32_t datalen = ntohs(length) - hdr_size();
    uint32_t sum = (IPPROTO_UDP << 8) + length;
    uint16_t hsum;
    int i;

    //Start at a negative index since IPv4 src/dst addresses precede UDP hdr
    for (i = -4; i < (int)(sizeof(struct udphdr) / sizeof(uint16_t)); i++)
    {
	sum += udphdr[i];
    }
    //Compute and add the checksum of the user data
    sum += pkt_chk_sum(data, datalen);
    //Fold 32-bit sum to 16 bits
    do//Do first fold speculatively
    {
	sum = (sum & 0xffff) + (sum >> 16);
    }
    while ((sum >> 16) != 0);
    //Finally one-complement it
    hsum = ~sum;
    //UDP doesn't like a positive zero checksum, that means no checksum
    if (hsum == 0)
    {
	//A zero checksum is instead expressed as negative zero
	hsum = 0xffff;
    }
    return hsum;
}

uint16_t tcphdr::checksum(const unsigned char *data, uint32_t datalen) const
{
    const uint16_t *tcphdr = (const uint16_t *)this;
    uint32_t tcp_len = datalen + hdr_size();
    uint32_t sum = (IPPROTO_TCP << 8) + htons(tcp_len);
    int i;

    //Start at a negative index since IPv4 src/dst addresses precede TCP hdr
    for (i = -4; i < (int)(sizeof(struct tcphdr) / sizeof(uint16_t)); i++)
    {
	sum += tcphdr[i];
    }
    //Compute and add the checksum of the user data
    sum += pkt_chk_sum(data, datalen);
    //Fold 32-bit sum to 16 bits
    while ((sum >> 16) != 0)
    {
	sum = (sum & 0xffff) + (sum >> 16);
    }
    //Return the ones complement of the (ones-complement) sum
    return ~sum;
}

struct iphdr_packed
{
	uint32_t w0, w1, w2, w3, w4;
}  __attribute__ ((__packed__));

static void iphdr_copy(void *__restrict _dst, const void *__restrict _src) __attribute((noinline));
static void iphdr_copy(void *__restrict _dst, const void *__restrict _src)
{
    unsigned nwords = 0xF & *(const uint8_t *)_src;
    if (unlikely(nwords > 5))
    {
	uint32_t *__restrict dst = (uint32_t *)_dst;
	const uint32_t *__restrict src = (const uint32_t *)_src;
	switch (nwords)
	{
	    case 15 :
		dst[14] = src[14];
	    case 14 :
		dst[13] = src[13];
	    case 13 :
		dst[12] = src[12];
	    case 12 :
		dst[11] = src[11];
	    case 11 :
		dst[10] = src[10];
	    case 10 :
		dst[ 9] = src[ 9];
	    case  9 :
		dst[ 8] = src[ 8];
	    case  8 :
		dst[ 7] = src[ 7];
	    case  7 :
		dst[ 6] = src[ 6];
	    case  6 :
		dst[ 5] = src[ 5];
	}
    }
    //Normal case
    //Must use packed struct to force compiler not to use LDM/STM
    iphdr_packed *__restrict pdst = (iphdr_packed *)_dst;
    const iphdr_packed *__restrict psrc = (const iphdr_packed *)_src;
    *pdst = *psrc;
}

void ipv4hdr::copy_to(void *dst) const
{
    iphdr_copy(dst, this);
}

void ipv4hdr::copy_from(const void *src)
{
    iphdr_copy(this, src);
}
