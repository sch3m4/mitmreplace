/*********************************************************************************
 * Copyright (c) 2012, Chema Garcia                                              *
 * All rights reserved.                                                          *
 *                                                                               *
 * Redistribution and use in source and binary forms, with or                    *
 * without modification, are permitted provided that the following               *
 * conditions are met:                                                           *
 *                                                                               *
 *    * Redistributions of source code must retain the above                     *
 *      copyright notice, this list of conditions and the following              *
 *      disclaimer.                                                              *
 *                                                                               *
 *    * Redistributions in binary form must reproduce the above                  *
 *      copyright notice, this list of conditions and the following              *
 *      disclaimer in the documentation and/or other materials provided          *
 *      with the distribution.                                                   *
 *                                                                               *
 *    * Neither the name of the SafetyBits nor the names of its contributors may *
 *      be used to endorse or promote products derived from this software        *
 *      without specific prior written permission.                               *
 *                                                                               *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"   *
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE     *
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE    *
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE     *
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR           *
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF          *
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS      *
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN       *
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)       *
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE    *
 * POSSIBILITY OF SUCH DAMAGE.                                                   *
 *********************************************************************************/

#ifndef __FORWARD_H__
# define __FORWARD_H__

#include <netinet/in.h>
#include <netinet/ether.h>
#include <pcap.h>
#include <glib.h>

#include <patterns.h>

/* direccion ethernet */
#define ETH_ALEN	6
struct eth_addr
{
    unsigned char   addr[ETH_ALEN];
};

/* cabecera ethernet */
struct eth_header
{
    struct eth_addr dst;
    struct eth_addr src;
    unsigned short  type;
};

/* cabecera IPv4 */
struct ipv4_header
{
    unsigned char   ip_vhl;     /* version << 4 | header length >> 2 */
    unsigned char   ip_tos;     /* type of service */
    unsigned short  ip_len;     /* total length */
    unsigned short  ip_id;      /* identification */
    unsigned short  ip_off;     /* fragment offset field */
    unsigned char   ip_ttl;     /* time to live */
    unsigned char   ip_proto;   /* protocol */
    unsigned short  ip_sum;     /* checksum */
    struct in_addr  ip_src;     /* source address */
    struct in_addr  ip_dst;     /* destination address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)

/* cabecera TCP */
struct tcp_header
{
    unsigned short	th_sport; 	/* source port */
    unsigned short 	th_dport;	/* destination port */
    unsigned int 	th_seq;  	/* sequence number */
    unsigned int 	th_ack;   	/* acknowledgement number */
    unsigned char  	th_offx2;   /* data offset, rsvd */
    unsigned char  	th_flags;
    unsigned short 	th_win;     /* window */
    unsigned short 	th_sum;     /* checksum */
    unsigned short 	th_urp;     /* urgent pointer */
};
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)

struct host
{
    struct in_addr  ip;
    struct eth_addr mac;
};

typedef struct
{
    struct eth_addr gw;         /* legacy gateway */
    struct eth_addr mac;        /* mac */
    struct in_addr  ip;         /* ip */
    struct in_addr  netmask;    /* mascara de red */
    struct in_addr  net;        /* red */
    struct in_addr  ipbcast;    /* broadcast */
} ifacedata_t , *pifacedata_t;

typedef struct
{
    char    *inname;            /* input interface name */
    char    *outname;           /* output interface name */

    unsigned short  promisc;    /* enables capturing in promisc. mode */
    char            *infilter;  /* capture filter */
    char            *outfilter; /* capture filter */

    char    *ingw;              /* legacy gateway of input interface */
    char    *outgw;             /* legacy gateway of output interface */

    char    *path;              /* path to the XML file containing the patterns */

    unsigned char   single;     /* work on a single interface? */

    pcap_t  *iniface;           /* input interface pcap handler */
    pcap_t  *outiface;          /* output interface pcap handler */

    GHashTable  *targets;       /* hash table of clients */

    ifacedata_t input;          /* input interface settings */
    ifacedata_t output;         /* output interface settings */

    ppattern_t  patterns;       /* stored patterns from XML file */
    size_t      patterns_count; /* amount of patterns stored */

} fwconfig_t , *pfwconfig_t;

int ethernet_forward ( struct eth_header *eth , struct ipv4_header *ip , pfwconfig_t forward_data );

#endif /* __FORWARD_H__ */
