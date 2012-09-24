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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <net/if.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <glib.h>

#include <main.h>
#include <forward.h>
#include <checksum.h>
#include <patterns.h>
#include <replace.h>

/*********************************/
/** [   DATOS DE LA CAPTURA   ] **/
/*********************************/
/* tam. de la captura */
#ifndef SNAPLEN
# define SNAPLEN	65535
#endif
/* timeout de la captura */
#ifndef CAP_TIMEOUT
# define CAP_TIMEOUT	10
#endif

/*********************************/
/** [ / DATOS DE LA CAPTURA   ] **/
/*********************************/

fwconfig_t forward_data;

void sig ( int s )
{
    if ( forward_data.iniface != 0 )
    {
        pcap_close ( forward_data.iniface );
        /* different interfaces? */
        if ( ! forward_data.single )
            pcap_close ( forward_data.outiface );
    }

    if ( forward_data.targets != NULL )
        g_hash_table_destroy ( forward_data.targets );

    free_patterns( forward_data.patterns );

    SAFE_FREE ( forward_data.ingw );
    SAFE_FREE ( forward_data.inname );
    SAFE_FREE ( forward_data.outgw );
    SAFE_FREE ( forward_data.outname );
    SAFE_FREE ( forward_data.path );
    SAFE_FREE ( forward_data.infilter );
    SAFE_FREE ( forward_data.outfilter );

    fprintf ( stderr , "\n" );

    exit ( s );
}

/* obtiene la mac,ip y mascara de una interface (si, se puede obtener con pcap_lookupnet pero este ya lo tenia hecho xD) */
void get_iface_data ( char *iface , pifacedata_t data , unsigned short show )
{
    int             s;
    struct ifreq    ifr;

    s = socket ( AF_INET, SOCK_STREAM, 0 );
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy ( ifr.ifr_name, iface , IFNAMSIZ - 1 );

    /* get mac address */
    ioctl ( s, SIOCGIFHWADDR, &ifr );
    memcpy ( ( void* ) data->mac.addr , ifr.ifr_hwaddr.sa_data , sizeof ( struct eth_addr ) );

    /* get network mask */
    ioctl ( s, SIOCGIFNETMASK, &ifr );
    data->netmask = ( ( struct sockaddr_in * ) & ifr.ifr_addr )->sin_addr;

    /* get IP */
    ioctl ( s, SIOCGIFADDR, &ifr );
    data->ip = ( ( struct sockaddr_in * ) & ifr.ifr_addr )->sin_addr;

    /* get network */
    data->net.s_addr = (data->ip.s_addr & data->netmask.s_addr);

    /* get broadcast */
    data->ipbcast.s_addr = data->net.s_addr | ~(data->netmask.s_addr);

    if ( show )
    {
        fprintf ( stderr , "\n\t+ MAC:.......%s" , ether_ntoa ( ( const struct ether_addr* ) & data->mac ) );
        fprintf ( stderr , "\n\t+ IP:........%s" , inet_ntoa ( data->ip ) );
        fprintf ( stderr , "\n\t+ Net:.......%s" , inet_ntoa ( data->net ) );
        fprintf ( stderr , "\n\t+ Netmask:...%s" , inet_ntoa ( data->netmask ) );
        fprintf ( stderr , "\n\t+ Broadcast:.%s" , inet_ntoa ( data->ipbcast ) );
        fprintf ( stderr , "\n\t+ Gateway:...%s\n" , ether_ntoa ( ( const struct ether_addr* ) & data->gw ) );
    }

    close ( s );

    return;
}

void pkt_handler ( unsigned char *user , const struct pcap_pkthdr *hdr , const unsigned char *pkt )
{
    struct eth_header	*eth;           /* Ethernet header */
    struct ipv4_header	*ip;		    /* IP Header */
    struct tcp_header	*tcp;		    /* cabecera TCP */
    size_t		        ips;		    /* IP Header length */
    size_t		        tcps;		    /* TCP Header length */
    unsigned char       *payload;	    /* payload */
    size_t              size_payload;   /* payload size */
    size_t              bytes;
    unsigned char       modified;       /* to know if the payload has been modified */
    char				*alias;			/* pattern alias */

    /* get ethernet header */
    eth = ( struct eth_header * ) pkt;
    if ( ntohs ( eth->type ) != ETHERTYPE_IP )
        return;

    /* get IP header */
    ip = ( struct ipv4_header * ) ( pkt + sizeof ( struct eth_header ) );
    if ( ( ips = IP_HL ( ip ) * 4 ) < sizeof ( struct ipv4_header ) )
        return;

    /* if we cannot do ethernet forwarding */
    if ( ! ethernet_forward ( eth , ip , &forward_data ) )
        return;

    /* we need the protocol to be TCP */
    if ( ip->ip_proto != IPPROTO_TCP )
        goto send_packet;

    /* get TCP header */
    tcp = ( struct tcp_header * ) ( pkt + sizeof ( struct eth_header ) + ips );
    if ( ( tcps = TH_OFF ( tcp ) * 4 ) < sizeof ( struct tcp_header ) )
        goto send_packet;

    /* get payload */
    if ( ! ( ( size_payload = ntohs ( ip->ip_len ) - ( ips + tcps ) ) > 0 ) )
        goto send_packet;

    /* localizamos el payload y la cadena a reemplazar (si no se encuentra salimos) */
    payload = ( unsigned char * ) ( pkt + sizeof ( struct eth_header ) + ips + tcps );

    bytes = 0;
    alias = 0;
    if ( ! ( modified = replace_payload ( &forward_data , payload , size_payload , &bytes , &alias ) ) )
        goto send_packet;

    /* recalculates the TCP checksum */
    tcp->th_sum = tcp_checksum ( ip->ip_proto , ( char* ) tcp , size_payload + tcps , ip->ip_src , ip->ip_dst , tcp->th_sum );

    /* show packet direction */
    fprintf ( stderr , "\n[ %s:%d ---> " , inet_ntoa ( ip->ip_src ) , ntohs ( tcp->th_sport ) );
    fprintf ( stderr , "%s:%d ] " , inet_ntoa ( ip->ip_dst ) , ntohs ( tcp->th_dport ) );
    fprintf ( stderr , "---> OK! (%d bytes | SEQ: %d ACK: %d LEN: %d Checksum: 0x%04x) - %s" , bytes , ntohs ( tcp->th_seq ) , ntohs ( tcp->th_ack ) , size_payload , ntohs ( tcp->th_sum ) , !alias?"N/A":alias);

send_packet:
    if ( pcap_inject ( forward_data.outiface , pkt , hdr->caplen ) < 0 )
        fprintf ( stderr , "\n[!] Cannot reinject packet: %s" , pcap_geterr(forward_data.outiface) );

    return;
}

void usage ( char *prog )
{
    fprintf ( stderr , "Usage: %s parameters\n" , prog );
    fprintf ( stderr , "\n[+] Parameters");
    fprintf ( stderr , "\n\t-i | --input <iface> ----------> Interface to read packets from");
    fprintf ( stderr , "\n\t-o | --output <iface> ---------> Interface to write packets to");
    fprintf ( stderr , "\n\t-I | --ingw <mac> -------------> MAC Address of the legacy gw of input interface");
    fprintf ( stderr , "\n\t-O | --outgw <mac> ------------> MAC Address of the legacy gw of output interface");
    fprintf ( stderr , "\n\t-p | --patterns <path> --------> Path to XML file containing match/replace patterns");
    fprintf ( stderr , "\n\t-P | --promisc ----------------> Enable promiscous mode");
    fprintf ( stderr , "\n\t-f | --input-filter <filter> --> Capture filter");
    fprintf ( stderr , "\n\t-F | --output-filter <filter> -> Capture filter\n\n");

    return;
}

unsigned short parse_args ( int argc , char *argv[] )
{
    char                    o = 0;
    const char              schema[] = "i:o:I:O:p:Pf:F:";
    int                     i = 0;
    unsigned short          ret = 0;
    static struct option    opc[] =
    {
        {"input", 1, 0, 'i'},
        {"output" , 1 , 0 , 'o'},
        {"ingw", 1 , 0 , 'I'},
        {"outgw", 1 , 0 , 'O'},
        {"patterns",1,0,'p'},
        {"promisc",0,0,'P'},
        {"input-filter",1,0,'f'},
        {"output-filter",1,0,'F'},
        {0, 0, 0, 0}
    };

    while ( !ret && ( o = getopt_long ( argc, argv, schema , opc, &i ) ) > 0 )
    {
        switch ( o )
        {
        case 'i':
            forward_data.inname = strdup ( optarg );
            break;

        case 'o':
            forward_data.outname = strdup ( optarg );
            break;

        case 'I':
            forward_data.ingw = strdup(optarg);
            break;

        case 'O':
            forward_data.outgw = strdup(optarg);
            break;

        case 'p':
            forward_data.path = strdup(optarg);
            break;

        case 'P':
            forward_data.promisc = 1;
            break;

        case 'f':
            forward_data.infilter = strdup(optarg);
            break;

        case 'F':
            forward_data.outfilter = strdup(optarg);
            break;

        default:
            ret++;
            break;
        }
    }

    return ret;
}

int main ( int argc, char* argv[] )
{
    int 		        mib[3] = { CTL_NET , NET_IPV4 , NET_IPV4_FORWARD };
    int 		        ipf_val = 0;
    char                errbuf[PCAP_ERRBUF_SIZE];
    unsigned int        rval = 0;
    struct bpf_program  fp;

    fprintf ( stderr , "+-----------------------------------+" );
    fprintf ( stderr , "\n|      MiTM Ethernet Forwarder      |" );
    fprintf ( stderr , "\n|                 &                 |");
    fprintf ( stderr , "\n| TCP/IPv4 Payload Replacement Tool |" );
    fprintf ( stderr , "\n|               %s              |" , VERSION );
    fprintf ( stderr , "\n|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|" );
    fprintf ( stderr , "\n|   Chema Garcia (a.k.a. sch3m4)    |" );
    fprintf ( stderr , "\n|        http://safetybits.net      |" );
    fprintf ( stderr , "\n|        chema@safetybits.net       |" );
    fprintf ( stderr , "\n+-----------------------------------+" );
    fprintf ( stderr , "\n\n" );

    memset ( ( void* ) &forward_data , 0 , sizeof ( forward_data ) );

    if ( parse_args(argc,argv) || !forward_data.path || !forward_data.ingw || !forward_data.inname )
    {
        usage(argv[0]);
        return -1;
    }

    /* parse patterns file */
    fprintf ( stderr , "\n[+] Parsing patterns file...");
    if ( (rval = load_patterns( (void*)&forward_data ) ) )
    {
        fprintf ( stderr , "ERROR: %s\n" , GET_PATTERNS_ERRSTR(rval) );
        sig(-2);
    }
    fprintf ( stderr , "OK\n\t- %d Patterns loaded\n" , forward_data.patterns_count );

    /* check if we're going to use only one interface */
    if ( ! forward_data.outname || !strcmp ( forward_data.inname , forward_data.outname ) )
    {
        forward_data.single = 1;
        SAFE_FREE ( forward_data.outgw );
        SAFE_FREE ( forward_data.outname );

        forward_data.outgw = strdup ( forward_data.ingw );
        forward_data.outname = strdup ( forward_data.inname );
    }

    if ( getuid() != 0 )
    {
        fprintf ( stderr , "\n[!] You must be root!\n\n" );
        return -3;
    }

    fprintf ( stderr , "\n[+] Disabling IPv4 Forwarding......." );

    if ( ! ( sysctl ( mib, sizeof ( mib ) / sizeof ( *mib ), 0, 0, &ipf_val, sizeof(ipf_val) ) < 0 ) )
        fprintf ( stderr, "OK!" );
    else
        fprintf ( stderr, "ERROR: %s (You shuld to manually disable it)" , strerror(errno) );

    /* instalamos el manejador de señales */
    signal ( SIGINT , &sig );
    signal ( SIGTERM , &sig );

    /* datos del gw real */
    ether_aton_r ( forward_data.ingw , ( struct ether_addr* ) &forward_data.input.gw );
    ether_aton_r ( forward_data.outgw , ( struct ether_addr* ) &forward_data.output.gw );

    fprintf ( stderr , "\n\n[+] Loading input interface %s....", forward_data.inname );
    if ( ( forward_data.iniface = pcap_open_live ( forward_data.inname , SNAPLEN, forward_data.promisc, CAP_TIMEOUT * 1000 , errbuf ) ) == NULL )
    {
        fprintf ( stderr, "ERROR: %s" , errbuf );
        sig(-4);
    }
    else
        fprintf ( stderr , "OK" );

    get_iface_data ( forward_data.inname , & forward_data.input , 1 );

    /* if we're running in single mode, do not loads output interface (use input as output) */
    if ( ! forward_data.single )
    {
        fprintf ( stderr , "\n[+] Loading output interface %s...", forward_data.outname );
        if ( ( forward_data.outiface = pcap_open_live ( forward_data.outname , SNAPLEN, forward_data.promisc, CAP_TIMEOUT, errbuf ) ) == NULL )
        {
            fprintf ( stderr, "ERROR: %s" , errbuf );
            sig(-5);
        }
        else
            fprintf ( stderr , "OK" );
    }else{
        forward_data.outiface = forward_data.iniface;
        fprintf ( stderr , "\n[+] Using %s as output interface" , forward_data.outname );
    }

    get_iface_data ( forward_data.outname , &forward_data.output , 0 );

    /* apply pcap filter to not to capture our own packets */
    if ( !forward_data.infilter )
        asprintf ( &forward_data.infilter , "host not %s" , inet_ntoa ( forward_data.input.ip ) );
    fprintf ( stderr , "\n\n[+] Setting input filter: \"%s\"..." , forward_data.infilter );
    if ( pcap_compile ( forward_data.iniface , &fp , forward_data.infilter , 0 , ( unsigned long ) forward_data.input.ip.s_addr ) < 0  || pcap_setfilter ( forward_data.iniface , &fp ) < 0 )
    {
        fprintf ( stderr, "ERROR: %s" , pcap_geterr ( forward_data.iniface ) );
        sig ( -6 );
    }
    else
        fprintf ( stderr , "OK" );
    pcap_freecode ( &fp );

    if ( !forward_data.single )
    {
        if ( !forward_data.outfilter )
            asprintf ( &forward_data.outfilter , "host not %s" , inet_ntoa ( forward_data.output.ip ) );
        fprintf ( stderr , "\n\n[+] Setting output filter: \"%s\"..." , forward_data.outfilter );
        if ( pcap_compile ( forward_data.outiface , &fp , forward_data.outfilter , 0 , ( unsigned long ) forward_data.output.ip.s_addr ) < 0  || pcap_setfilter ( forward_data.outiface , &fp ) < 0 )
        {
            fprintf ( stderr, "ERROR: %s" , pcap_geterr ( forward_data.outiface ) );
            sig ( -6 );
        }
        else
            fprintf ( stderr , "OK" );
        pcap_freecode ( &fp );
    }else
        fprintf ( stderr , "\n[+] Using input filter as output filter");

    fprintf ( stderr , "\n\n[---------------------------------]\n\n");

    /* creamos la tabla hash */
    forward_data.targets = g_hash_table_new_full ( g_int_hash, g_int_equal, NULL, g_free );
    if ( ( pcap_loop ( forward_data.iniface, -1, pkt_handler, NULL ) ) < 0 )
    {
        fprintf ( stderr, "\n\n[!] Error pcap_loop: %s\n" , pcap_geterr ( forward_data.iniface ) );
        sig(-7);
    }

    sig ( 0 );

    /* dummy return */
    return 0;
}

/* SMG! */
