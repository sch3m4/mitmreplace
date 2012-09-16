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

#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <main.h>
#include <forward.h>
#include <checksum.h>

#define IN_OUT	1
#define OUT_IN	2

static inline void store_client ( GHashTable *tabla , struct in_addr *ip , struct eth_addr *mac )
{
    struct host *entry = NULL;

    SAFE_CALLOC ( entry , 1 , sizeof ( struct host ) );

    memcpy ( (void*) & entry->ip , (void*) ip , sizeof ( struct in_addr ) );
    memcpy ( (void*) & entry->mac , (void*) mac , sizeof ( struct ether_addr ) );

    g_hash_table_insert ( tabla , ( void* ) & entry->ip , ( void* ) entry );

    return;
}

int ethernet_forward ( struct eth_header *eth , struct ipv4_header *ip , pfwconfig_t forward_data )
{
    struct host     *vic = 0;
    struct in_addr  *ipaux = 0;
    unsigned char   dir = 0;

    /* check if the source/destination IP belongs to our network */
    if ( ( ip->ip_dst.s_addr & forward_data->input.netmask.s_addr ) == forward_data->input.net.s_addr )
    {
        dir = OUT_IN;
        ipaux = &ip->ip_dst;

        if ( !g_hash_table_lookup ( forward_data->targets , ( const void* ) & ipaux->s_addr ) )
            return 0;
    }
    else if ( ( ip->ip_src.s_addr & forward_data->input.netmask.s_addr ) == forward_data->input.net.s_addr )
    {
        dir = IN_OUT;
        ipaux = &ip->ip_src;

        /* if this client is not known, store it */
        if ( !g_hash_table_lookup ( forward_data->targets , ( const void* ) & ipaux->s_addr ) )
            store_client ( forward_data->targets , ipaux , & eth->src );
    }
    else
    {
        fprintf ( stderr , "\n~>:-( Client asking for IP?: %s ---> " , inet_ntoa ( ip->ip_src ) );
        fprintf ( stderr , "%s" , inet_ntoa ( ip->ip_dst ) );
        return 0;
    }

    memcpy ( ( void* ) eth->src.addr , ( void* ) forward_data->output.mac.addr , sizeof ( struct eth_addr ) );

    if ( dir == IN_OUT )
        memcpy ( ( void* ) eth->dst.addr , ( void* ) forward_data->output.gw.addr , sizeof ( struct eth_addr ) );
    else if ( ( vic = ( struct host* ) g_hash_table_lookup ( forward_data->targets , ( const void* ) & ipaux->s_addr ) ) != NULL )
        memcpy ( ( void* ) eth->dst.addr , ( void* ) vic->mac.addr , sizeof ( struct eth_addr ) );
    else
        fprintf ( stderr , "\n[!] I've no data stored from %s :-(", inet_ntoa ( *ipaux ) );

    return 1;
}
