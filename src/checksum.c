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
#include <netinet/in.h>

#include <main.h>
#include <checksum.h>

struct pseudoh
{
    struct in_addr 	source_address;
    struct in_addr 	dest_address;
    unsigned char 	place_holder;
    unsigned char 	protocol;
    unsigned short 	length;
};

static inline unsigned short inet_checksum ( void *data, int len, unsigned short prevsum )
{
    unsigned short          *p = data;
    register unsigned int   checksum = prevsum ^ 0xFFFF;

    while ( len >= 2 )
    {
        checksum += *p++;
        len -= 2;
    }

    if ( len )
        checksum += * ( unsigned char * ) p;

    while ( checksum >> 16 )
        checksum = ( checksum & 0xFFFF ) + ( checksum >> 16 );

    return ( ~checksum );
}

/* funcion para recalcular el checksum TCP */
unsigned short tcp_checksum ( unsigned char proto, char *packet, int length, struct in_addr source_address, struct in_addr dest_address, unsigned short prevsum )
{
    struct pseudoh	pseudohdr;
    unsigned char   *pseudo_packet;
    unsigned short  cksum;

    pseudohdr.protocol = proto;
    pseudohdr.length = htons ( length );
    pseudohdr.place_holder = 0;
    pseudohdr.source_address = source_address;
    pseudohdr.dest_address = dest_address;

    SAFE_CALLOC ( pseudo_packet , 1 , sizeof ( pseudohdr ) + length );

    memcpy ( pseudo_packet, &pseudohdr, sizeof ( pseudohdr ) );
    memcpy ( ( pseudo_packet + sizeof ( pseudohdr ) ), packet, length );

    cksum = inet_checksum ( ( unsigned short * ) pseudo_packet, ( length + sizeof ( pseudohdr ) ), prevsum );

    SAFE_FREE ( pseudo_packet );

    return cksum;
}
