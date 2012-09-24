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
#include <pthread.h>

#include <main.h>
#include <patterns.h>
#include <replace.h>

/* I know, so dirty... */
unsigned char   *payload;
size_t          size_payload;
size_t          *bytes;
char			*alias;

static void *replace_thread ( void *p )
{
    size_t          i,len;
    ppattern_t      ptern = (ppattern_t)p;

    /* look for the match string */
    for ( i = 0 ; i < size_payload; i++ )
    {
        if ( size_payload - i < ptern->mlen )
            break;

        if ( !memcmp ( payload + i , (void*)ptern->match , ptern->mlen ) )
        {
            len = size_payload - i < ptern->rlen ? ptern->mlen : ptern->rlen;
            memcpy ( payload + i , ptern->replace , len );
            i += len;
            *bytes += len;
            alias = ptern->alias;
        }
    }

    pthread_exit(0);
    /* dummy return */
    return 0;
}

unsigned short replace_payload ( pfwconfig_t data , unsigned char *p , size_t sp , size_t *b, char *alias )
{
    pthread_t   *tids;
    ppattern_t  ptern;
    size_t      i;

    /* set global data */
    *b = 0;
    payload = p;
    size_payload = sp;
    bytes = b;

    SAFE_CALLOC ( tids , data->patterns_count , sizeof ( pthread_t ) );

    /* for each pattern */
    i = 0;
    for ( ptern = data->patterns ; ptern != 0 ; ptern = ptern->next )
    {
        /* creates a new thread */
        pthread_create(&tids[i],0,replace_thread,(void*)ptern);
        i++;
    }

    /* wait for all threads */
    for ( i = 0 ; i < data->patterns_count ; i++ )
        pthread_join ( tids[i] , 0 );

    SAFE_FREE ( tids );

    return *b > 0?1:0;
}
