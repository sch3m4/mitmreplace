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
#include <libxml/xmlreader.h>

#include <main.h>
#include <patterns.h>
#include <forward.h>

void free_patterns ( ppattern_t patterns )
{
    ppattern_t aux;

    while ( (aux = patterns) != 0 )
    {
        patterns = aux->next;

        SAFE_FREE ( aux->match );
        SAFE_FREE ( aux->replace );
        SAFE_FREE ( aux );
    }

    return;
}

static void add_pattern ( ppattern_t *patterns , ppattern_t node )
{
    node->next = *patterns;
    *patterns = node;
}

static inline void hex_string ( char *src , unsigned char **dst , size_t *olen )
{
    size_t  i;
    size_t  len = strlen(src);
    unsigned char *data;

    *olen = len /2;
    data = (unsigned char*) calloc ( *olen , sizeof ( unsigned char ) );
    for ( i = 0 ; i < len ; i += 2 )
        sscanf(&src[i],"%02x", (unsigned int*)&data[i - i/2] );
    *dst = data;
    return;
}

static size_t parse_nodes (xmlDocPtr doc, xmlNodePtr cur , ppattern_t *patterns )
{
    xmlChar         *match,*mbin,*replace,*rbin;
    ppattern_t      node;
    size_t          ret = 0;

    cur = cur->xmlChildrenNode;
    while (cur != NULL)
    {
        if ( (!xmlStrcmp(cur->name, (const xmlChar *)"pattern") ) )
        {
            match = xmlGetProp(cur,(const xmlChar*) "match");
            mbin = xmlGetProp(cur,(const xmlChar*) "match_bin" );
            replace = xmlGetProp(cur,(const xmlChar*) "replace");
            rbin = xmlGetProp(cur,(const xmlChar*) "replace_bin");

            if ( !match || !replace || !strlen((char*)match) || !strlen((char*)replace) )
                goto tofree;

            SAFE_CALLOC ( node , 1 , sizeof ( pattern_t ) );

            if ( mbin != 0 && *mbin == '1' )
            {
                node->flags |= MATCH_IS_BINARY;
                hex_string ( (char*) match , &node->match , &node->mlen );
            }else{
                node->match = (unsigned char*) strdup ( (char*) match );
                node->mlen = strlen((const char*)node->match);
            }

            if ( rbin != 0 && *rbin == '1' )
            {
                node->flags |= REPLACE_IS_BINARY;
                hex_string ( (char*) replace , &node->replace , &node->rlen );
            }else{
                node->replace = (unsigned char*) strdup ( (char*)replace );
                node->rlen = strlen((const char*)node->replace);
            }

            add_pattern ( patterns , node );
            ret++;

tofree:
            xmlFree(match);
            xmlFree(replace);
            xmlFree(mbin);
            xmlFree(rbin);
        }
        cur = cur->next;
    }

    return ret;
}

unsigned short load_patterns ( void *p )
{
    int ret = 0;
    xmlDocPtr doc;
    xmlNodePtr cur;
    pfwconfig_t data = (pfwconfig_t)p;

    LIBXML_TEST_VERSION

    if ( (doc = xmlParseFile(data->path)) == NULL )
        return 1;

    if ( (cur = xmlDocGetRootElement(doc)) == NULL)
    {
        ret = 2;
        goto badret;
    }

    if ( xmlStrcmp(cur->name, (const xmlChar *) "config" ) )
    {
        ret = 3;
        goto badret;
    }

    data->patterns_count = parse_nodes (doc, cur , &data->patterns );

badret:
    xmlFreeDoc(doc);

    xmlCleanupParser();

    if ( !ret && !data->patterns )
        ret = 4;

    return ret;
}
