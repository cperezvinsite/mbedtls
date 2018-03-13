/*
 *  Public key-based signature creation program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_snprintf   snprintf
#define mbedtls_printf     printf
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) ||  \
    !defined(MBEDTLS_SHA256_C) || !defined(MBEDTLS_MD_C) || \
    !defined(MBEDTLS_PK_PARSE_C) || !defined(MBEDTLS_FS_IO) ||    \
    !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or "
           "MBEDTLS_SHA256_C and/or MBEDTLS_MD_C and/or "
           "MBEDTLS_PK_PARSE_C and/or MBEDTLS_FS_IO and/or "
           "MBEDTLS_CTR_DRBG_C not defined.\n");
    return( 0 );
}
#else

#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/base64.h"

#include <stdio.h>
#include <string.h>

int main( int argc, char *argv[] )
{
    int ret = 1;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char hash[32];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    char tmp;
    int iSize = 0;
    const char *pers = "mbedtls_pk_sign";
    char * pkeyBuf = malloc(2049);
    char * result_b64 = malloc(300);
    bzero(pkeyBuf,2049);
    size_t olen = 0;
    size_t olenB64 = 0;
    size_t olenSign = 0;

    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_pk_init( &pk );

    if( argc != 2 )
    {
        mbedtls_printf( "usage: mbedtls_pk_sign <id>\n" );
        goto exit;
    }

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret );
        goto exit;
    }

    
    //READ PRIVATE KEY FROM CONSOLE
    while(1) {
        tmp =(char)getchar();
        if((tmp=='\n' && (iSize > 0 && pkeyBuf[iSize-1] == '\n')) || iSize>=2049){
            break;
        } 
        pkeyBuf[iSize]=tmp;
        iSize++;
    }
    olen = strlen(pkeyBuf)+1;
    // PARSE PRIVATE KEY
    if( ( ret = mbedtls_pk_parse_key( &pk, (const unsigned char *)pkeyBuf, olen, (const unsigned char *)"", 0 ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_pk_parse_keyfile returned -0x%04x\n", -ret );
        goto exit;
    }
    */


    /*
     * Compute the SHA-256 hash of the input file,
     * then calculate the signature of the hash.
     */

    /*
    
    if( ( ret = mbedtls_md(mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), (const unsigned char *)argv[1], strlen(argv[1]), hash ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! Could not open or read %s\n\n", argv[1] );
        goto exit;
    }
    
    if( ( ret = mbedtls_pk_sign( &pk, MBEDTLS_MD_SHA256, hash, 0, buf, &olenSign, mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_pk_sign returned -0x%04x\n", -ret );
        goto exit;
    }

    mbedtls_base64_encode(result_b64, 300, &olenB64, (const char *)buf, olenSign);
    printf("%s",result_b64);
    
exit:
    mbedtls_pk_free( &pk );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    free(pkeyBuf);
    free(result_b64);

#if defined(MBEDTLS_ERROR_C)
    if( ret != 0 )
    {
        mbedtls_strerror( ret, (char *) buf, sizeof(buf) );
        mbedtls_printf( "  !  Last error was: %s\n", buf );
    }
#endif

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif *//* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_SHA256_C && MBEDTLS_PK_PARSE_C && MBEDTLS_FS_IO &&
          MBEDTLS_CTR_DRBG_C */


#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha256.h"
#include "mbedtls/base64.h"

#include <stdlib.h>
#include <stdio.h>
int main( int argc, char *argv[] )
{
    if( argc != 3 )
    {
        printf( "usage: mbedtls_pk_sign <pv_key_addr> <message>\n" );
        return -1;
    }
    const char * pr_key_addr = argv[1];
    const char * msg_to_sign = argv[2];
    char * ptr = malloc(250);
    char * ptr_elliptic = malloc(250);
    int result;
    FILE * fp;
    char c;
    fp = fopen(pr_key_addr, "r");
    int counter = 0;
    if (fp) {
        while ((c = getc(fp)) != EOF){
            ptr[counter] = c;
            counter++;
        }
        fclose(fp);
        ptr[counter] = '\0';
    }
    result = elliptic_c_sign(ptr,msg_to_sign,ptr_elliptic);
    printf("%s\n",ptr_elliptic);
    free(ptr);
    free(ptr_elliptic);
    return 0;
}
void helpers_free_ptr(void ** ptr){
    if(*ptr != NULL){
        free(*ptr);
        *ptr = NULL;
    }
}

int elliptic_c_init(mbedtls_pk_context *pk, const char* pr_key,
                mbedtls_entropy_context *entropy, mbedtls_ctr_drbg_context *ctr_drbg){
    int olen;
    int ret;

    mbedtls_pk_init( pk );    
    mbedtls_ctr_drbg_init( ctr_drbg );              
    mbedtls_entropy_init( entropy );
    
    olen = strlen(pr_key)+1;
    

    if( ( ret = mbedtls_pk_parse_key( pk, (const unsigned char *)pr_key, olen, (const unsigned char *)"", 0 ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_parse_keyfile returned ------ -0x%04x\n", -ret );
        return -1;
    }

    return 0;

}

int elliptic_c_sign(const char *pr_key, const char *msg_to_sign, char *signed_msg){
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    size_t olen;// strlen(pr_key);
    size_t olen2;
    int ret;

    char * hashed_msg = NULL;
    char * buf = NULL;
    ret = -1;
    if(elliptic_c_init(&pk, pr_key, &entropy, &ctr_drbg)!=0)
        goto exit;        

        
    hashed_msg = malloc(40);
    bzero(hashed_msg, 40);

    if( ( ret = mbedtls_md(mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), (const unsigned char*)msg_to_sign, strlen(msg_to_sign), (unsigned        char*)hashed_msg ) ) != 0 )
    {
        printf("failed\n  ! Could not read %s\n\n", msg_to_sign );
        ret = -1;
        goto exit;
    }
    
    buf = malloc(200);
    if( ( ret = mbedtls_pk_sign( &pk, MBEDTLS_MD_SHA256,(unsigned char*)hashed_msg, 0,(unsigned char*)buf, &olen, mbedtls_ctr_drbg_random,      &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_sign returned -0x%04x\n", -ret );
        ret = -1;
        goto exit;
    }
    
    mbedtls_base64_encode((unsigned char*)signed_msg, 119, &olen2, (const unsigned char *)buf, olen);
    
    ret = 0;

    exit:
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_pk_free( &pk );
    helpers_free_ptr((void**)&hashed_msg);
    helpers_free_ptr((void**)&buf);
    return ret;

}


