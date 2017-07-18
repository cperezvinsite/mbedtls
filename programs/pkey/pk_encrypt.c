/*
 *  RSA simple data encryption program
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#endif

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_PK_PARSE_C) && \
    defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_FS_IO) && \
    defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <stdio.h>
#include <string.h>
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_PK_PARSE_C) ||  \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_FS_IO) || \
    !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_PK_PARSE_C and/or "
           "MBEDTLS_ENTROPY_C and/or MBEDTLS_FS_IO and/or "
           "MBEDTLS_CTR_DRBG_C not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    int ret;
    size_t i, olen = 0;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char input[1024];
    unsigned char buf[512];
    const char *pers = "mbedtls_pk_encrypt";
    if( argc != 2 )
    {
        mbedtls_printf( "usage: mbedtls_pk_sign <enc text>\n" );
        return -1;
    }
    ret = 1;
    mbedtls_ctr_drbg_init( &ctr_drbg );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret );
        goto exit;
    }

    fflush( stdout );

    mbedtls_pk_init( &pk );
    char * pkeyBuf = malloc(550);
    //char * to_crypt = malloc(100);
    char tmp;
    int iSize = 0;
    //printf("\npubkey");
    //READ PUBLIC KEY FROM INPUT
    bzero(pkeyBuf,550);
    while(1) {
        tmp =(char)getchar();
        if((tmp=='\n' && (iSize > 0 && pkeyBuf[iSize-1] == '\n')) || iSize>=550){
            break;
        } 
        pkeyBuf[iSize]=tmp;
        iSize++;
    }
    olen = strlen(pkeyBuf)+1;
    if( ( ret = mbedtls_pk_parse_public_key( &pk, (const unsigned char *)pkeyBuf, olen ) ) != 0 )
    {
        printf( "\nfailed! mbedtls_pk_parse_public_key returned %d\n", ret );
        //goto exit;
        return -1;
    }
    
    // printf("\ntext");
    // iSize = 0;
    // while(1) {
    //     tmp =(char)getchar();
    //     if(tmp=='\n'|| iSize>=100){
    //         break;
    //     } 
    //     to_crypt[iSize]=tmp;
    //     iSize++;
    // }
    if( strlen( argv[1] ) > 255 )
    {
        mbedtls_printf( " Input data larger than 100 characters.\n\n" );
        return -1;
    }
    memcpy( input, argv[1], strlen( argv[1] ) );
    //printf("\nthe text is \n%s\n",input);
    /*
     * Calculate the RSA encryption of the hash.
     */

    if( ( ret = mbedtls_pk_encrypt( &pk, input, strlen( argv[1] ),
                            buf, &olen, sizeof(buf),
                            mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n", -ret );
        goto exit;
    }

    /*
     * Write the signature into result-enc.txt
     */
    //SE QUITO EL LOG DE PK.C LINEA 304 //printf("\nmbedtls_pk_encrypt input: %s\n ilen: %d\n output: %s\n osize: %d\n",input, ilen, output, osize);
    printf("RESULTPKENCRYPT:");
    for( i = 0; i < olen; i++ )
        printf( "%02X%s", buf[i], ( i + 1 ) % 16 == 0 ? "\r\n" : " " );

exit:
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

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
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_PK_PARSE_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_FS_IO && MBEDTLS_CTR_DRBG_C */
