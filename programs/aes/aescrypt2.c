/*
 *  AES-256 file encryption program
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

#include "mbedtls/aes.h"
#include "mbedtls/base64.h"

#include "mbedtls/md.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#if !defined(_WIN32_WCE)
#include <io.h>
#endif
#else
#include <sys/types.h>
#include <unistd.h>
#endif

#define MODE_ENCRYPT    0
#define MODE_DECRYPT    1

#define USAGE   \
    "\n  aescrypt2 <mode> <input filename> <output filename> <key>\n" \
    "\n   <mode>: 0 = encrypt, 1 = decrypt\n" \
    "\n  example: aescrypt2 0 file file.aes hex:E76B2413958B00E193\n" \
    "\n"

#if !defined(MBEDTLS_AES_C) || !defined(MBEDTLS_SHA256_C) || \
    !defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_MD_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_AES_C and/or MBEDTLS_SHA256_C "
                    "and/or MBEDTLS_FS_IO and/or MBEDTLS_MD_C "
                    "not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    if( argc != 3 )
    {
        mbedtls_printf( "usage:  <key> <enc text>\n" );
        return -1;
    }
    if( strlen( argv[1] ) > 64 )
    {
        mbedtls_printf( " Input data larger than 64 characters.\n\n" );
        return -1;
    }
    if( strlen( argv[2] ) > 100 )
    {
        mbedtls_printf( " Input data larger than 100 characters.\n\n" );
        return -1;
    }
    

    char tmpArr[5];
    char * key = malloc(64);
    char * buffer = malloc(16);
    char * input = malloc(100);
    char * result = malloc(300);
    char * finalKey = malloc(32);
    unsigned char * result_b64 = malloc(300);
    int i = 0;
    int counter = 0;
    size_t olen = 0;


    bzero(input,100);
    tmpArr[0] = '0';
    tmpArr[1] = 'x';

    memcpy( key, argv[1], strlen( argv[1] ) );
    memcpy( input, argv[2], strlen( argv[2] ) );
    
    mbedtls_aes_context aes_cr;
    mbedtls_aes_context aes_dec;
    mbedtls_aes_init( &aes_cr );
    mbedtls_aes_init( &aes_dec );

    //crear nueva llave usando un hex en string y separando cada byte
    for(i = 2; i<64; i += 2){
        tmpArr[2] = key[i-2];
        tmpArr[3] = key[i-1];
        tmpArr[4] = '\0';
        finalKey[counter++] = strtol(tmpArr,NULL,0);
    }

    //crea llave aes con libreria, si falla retorna 
    if(mbedtls_aes_setkey_enc( &aes_cr, (const unsigned char *)finalKey, 256 )){
        printf("enc key error\n");
        free(key);
        free(result);
        free(result_b64);
        free(input);
        free(finalKey);
        free(buffer);
        return -1;
    }

    //cifra el texto
    (void)mbedtls_aes_crypt_ecb( &aes_cr, MBEDTLS_AES_ENCRYPT, (const unsigned char *)input, (unsigned char *)result );    
    mbedtls_base64_encode(result_b64, 300, &olen, (const unsigned char *)result, strlen(result));
    printf("AESENC_%s",result_b64);
    
    //FIN
    free(key);
    free(result);
    free(result_b64);
    free(input);
    free(finalKey);
    free(buffer);
    return 0;
}
#endif  //MBEDTLS_AES_C && MBEDTLS_SHA256_C && MBEDTLS_FS_IO 