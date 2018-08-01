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
    int c;
    fp = fopen(pr_key_addr, "r");
    int counter = 0;
    if (fp) {
        c = getc(fp);
        while(c != EOF){
            ptr[counter] = (char)c;
            counter++;
            c=getc(fp);
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