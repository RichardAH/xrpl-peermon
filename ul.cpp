#include <sodium.h>

#include <iostream>
#include <string_view>
#include <string>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h> 

#include <stdio.h>
#include <secp256k1.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <libbase58.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "peers.h"
#include "ripple.pb.h"

#define DEBUG 1


template<class... Args>
int printd(Args ... args)
{
    (std::cerr << ... << args) << "\n";
    return 1;
}

int connect_peer(std::string_view ip_port) {

    auto x = ip_port.find_last_of(":");
    if (x == std::string_view::npos)
        return printd("[DBG] Could not find port in ", ip_port), -1;

    std::string ip { ip_port.substr(0, x) };
    long port = strtol(ip_port.substr(x+1).data(), 0, 10);

    if (port <= 0)
        return printd("[DBG] Port of ", ip_port, " parsed to 0 or neg"), -1;    

    int sockfd = 0;
    struct sockaddr_in serv_addr; 

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return printd("[DBG] Could not create socket for ", ip_port, "\n"), -1;

    memset(&serv_addr, '0', sizeof(serv_addr)); 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port); 

    if(inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr)<=0)
        return printd("[DBG] Could not create socket for ", ip_port," inet_pton error occured"), -1;

    if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        return printd("[DBG] Could not connect to ", ip_port), -1;

    return sockfd;
}


int generate_node_keys(secp256k1_context* ctx, unsigned char* outsec32, unsigned char* outpubraw64, unsigned char* outpubcompressed33, char* outnodekeyb58, size_t* outnodekeyb58size) {
    
    // create secp256k1 context and randomize it

    int rndfd = open("/dev/urandom", O_RDONLY);

    if (rndfd < 0) {
        fprintf(stderr, "[FATAL] Could not open /dev/urandom for reading\n");
        exit(1);
    }



    unsigned char seed[32];
    auto result = read(rndfd, seed, 32);
    if (result != 32) {
        fprintf(stderr, "[FATAL] Could not read 32 bytes from /dev/urandom\n");
        exit(2);
    }

    if (!secp256k1_context_randomize(ctx, seed)) {
        fprintf(stderr, "[FATAL] Could not randomize secp256k1 context\n");
        exit(3);
    }


    result = read(rndfd, outsec32, 32);
    if (result != 32) {
        fprintf(stderr, "[FATAL] Could not read 32 bytes from /dev/urandom\n");
        exit(4);
    }

    secp256k1_pubkey* pubkey = (secp256k1_pubkey*)((void*)(outpubraw64));

    if (!secp256k1_ec_pubkey_create(ctx, pubkey, (const unsigned char*)outsec32)) {
        fprintf(stderr, "[FATAL] Could not generate secp256k1 keypair\n");
        exit(5);
    }

    size_t out_size = 33;
    secp256k1_ec_pubkey_serialize(ctx, outpubcompressed33, &out_size, pubkey, SECP256K1_EC_COMPRESSED);

    unsigned char outpubcompressed38[38];

    // copy into the 38 byte check version
    for(int i = 0; i < 33; ++i) outpubcompressed38[i+1] = outpubcompressed33[i];

    // clean up
    close(rndfd);

    // pub key must start with magic type 0x1C
    outpubcompressed38[0] = 0x1C;
    // generate the double sha256
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, outpubcompressed38, 34);

    unsigned char hash2[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash2, hash, crypto_hash_sha256_BYTES);

    // copy checksum bytes to the end of the compressed key
    for (int i = 0; i < 4; ++i) 
        outpubcompressed38[34+i] = hash2[i];


    // generate base58 encoding
    b58enc(outnodekeyb58, outnodekeyb58size, outpubcompressed38, 38);

    outnodekeyb58[*outnodekeyb58size] = '\0';

}

//todo: clean up and optimise, check for overrun 
SSL* ssl_handshake_and_upgrade(secp256k1_context* secp256k1ctx, int fd, SSL_CTX** outctx) {

    const SSL_METHOD *method = TLS_client_method(); 
    SSL_CTX *ctx = SSL_CTX_new(method);

    *outctx = ctx;

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd); 

    int status = SSL_connect(ssl);
    if ( status != 1 ) {
        fprintf(stderr, "[FATAL] SSL_connect failed with SSL_get_error code %d\n", status);
        return NULL;
    }    

    unsigned char buffer[1024];
    size_t len = SSL_get_finished(ssl, buffer, 1024);
    if (len < 12) {
        fprintf(stderr, "[FATAL] Could not SSL_get_finished\n");
        return NULL;
    }

    // SHA512 SSL_get_finished to create cookie 1
    unsigned char cookie1[64];
    crypto_hash_sha512(cookie1, buffer, len);
    
    len = SSL_get_peer_finished(ssl, buffer, 1024);
    if (len < 12) {
        fprintf(stderr, "[FATAL] Could not SSL_get_peer_finished\n");
        return NULL;
    }   
   
    // SHA512 SSL_get_peer_finished to create cookie 2
    unsigned char cookie2[64];
    crypto_hash_sha512(cookie2, buffer, len);

    // xor cookie2 onto cookie1
    for (int i = 0; i < 64; ++i) cookie1[i] ^= cookie2[i];

    // the first half of cookie2 is the true cookie
    crypto_hash_sha512(cookie2, cookie1, 64);

    // generate keys

    unsigned char sec[32], pub[64], pubc[33];
    char b58[100];
    size_t b58size = 100;
    generate_node_keys(secp256k1ctx, sec, pub, pubc, b58, &b58size);

    secp256k1_ecdsa_signature sig;
    secp256k1_ecdsa_sign(secp256k1ctx, &sig, cookie2, sec, NULL, NULL);
   
    unsigned char buf[200];
    size_t buflen = 200;
    secp256k1_ecdsa_signature_serialize_der(secp256k1ctx, buf, &buflen, &sig);

    char buf2[200];
    size_t buflen2 = 200;
    sodium_bin2base64(buf2, buflen2, buf, buflen, sodium_base64_VARIANT_ORIGINAL);

    buf2[buflen2] = '\0';
    printf("base64: %s\n", buf2);


    char buf3[2048];
    size_t buf3len = snprintf(buf3, 2047, "GET / HTTP/1.1\r\nUser-Agent: rippled-1.6.0\r\nUpgrade: RTXP/1.2\r\nConnection: Upgrade\r\nConnect-As: Peer\r\nCrawl: private\r\nSession-Signature: %s\r\nPublic-Key: %s\r\n\r\n", buf2, b58);

    printf("To write:\n%s", buf3);

    if (SSL_write(ssl, buf3, buf3len) <= 0) {
        fprintf(stderr, "[FATAL] Failed to write bytes to openssl fd\n");
        return NULL;
    }

    return ssl;

}

int main() {


    if (sodium_init() < 0) {
        fprintf(stderr, "[FATAL] Could not init libsodium\n");
        exit(6);
    }

    SSL_library_init();
    
    secp256k1_context* secp256k1ctx = secp256k1_context_create(
                SECP256K1_CONTEXT_VERIFY |
                SECP256K1_CONTEXT_SIGN) ;


    int fd = -1;

    /*for (auto& v: peers) {
        std::cout << v << "\n";
        std::cout << "socketfd: " << (fd = connect_peer(v)) << "\n";
        break;
    }*/
    fd = connect_peer("35.158.96.209:51235");


    if (fd <= 0) {
        fprintf(stderr, "[FATAL] Could not connect\n"); // todo just return
        exit(11);
    }

    SSL_CTX* sslctx = NULL;

    SSL* ssl = ssl_handshake_and_upgrade(secp256k1ctx, fd, &sslctx);

    if (ssl == NULL) {
        fprintf(stderr, "[FATAL] Could not handshake\n");
        exit(12);
    }
 

 
    unsigned char buffer[2048];
    size_t bufferlen = 2048;

 
    int pc = 0;
    while (1) {
        bufferlen = SSL_read(ssl, buffer, 2048); 
        buffer[bufferlen] = '\0';
        if (!pc) {
            printf("returned:\n%s", buffer);
            pc++;
            continue;
        }
        
        printf("packet %d:\n", pc++);
        for (int i = 0; i < bufferlen; ++i)
            printf("%02X", buffer[i]);

        printf("\n");
        
    }

    secp256k1_context_destroy(secp256k1ctx);
    SSL_free(ssl);
    SSL_CTX_free(sslctx);
    close(fd);

    return 0;
}
