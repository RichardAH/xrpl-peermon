
#include <sodium.h>

#include <iostream>
#include <string_view>
#include <string>
#include <string.h>
#include <time.h>

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

#include "libbase58.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <stdint.h>

#include <set>
#include <map>
#include <utility>

#include "ripple.pb.h"

#include "stlookup.h"
#include  <netdb.h>

#include "sha-256.h"
#include "xd.h"
#define DEBUG 1
#define PACKET_STACK_BUFFER_SIZE 2048

#define VERSION "1.0"

std::string peer;
time_t time_start;

template<class... Args>
int printd(Args ... args)
{
    (std::cerr << ... << args) << "\n";
    return 1;
}

int connect_peer(std::string_view ip_port)
{

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


int generate_node_keys(
        secp256k1_context* ctx,
        unsigned char* outsec32,
        unsigned char* outpubraw64,
        unsigned char* outpubcompressed33,
        char* outnodekeyb58,
        size_t* outnodekeyb58size)
{
    
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
SSL* ssl_handshake_and_upgrade(secp256k1_context* secp256k1ctx, int fd, SSL_CTX** outctx)
{
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
    size_t buf3len = snprintf(buf3, 2047, "GET / HTTP/1.1\r\nUser-Agent: rippled-1.8.0\r\nUpgrade: RTXP/1.2\r\nConnection: Upgrade\r\nConnect-As: Peer\r\nCrawl: private\r\nSession-Signature: %s\r\nPublic-Key: %s\r\n\r\n", buf2, b58);

    printf("To write:\n%s", buf3);

    if (SSL_write(ssl, buf3, buf3len) <= 0) {
        fprintf(stderr, "[FATAL] Failed to write bytes to openssl fd\n");
        return NULL;
    }

    return ssl;
}

const char* mtUNKNOWN = "mtUNKNOWN_PACKET";

const char* packet_name(
        int packet_type, int padded)
{
    switch(packet_type)
    {
        case 2: return (padded ? "mtMANIFESTS               " : "mtMANIFESTS");
        case 3: return (padded ? "mtPING                    " : "mtPING");
        case 5: return (padded ? "mtCLUSTER                 " : "mtCLUSTER");
        case 15: return (padded ? "mtENDPOINTS               " : "mtENDPOINTS");
        case 30: return (padded ? "mtTRANSACTION             " : "mtTRANSACTION");
        case 31: return (padded ? "mtGET_LEDGER              " : "mtGET_LEDGER");
        case 32: return (padded ? "mtLEDGER_DATA             " : "mtLEDGER_DATA");
        case 33: return (padded ? "mtPROPOSE_LEDGER          " : "mtPROPOSE_LEDGER");
        case 34: return (padded ? "mtSTATUS_CHANGE           " : "mtSTATUS_CHANGE");
        case 35: return (padded ? "mtHAVE_SET                " : "mtHAVE_SET");
        case 41: return (padded ? "mtVALIDATION              " : "mtVALIDATION");
        case 42: return (padded ? "mtGET_OBJECTS             " : "mtGET_OBJECTS");
        case 50: return (padded ? "mtGET_SHARD_INFO          " : "mtGET_SHARD_INFO");
        case 51: return (padded ? "mtSHARD_INFO              " : "mtSHARD_INFO");
        case 52: return (padded ? "mtGET_PEER_SHARD_INFO     " : "mtGET_PEER_SHARD_INFO");
        case 53: return (padded ? "mtPEER_SHARD_INFO         " : "mtPEER_SHARD_INFO");
        case 54: return (padded ? "mtVALIDATORLIST           " : "mtVALIDATORLIST");
        case 55: return (padded ? "mtSQUELCH                 " : "mtSQUELCH");
        case 56: return (padded ? "mtVALIDATORLISTCOLLECTION " : "mtVALIDATORLISTCOLLECTION");
        case 57: return (padded ? "mtPROOF_PATH_REQ          " : "mtPROOF_PATH_REQ");
        case 58: return (padded ? "mtPROOF_PATH_RESPONSE     " : "mtPROOF_PATH_RESPONSE");
        case 59: return (padded ? "mtREPLAY_DELTA_REQ        " : "mtREPLAY_DELTA_REQ");
        case 60: return (padded ? "mtREPLAY_DELTA_RESPONSE   " : "mtREPLAY_DELTA_RESPONSE");
        case 61: return (padded ? "mtGET_PEER_SHARD_INFO_V2  " : "mtGET_PEER_SHARD_INFO_V2");
        case 62: return (padded ? "mtPEER_SHARD_INFO_V2      " : "mtPEER_SHARD_INFO_V2");
        case 63: return (padded ? "mtHAVE_TRANSACTIONS       " : "mtHAVE_TRANSACTIONS");
        case 64: return (padded ? "mtTRANSACTIONS            " : "mtTRANSACTIONS");        
        default: return (padded ? "mtUNKNOWN_PACKET          " : mtUNKNOWN);
    }
}




std::set<int> suppressions;
std::map<int, std::pair<uint64_t, uint64_t>> counters; // packet type => [ packet_count, total_bytes ];


void rpad(char* output, int padding_chars)
{
    int i = strlen(output);
    while (padding_chars -i > 0)
        output[i++] = ' ';
    output[i] = '\0';
}

void human_readable_double(double bytes, char* output, char* end)
{
    char* suffix[] = {"B", "K", "M", "G", "T"};
  	char length = sizeof(suffix) / sizeof(suffix[0]);
    int i = 0;
    while (bytes > 1024 && i < length - 1)
    {
        bytes /= 1024;
        i++;
	}
    sprintf(output, "%.02lf %s%s", bytes, suffix[i], (end ? end : ""), i);
}

void human_readable(uint64_t bytes, char* output, char* end)
{
    human_readable_double(bytes, output, end);
}

#define PAD 20

int use_cls = 1, no_dump = 0, slow = 0;
time_t last_print = 0;

void process_packet(
        SSL* ssl,
        int packet_type,
        unsigned char* packet_buffer,
        size_t packet_len)
{

    if (counters.find(packet_type) == counters.end())
        counters.emplace(std::pair<int, std::pair<uint64_t, uint64_t>>{packet_type, std::pair<uint64_t, uint64_t>{1,packet_len}});
    else
    {
        auto& p = counters[packet_type];
        p.first++;
        p.second += packet_len;
    }

    if (suppressions.find(packet_type) != suppressions.end())
        return;

    // cls   
    if (use_cls) 
        fprintf(stdout, "%c%c", 033, 'c');

    time_t time_now = time(NULL);
    if (slow && time_now - last_print < 5)
        return;
    last_print = time_now;

    // display logic
    {
        time_t time_elapsed = time_now - time_start;
        if (time_elapsed <= 0) time_elapsed = 1;

        printf(
            "XRPL-Peermon\nConnected to Peer: %s for %llu sec\n\n"
            "Packet                    Total               Per second          Total Bytes         Data rate       \n"
            "------------------------------------------------------------------------------------------------------\n"
            ,peer.c_str(), time_elapsed);

        double total_rate = 0;
        uint64_t total_packets = 0;
        uint64_t total_bytes = 0;

        for (int i = 0; i < 128; ++i)
        if (counters.find(i) != counters.end())
        {
            auto& p = counters[i];
            double bps = ((double)(p.second))/(double)(time_elapsed);
            double cps = ((double)(p.first))/(double)(time_elapsed);
            total_bytes += p.second;
            total_rate += p.second;
            total_packets += p.first;

            char bps_str[64];
            bps_str[0] = '\0';

            char bto_str[64];
            bto_str[0] = '\0';

            human_readable_double(bps, bps_str, "/s");
            human_readable(p.second, bto_str, 0);
            rpad(bto_str, PAD);

            char cou_str[64];
            cou_str[0] = '\0';
            sprintf(cou_str, "%llu", p.first);
            rpad(cou_str, PAD);

            char cps_str[64];
            cps_str[0] = '\0';
            sprintf(cps_str, "%g", cps);
            rpad(cps_str, PAD);

            printf("%s%s%s%s%s\n", packet_name(i, 1), cou_str, cps_str, bto_str, bps_str);
        }
        total_rate /= ((double)(time_elapsed));

        char bps_str[64];
        bps_str[0] = '\0';
        char bto_str[64];
        bto_str[0] = '\0';
        human_readable_double(total_rate, bps_str, "/s");
        human_readable(total_bytes, bto_str, 0);
        rpad(bto_str, PAD);
            
        char cou_str[64];
        cou_str[0] = '\0';
        sprintf(cou_str, "%llu", total_packets);
        rpad(cou_str, PAD);

        char cps_str[64];
        cps_str[0] = '\0';
        sprintf(cps_str, "%g", ((double)(total_packets))/((double)(time_elapsed)));
        rpad(cps_str, PAD);

        
        printf(        
            "------------------------------------------------------------------------------------------------------\n"
            "Totals                    %s%s%s%s\n\n\n",
            cou_str, cps_str, bto_str, bps_str);
    }

    printf("Latest packet: %s [%d] -- %lu bytes\n", packet_name(packet_type, 0), packet_type, packet_len);

    if (no_dump)
        return;

    switch (packet_type)
    {
        case 2: // mtMANIFESTS
        {
            break;
        }
        case 3: // mtPING
        {
            protocol::TMPing ping;
            bool success = ping.ParseFromArray( packet_buffer, packet_len ) ;
            printf("parsed ping: %s\n", (success ? "yes" : "no") );
            ping.set_type(protocol::TMPing_pingType_ptPONG);

            //unsigned char* buf = (unsigned char*) malloc(ping.ByteSizeLong());
            ping.SerializeToArray(packet_buffer, packet_len);

            uint32_t reply_len = packet_len;
            uint16_t reply_type = 3;

            // write reply header
            unsigned char header[6];
            header[0] = (reply_len >> 24) & 0xff;
            header[1] = (reply_len >> 16) & 0xff;
            header[2] = (reply_len >> 8) & 0xff;
            header[3] = reply_len & 0xff;
            header[4] = (reply_type >> 8) & 0xff;
            header[5] = reply_type & 0xff;
            SSL_write(ssl, header, 6);
            SSL_write(ssl, packet_buffer, packet_len);
            
            printf("Sent PONG\n");
            return;
        }
        case 5: // mtCLUSTER
        {
            break;
        }
        case 15: // mtENDPOINTS
        {
            break;
        }
        case 30: // mtTRANSACTION
        {   //rawTransaction
            protocol::TMTransaction txn;
            bool success = txn.ParseFromArray( packet_buffer, packet_len );
            printf("parsed transaction: %s\n", (success ? "yes" : "no") );
            const std::string& st = txn.rawtransaction();
            printf("sttransaction data: ");
            for (unsigned char c : st)
                printf("%02X", c);

            printf("\n");
            uint8_t* output = 0;
            if (!deserialize(&output, st.c_str(), st.size(), 0, 0, 0))
                return fprintf(stderr, "Could not deserialize\n");
            printf("%s\n", output);
            free(output);
            break;
            break;
        }
        case 31: // mtGET_LEDGER
        {
            break;
        }
        case 32: // mtLEDGER_DATA
        {
            break;
        }
        case 33: // mtPROPOSE_LEDGER
        {
            break;
        }
        case 34: // mtSTATUS_CHANGE
        {
            break;
        }
        case 35: // mtHAVE_SET
        {
            break;
        }
        case 41: // mtVALIDATION
        {
            protocol::TMValidation validation;
            bool success = validation.ParseFromArray( packet_buffer, packet_len );
            printf("parsed validation: %s\n", (success ? "yes" : "no") );
            const std::string& stvalidation = validation.validation();
            printf("stvalidation data: ");
            for (unsigned char c : stvalidation)
                printf("%02X", c);

            printf("\n");
            uint8_t* output = 0;
            if (!deserialize(&output, stvalidation.c_str(), stvalidation.size(), 0, 0, 0))
                return fprintf(stderr, "Could not deserialize\n");
            printf("%s\n", output);
            free(output);
            break;
        }
        case 42: // mtGET_OBJECTS
        {
            break;
        }
        case 50: // mtGET_SHARD_INFO
        {
            break;
        }
        case 51: // mtSHARD_INFO
        {
            break;
        }
        case 52: // mtGET_PEER_SHARD_INFO
        {
            break;
        }
        case 53: // mtPEER_SHARD_INFO
        {
            break;
        }
        case 54: // mtVALIDATORLIST
        {
            break;
        }
        case 55: // mtSQUELCH
        {
            break;
        }
        case 56: // mtVALIDATORLISTCOLLECTION
        {
            break;
        }
        case 57: // mtPROOF_PATH_REQ
        {
            break;
        }
        case 58: // mtPROOF_PATH_RESPONSE
        {
            break;
        }
        case 59: // mtREPLAY_DELTA_REQ
        {
            break;
        }
        case 60: // mtREPLAY_DELTA_RESPONSE
        {
            break;
        }
        case 61: // mtGET_PEER_SHARD_INFO_V2
        {
            break;
        }
        case 62: // mtPEER_SHARD_INFO_V2
        {
            break;
        }
        case 63: // mtHAVE_TRANSACTIONS
        {
            break;
        }
        case 64: // mtTRANSACTIONS
        {
            break;
        }
        default:
        {
            printf(
                "==== unknown contents ===[\n");
            for (int i = 0; i < packet_len && i < 64; ++i)
                printf("%02X", packet_buffer[i]);
            printf("\n"
                "]===(may be truncated)====\n");
        }
    }
}

int print_usage(int argc, char** argv, char* message)
{
    fprintf(stderr, "XRPL Peer Monitor\nVersion: %s\nAuthor: Richard Holland / XRPL-Labs\n", VERSION);
    if (message)
        fprintf(stderr, "Error: %s\n", message);
    else
        fprintf(stderr, "A tool to connect to a rippled node as a peer and monitor the traffic it produces\n");
    fprintf(stderr, "Usage: %s PEER-IP PORT [OPTIONS]\n", argv[0]);
    fprintf(stderr, "Options:\n"
            "\tno-cls\t- Don't clear the screen between printing stats.\n"
            "\tno-dump\t- Don't dump the latest packet contents.\n"
            "\tslow\t- Only print at most once every 5 seconds.\n");
    fprintf(stderr, "Example: %s r.ripple.com 51235\n", argv[0]);
    return 1;
}

int fd_valid(int fd)
{
    return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

int main(int argc, char** argv)
{

    if (argc < 3)
        return print_usage(argc, argv, NULL);

    int port = 0;

    if (sscanf(argv[2], "%lu", &port) != 1)
        return print_usage(argc, argv, "Invalid port");

    int ip[4];
    char* host = argv[1];
    if (sscanf(host, "%lu.%lu.%lu.%lu", ip, ip+1, ip+2, ip+3) != 4)
    {
        // try do a hostname lookup
        struct hostent* hn = gethostbyname(argv[1]);
        if (!hn)
            return print_usage(argc, argv, "Invalid IP/hostname (IPv4 ONLY)");
        
        struct in_addr** addr_list = (struct in_addr **)hn->h_addr_list;
        host = inet_ntoa(*addr_list[0]);
        if (sscanf(host, "%lu.%lu.%lu.%lu", ip, ip+1, ip+2, ip+3) != 4)
            return print_usage(argc, argv, "Invalid IP after resolving hostname (IPv4 ONLY)");
    }


    peer = std::string{host} + ":" + std::string{argv[2]};

    for (int i = 3; i < argc; ++i)
    {
        if (strcmp(argv[i], "no-cls") == 0)
            use_cls = 0;
        else if (strcmp(argv[i], "no-dump") == 0)
            no_dump = 1;
        else if (strcmp(argv[i], "slow") == 0)
            slow = 1;
        else
            return print_usage(argc, argv, "Valid options: no-cls");
    }

    //suppressions.emplace(3);
    //suppressions.emplace(30);
    //suppressions.emplace(41);

/*    std::cout << "Suppressing: \n";
    for (int x : suppressions)
        std::cout << "\t" << packet_name(x, 0) << "\n";

    std::cout << "\n";
*/

    b58_sha256_impl = calc_sha_256; 
    if (sodium_init() < 0) {
        fprintf(stderr, "[FATAL] Could not init libsodium\n");
        exit(6);
    }

    SSL_library_init();
    
    secp256k1_context* secp256k1ctx = secp256k1_context_create(
                SECP256K1_CONTEXT_VERIFY |
                SECP256K1_CONTEXT_SIGN) ;


    int fd = -1;

    fd = connect_peer(peer.c_str());

    time_start = time(NULL);

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
 
    unsigned char buffer[PACKET_STACK_BUFFER_SIZE];
    size_t bufferlen = PACKET_STACK_BUFFER_SIZE;

    int pc = 0;
    while (fd_valid(fd)) {
        bufferlen = SSL_read(ssl, buffer, PACKET_STACK_BUFFER_SIZE); 
        buffer[bufferlen] = '\0';
        if (!pc) {
            printf("Returned:\n%s", buffer);

            if (bufferlen >= sizeof("HTTP/1.1 503 Service Unavailable")-1 &&
                memcmp(buffer, "HTTP/1.1 503 Service Unavailable", sizeof("HTTP/1.1 503 Service Unavailable")-1) == 0)
            {
                fprintf(stderr, "Node reported Service Unavailable\n");
                return 2;
            }

            pc++;
            continue;
        }


        // check header version
//        if (buffer[0] >> 2 != 0) {
//            fprintf(stderr, "[FATAL] Peer sent packets we don't understand\n");
//            exit(13);
//        }

        // first 4 bytes are bigendian payload size
        uint32_t payload_size = (buffer[0] << 24) + (buffer[1] << 16) + (buffer[2] << 8) + buffer[3];
        uint16_t packet_type = (buffer[4] << 8) + buffer[5];


        // the vast majority of packets will fit in the stack buffer, but for those which do not, we will read the rest into heap
        if (payload_size + 6 > bufferlen) {
            // incomplete packet, receive the rest into a heap buffer
            size_t bufferlen2 = payload_size;
            unsigned char* heapbuf = (unsigned char*) malloc( bufferlen2 );
            bufferlen2 = SSL_read(ssl, heapbuf + bufferlen, bufferlen2);

            for (size_t i = 0; i < bufferlen; ++i) heapbuf[i] = buffer[i + 6];

            process_packet( ssl, packet_type, heapbuf, payload_size );
            free(heapbuf);
        }

        process_packet( ssl, packet_type, buffer+6, bufferlen-6 );
        
    }

    secp256k1_context_destroy(secp256k1ctx);
    SSL_free(ssl);
    SSL_CTX_free(sslctx);
    close(fd);

    return 0;
}
