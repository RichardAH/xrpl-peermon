// Mock rippled/xahaud peer for testing peermon end to end without a network.
//
// It implements the server- and client-side handshake checks xahaud performs
// (OverlayImpl::onHandoff / ConnectAttempt + Handshake.cpp):
//   - shared value = sha512Half(sha512(our Finished) ^ sha512(peer Finished))
//   - Session-Signature must verify against Public-Key over the shared value
//   - Network-ID: absent counts as 0 and must equal ours (xahaud semantics)
//   - protocol version negotiated from the Upgrade list
// and then exchanges framed protobuf messages.
//
// serve   PORT NID|none VERSIONS [t:HEX | v:HEX ...]
//     Accept one connection. After a successful handshake send a 2 byte ping
//     followed by one TMTransaction per t:HEX and one TMValidation per v:HEX,
//     all coalesced into ONE TLS write, then wait for the PONG and close.
// connect PORT NID|none
//     Connect to a peermon in listen mode, verify its 101 response the way
//     xahaud's ConnectAttempt does, and check the TMPing it sends.
//
// Exit status 0 on success. Needs tests/peer.cert + tests/peer.key (serve).

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <secp256k1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include <optional>
#include <string>
#include <vector>

#include "../libbase58.h"
#include "../sha-256.h"
#include "../ripple.pb.h"

static secp256k1_context* ctx;
static uint8_t our_sec[32];
static uint8_t our_pub[33];

#define FAIL(...) do { fprintf(stderr, "MOCK FAIL: " __VA_ARGS__); fprintf(stderr, "\n"); exit(1); } while (0)

static std::string header(const std::string& head, const char* name)
{
    size_t nl = strlen(name);
    for (size_t p = head.find("\r\n"); p != std::string::npos; p = head.find("\r\n", p))
    {
        p += 2;
        if (strncasecmp(head.c_str() + p, name, nl) == 0 && head[p + nl] == ':')
        {
            size_t v = p + nl + 1;
            while (v < head.size() && head[v] == ' ')
                ++v;
            return head.substr(v, head.find("\r\n", v) - v);
        }
    }
    return "";
}

static bool has_header(const std::string& head, const char* name)
{
    std::string needle = std::string("\r\n") + name + ":";
    return strcasestr(head.c_str(), needle.c_str()) != NULL;
}

static std::string read_head(SSL* ssl)
{
    std::string h;
    char c;
    while (h.find("\r\n\r\n") == std::string::npos)
    {
        if (SSL_read(ssl, &c, 1) != 1)
            FAIL("connection closed while reading HTTP head");
        h += c;
    }
    return h;
}

static void read_exact(SSL* ssl, uint8_t* p, size_t n)
{
    size_t got = 0;
    while (got < n)
    {
        int r = SSL_read(ssl, p + got, (int)(n - got));
        if (r <= 0)
            FAIL("connection closed while reading a message");
        got += r;
    }
}

// Handshake.cpp makeSharedValue()
static void shared_value(SSL* ssl, uint8_t out[32])
{
    uint8_t f1[1024], f2[1024], c1[64], c2[64], x[64], h[64];
    size_t l1 = SSL_get_finished(ssl, f1, sizeof(f1));
    size_t l2 = SSL_get_peer_finished(ssl, f2, sizeof(f2));
    if (l1 < 12 || l2 < 12)
        FAIL("finished messages unavailable");
    SHA512(f1, l1, c1);
    SHA512(f2, l2, c2);
    int zero = 1;
    for (int i = 0; i < 64; ++i)
        zero &= !(x[i] = c1[i] ^ c2[i]);
    if (zero)
        FAIL("identical finished messages");
    SHA512(x, 64, h);
    memcpy(out, h, 32);
}

// Ripple-alphabet base58check decode of a 38 byte node public key token.
// (base58.c only encodes with the Ripple alphabet; its decoder uses Bitcoin's.)
static bool node_public_decode(const std::string& s, uint8_t out[38])
{
    static const char* A = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
    uint8_t num[38] = {0};
    for (char ch : s)
    {
        const char* p = strchr(A, ch);
        if (!p || !ch)
            return false;
        unsigned carry = (unsigned)(p - A);
        for (int i = 37; i >= 0; --i)
        {
            carry += 58U * num[i];
            num[i] = carry & 0xFF;
            carry >>= 8;
        }
        if (carry)
            return false;  // longer than 38 bytes
    }
    uint8_t h1[32], h2[32];
    SHA256(num, 34, h1);
    SHA256(h1, 32, h2);
    if (memcmp(h2, num + 34, 4) != 0)
        return false;
    memcpy(out, num, 38);
    return true;
}

static std::string node_public_b58(const uint8_t pub[33])
{
    char b58[128];
    size_t sz = sizeof(b58);
    if (!b58check_enc(b58, &sz, 0x1C, pub, 33))
        FAIL("b58 encode");
    return std::string(b58);
}

static std::string sign_b64(const uint8_t digest[32])
{
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, digest, our_sec, NULL, NULL))
        FAIL("sign");
    uint8_t der[80];
    size_t derlen = sizeof(der);
    secp256k1_ecdsa_signature_serialize_der(ctx, der, &derlen, &sig);
    char b64[160];
    int n = EVP_EncodeBlock((unsigned char*)b64, der, (int)derlen);
    return std::string(b64, n);
}

// Handshake.cpp verifyHandshake(): network, public key, session signature
static void verify_handshake(const std::string& head, const uint8_t shared[32], std::optional<uint32_t> nid)
{
    uint32_t theirs = 0;
    std::string v = header(head, "Network-ID");
    if (has_header(head, "Network-ID"))
    {
        char* e = NULL;
        unsigned long x = strtoul(v.c_str(), &e, 10);
        if (v.empty() || *e)
            throw std::string("Invalid peer network identifier");
        theirs = (uint32_t)x;
    }
    if (nid.value_or(0) != theirs)
        throw std::string("Peer is on a different network");

    std::string pk = header(head, "Public-Key");
    uint8_t raw[38];
    if (!node_public_decode(pk, raw) || raw[0] != 0x1C || (raw[1] != 2 && raw[1] != 3))
        throw std::string("Bad node public key");
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_parse(ctx, &pub, raw + 1, 33))
        throw std::string("Bad node public key");

    std::string sigb64 = header(head, "Session-Signature");
    if (sigb64.empty())
        throw std::string("No session signature specified");
    uint8_t der[128];
    int n = EVP_DecodeBlock(der, (const unsigned char*)sigb64.c_str(), (int)sigb64.size());
    if (n <= 0)
        throw std::string("Failed to verify session");
    // EVP_DecodeBlock counts '=' padding as zero bytes, so take the real
    // length from the DER header (ECDSA signatures use short-form lengths).
    int derlen = (n >= 2 && der[0] == 0x30) ? der[1] + 2 : n;
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_der(ctx, &sig, der, derlen))
        throw std::string("Failed to verify session");
    secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);  // mustBeFullyCanonical = false
    if (!secp256k1_ecdsa_verify(ctx, &sig, shared, &pub))
        throw std::string("Failed to verify session");

    if (memcmp(raw + 1, our_pub, 33) == 0)
        throw std::string("Self connection");
}

static std::vector<std::pair<int, int>> parse_versions(const std::string& s)
{
    std::vector<std::pair<int, int>> out;
    size_t p = 0;
    while (p < s.size())
    {
        size_t e = s.find(',', p);
        std::string tok = s.substr(p, e == std::string::npos ? std::string::npos : e - p);
        while (!tok.empty() && tok[0] == ' ') tok.erase(0, 1);
        while (!tok.empty() && tok.back() == ' ') tok.pop_back();
        int a, b;
        if (sscanf(tok.c_str(), "XRPL/%d.%d", &a, &b) == 2)
            out.push_back({a, b});
        else if (sscanf(tok.c_str(), "%d.%d", &a, &b) == 2)  // our own supported list
            out.push_back({a, b});
        if (e == std::string::npos)
            break;
        p = e + 1;
    }
    return out;
}

static void frame(std::string& out, uint16_t type, const google::protobuf::MessageLite& m)
{
    std::string body = m.SerializeAsString();
    uint32_t n = body.size();
    char h[6] = {(char)(n >> 24), (char)(n >> 16), (char)(n >> 8), (char)n, (char)(type >> 8), (char)type};
    out.append(h, 6);
    out += body;
}

static std::string unhex(const char* s)
{
    std::string out;
    for (size_t i = 0; s[i] && s[i + 1]; i += 2)
    {
        unsigned v;
        sscanf(s + i, "%2x", &v);
        out += (char)v;
    }
    return out;
}

static int tcp_listen(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (sockaddr*)&a, sizeof(a)) || listen(fd, 1))
        FAIL("bind/listen");
    return fd;
}

static int serve(int port, std::optional<uint32_t> nid, const std::string& versions, int argc, char** argv)
{
    SSL_CTX* c = SSL_CTX_new(TLS_server_method());
    if (SSL_CTX_use_certificate_file(c, "tests/peer.cert", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(c, "tests/peer.key", SSL_FILETYPE_PEM) <= 0)
        FAIL("tests/peer.cert / tests/peer.key missing");
    int lfd = tcp_listen(port);
    printf("MOCK listening\n");
    fflush(stdout);
    int fd = accept(lfd, NULL, NULL);
    SSL* ssl = SSL_new(c);
    SSL_set_fd(ssl, fd);
    if (SSL_accept(ssl) != 1)
        FAIL("SSL_accept");

    std::string req = read_head(ssl);
    uint8_t shared[32];
    shared_value(ssl, shared);

    auto refuse = [&](const std::string& why) {
        std::string r = "HTTP/1.1 400 Bad Request (" + why + ")\r\nServer: xahaud-mock\r\nConnection: close\r\n\r\n";
        SSL_write(ssl, r.data(), (int)r.size());
        SSL_shutdown(ssl);
        printf("MOCK refused: %s\n", why.c_str());
        exit(3);
    };

    // negotiateProtocolVersion(): highest version both sides support
    auto ours = parse_versions(versions), theirs = parse_versions(header(req, "Upgrade"));
    std::pair<int, int> best{-1, -1};
    for (auto& v : theirs)
        for (auto& o : ours)
            if (v == o && v > best)
                best = v;
    if (best.first < 0)
        refuse("Unable to agree on a protocol version");

    try
    {
        verify_handshake(req, shared, nid);
    }
    catch (std::string const& e)
    {
        refuse(e);
    }
    printf("MOCK handshake ok: session signature verified, peer Network-ID %s, negotiated XRPL/%d.%d\n",
           has_header(req, "Network-ID") ? header(req, "Network-ID").c_str() : "(absent)", best.first, best.second);

    char resp[2048];
    snprintf(resp, sizeof(resp),
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: XRPL/%d.%d\r\nConnect-As: Peer\r\n"
        "Server: xahaud-2026.6.21-mock\r\nCrawl: private\r\nX-Protocol-Ctl: \r\n%s%s%s"
        "Public-Key: %s\r\nSession-Signature: %s\r\nInstance-Cookie: 1\r\n\r\n",
        best.first, best.second, nid ? "Network-ID: " : "", nid ? std::to_string(*nid).c_str() : "", nid ? "\r\n" : "",
        node_public_b58(our_pub).c_str(), sign_b64(shared).c_str());
    SSL_write(ssl, resp, (int)strlen(resp));

    // Everything below goes out in ONE TLS record: a 2 byte ping first, so a
    // reader that over-reads past short messages loses sync immediately.
    std::string batch;
    protocol::TMPing ping;
    ping.set_type(protocol::TMPing_pingType_ptPING);
    frame(batch, 3, ping);
    int ntx = 0, nval = 0;
    for (int i = 0; i < argc; ++i)
    {
        if (strncmp(argv[i], "t:", 2) == 0)
        {
            protocol::TMTransaction t;
            t.set_rawtransaction(unhex(argv[i] + 2));
            t.set_status(protocol::tsNEW);
            frame(batch, 30, t);
            ++ntx;
        }
        else if (strncmp(argv[i], "v:", 2) == 0)
        {
            protocol::TMValidation v;
            v.set_validation(unhex(argv[i] + 2));
            frame(batch, 41, v);
            ++nval;
        }
    }
    protocol::TMPing ping2;
    ping2.set_type(protocol::TMPing_pingType_ptPING);
    ping2.set_seq(4242);
    frame(batch, 3, ping2);
    if (SSL_write(ssl, batch.data(), (int)batch.size()) != (int)batch.size())
        FAIL("write batch");
    printf("MOCK sent %d transactions, %d validations, 2 pings in one %zu byte write\n", ntx, nval, batch.size());

    // expect two PONGs, the second carrying seq 4242
    for (int i = 0; i < 2; ++i)
    {
        uint8_t h[6];
        read_exact(ssl, h, 6);
        uint32_t n = (uint32_t)h[0] << 24 | h[1] << 16 | h[2] << 8 | h[3];
        uint16_t type = h[4] << 8 | h[5];
        std::string body(n, '\0');
        read_exact(ssl, (uint8_t*)body.data(), n);
        protocol::TMPing p;
        if (type != 3 || !p.ParseFromString(body) || p.type() != protocol::TMPing_pingType_ptPONG)
            FAIL("expected a PONG, got type %u", type);
        if (i == 1 && p.seq() != 4242)
            FAIL("second PONG has seq %u", p.seq());
    }
    printf("MOCK got both PONGs (seq preserved)\n");
    SSL_shutdown(ssl);
    close(fd);
    return 0;
}

static int connect_to(int port, std::optional<uint32_t> nid)
{
    SSL_CTX* c = SSL_CTX_new(TLS_client_method());
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    for (int i = 0; connect(fd, (sockaddr*)&a, sizeof(a)) != 0; ++i)
    {
        if (i > 50) FAIL("connect");
        usleep(100000);
    }
    SSL* ssl = SSL_new(c);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1)
        FAIL("SSL_connect");
    uint8_t shared[32];
    shared_value(ssl, shared);

    char req[2048];
    snprintf(req, sizeof(req),
        "GET / HTTP/1.1\r\nUser-Agent: xahaud-2026.6.21-mock\r\nUpgrade: XRPL/2.1, XRPL/2.2\r\nConnection: Upgrade\r\n"
        "Connect-As: Peer\r\nCrawl: private\r\n%s%s%sPublic-Key: %s\r\nSession-Signature: %s\r\n\r\n",
        nid ? "Network-ID: " : "", nid ? std::to_string(*nid).c_str() : "", nid ? "\r\n" : "",
        node_public_b58(our_pub).c_str(), sign_b64(shared).c_str());
    SSL_write(ssl, req, (int)strlen(req));

    std::string resp = read_head(ssl);
    if (resp.compare(0, 12, "HTTP/1.1 101") != 0)
        FAIL("expected 101, got: %s", resp.substr(0, resp.find("\r\n")).c_str());
    auto up = parse_versions(header(resp, "Upgrade"));
    if (up.size() != 1 || (up[0] != std::make_pair(2, 1) && up[0] != std::make_pair(2, 2)))
        FAIL("bad Upgrade in response: %s", header(resp, "Upgrade").c_str());
    try
    {
        verify_handshake(resp, shared, nid);  // ConnectAttempt::processResponse
    }
    catch (std::string const& e)
    {
        FAIL("response rejected: %s", e.c_str());
    }
    printf("MOCK listen-mode response ok: signature verified, Network-ID %s, Upgrade %s\n",
           has_header(resp, "Network-ID") ? header(resp, "Network-ID").c_str() : "(absent)",
           header(resp, "Upgrade").c_str());

    uint8_t h[6];
    read_exact(ssl, h, 6);
    uint32_t n = (uint32_t)h[0] << 24 | h[1] << 16 | h[2] << 8 | h[3];
    uint16_t type = h[4] << 8 | h[5];
    std::string body(n, '\0');
    read_exact(ssl, (uint8_t*)body.data(), n);
    protocol::TMPing p;
    if (type != 3 || !p.ParseFromString(body) || p.type() != protocol::TMPing_pingType_ptPING)
        FAIL("expected a well formed TMPing from peermon (type %u, %u bytes)", type, n);
    printf("MOCK got a well formed %u byte TMPing from peermon\n", n);
    SSL_shutdown(ssl);
    close(fd);
    return 0;
}

int main(int argc, char** argv)
{
    if (argc < 4)
        return fprintf(stderr, "usage: see header comment\n"), 2;
    b58_sha256_impl = calc_sha_256;
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    FILE* r = fopen("/dev/urandom", "rb");
    secp256k1_pubkey pub;
    do
    {
        if (fread(our_sec, 1, 32, r) != 32)
            FAIL("urandom");
    } while (!secp256k1_ec_pubkey_create(ctx, &pub, our_sec));
    fclose(r);
    size_t pl = 33;
    secp256k1_ec_pubkey_serialize(ctx, our_pub, &pl, &pub, SECP256K1_EC_COMPRESSED);

    int port = atoi(argv[2]);
    std::optional<uint32_t> nid;
    if (strcmp(argv[3], "none") != 0)
        nid = (uint32_t)strtoul(argv[3], NULL, 10);

    if (strcmp(argv[1], "serve") == 0 && argc >= 5)
        return serve(port, nid, argv[4], argc - 5, argv + 5);
    if (strcmp(argv[1], "connect") == 0)
        return connect_to(port, nid);
    return 2;
}
