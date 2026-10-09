extern "C" {

/**
 * XRPL / Xahau Deserializer
 * Author: Richard Holland
 * Date: 21/5/21
 * Pass a hex encoded xrpl binary object via argument to the executable
 * Output: JSON
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "libbase58.h"
#include "xd.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "sha-256.h"

#define DEFAULT_SIZE (2048*1024)

#define DEBUG 0

int append(int indent_level, uint8_t** output, int* upto, int* len, int write_fd, void const* append_raw, int append_len)
{
    uint8_t* append = (uint8_t*)append_raw;

    if (DEBUG)
        printf("append: `%s`\n", append);

    // stream mode
    if (write_fd)
    {
        char tab[1] = {'\t'};
        for (int i = 0; i < indent_level; ++i)
            if (write(write_fd, tab, 1) <= 0)
                return 0;
       
        int l = strnlen(reinterpret_cast<char const*>(append), append_len); 
        if (write(write_fd, append, l) < l)
            return 0;

        return 1;
    }

    if (*len - *upto < append_len + 1 + indent_level)
    {
        *len *= 2;
        *output = (uint8_t*)realloc(*output, *len + 1);
        if (*output == 0)
            return 0;
    }

    // tabs for indent

    for (int i = 0; i < indent_level; ++i)
        *(*output + (*upto)++) = '\t';

    for (uint8_t* x = *output + *upto, *end = *output + *upto + append_len; x < end && *append; (*upto)++)
        *x++ = *append++;

    *(*output + *upto) = '\0';

    return 1;
}

#define SBUF(x) x,sizeof(x)
#define APPENDPARAMS indent_level, output, &upto, &len, write_fd
#define APPENDNOINDENT 0, output, &upto, &len, write_fd


#define _REQUIRE(b,suppress)\
{\
    if (DEBUG) printf("\nREQUIRE CALLED AT LINE %d FOR %d bytes, remaining = %d\n", __LINE__, (b), remaining);\
    if (remaining < (b) && !(!fetch_data_func && suppress))\
    {\
        if (!fetch_data_func)\
            break;\
        int upto = n - input;\
        if (input_len - upto - remaining < 0)\
        {\
            fprintf(stderr, "Error: remaining past end of input len, maybe overlarge vl blob in input?\n");\
            exit(1);\
        }\
        int needed = 0;\
        do\
        {\
            needed = (b) - remaining;\
            if (needed < 0) needed = 0;\
            int bytes_read = (*fetch_data_func)(input + upto + remaining, input_len - upto - remaining, needed, read_fd);\
            if (bytes_read < 0)\
            {\
                if (!suppress)\
                    fprintf(stderr, "Error: expecting %d nibbles at nibble %d but input was short (only %d remain) code line %d\n", (b)*2, upto*2, remaining * 2,  __LINE__);\
                break;\
            }\
            remaining += bytes_read;\
        } while(remaining < (b));\
    }\
}
/*
    printf("\n");\
    for (int i = 0; i < (n - input) + remaining; ++i)\
        printf("%02X ", input[i]);\
    printf("\n");\
*/

#define REQUIRE(b) _REQUIRE(b,0)

#define ADVANCE(x)\
{\
    if (fetch_data_func)\
        REQUIRE(x);\
    n += (x); remaining -= (x);\
    int upto = n - input;\
    if (fetch_data_func &&\
        upto > input_len / 2)\
    {\
        memcpy(input, n, remaining);\
        n = input;\
    }\
}

#define HEX(out_raw, in_raw, len_raw)\
{\
    uint8_t* out = (uint8_t*)(out_raw);\
    uint8_t* in = (uint8_t*)(in_raw);\
    uint64_t len = (len_raw);\
    for (int i = 0; i < len; ++i)\
    {\
        unsigned char hi = in[i] >> 4U;\
        unsigned char lo = in[i] & 0xFU;\
        hi += (hi > 9 ? 'A' - 10 : '0');\
        lo += (lo > 9 ? 'A' - 10 : '0');\
        out[i*2+0] = (char)hi;\
        out[i*2+1] = (char)lo;\
    }\
}

/*
 * Field, transaction, ledger entry and result names come from xd_defs.h,
 * which gen_defs.py generates from rippled's and xahaud's own definition
 * macros. The two networks share the wire format but not these tables (the
 * same type/field code can name different fields), so the active table is
 * selected at runtime with xd_network.
 */
#include "xd_defs.h"

int xd_network = XD_NETWORK_XRPL;

static const char* xd_field_name(int type_code, int field_code)
{
    int key = (type_code << 8) | field_code;
    return xd_network == XD_NETWORK_XAHAU ? xd_field_name_xahau(key) : xd_field_name_xrpl(key);
}

static const char* xd_tx_name(int v)
{
    return xd_network == XD_NETWORK_XAHAU ? xd_tx_name_xahau(v) : xd_tx_name_xrpl(v);
}

static const char* xd_le_name(int v)
{
    return xd_network == XD_NETWORK_XAHAU ? xd_le_name_xahau(v) : xd_le_name_xrpl(v);
}

static const char* xd_ter_name(int v)
{
    return xd_network == XD_NETWORK_XAHAU ? xd_ter_name_xahau(v) : xd_ter_name_xrpl(v);
}

const char* xd_native_currency(void)
{
    return xd_network == XD_NETWORK_XAHAU ? "XAH" : "XRP";
}

static uint64_t be64(const uint8_t* p)
{
    uint64_t r = 0;
    for (int i = 0; i < 8; ++i)
        r = (r << 8U) | p[i];
    return r;
}

static uint32_t be32(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24U) | ((uint32_t)p[1] << 16U) | ((uint32_t)p[2] << 8U) | p[3];
}

// Renders mantissa * 10^exponent as a quoted decimal string.
// Returns the number of bytes written (including the NUL) or -1 if it would
// not fit in len bytes, in which case the caller should fall back to
// scientific notation.
int to_fixed_point(uint8_t* outbuf, int len, uint64_t mantissa, int64_t exponent, int negative)
{
    int upto = 0;
    char digits[24];
    int digitcount = snprintf(digits, sizeof(digits), "%llu", (unsigned long long)mantissa);
    int digitupto = 0;
    int64_t point = exponent + digitcount;
    int printed_point = 0;

#define PUT(c) { if (upto >= len - 2) return -1; outbuf[upto++] = (c); }
    PUT('"');
    if (mantissa == 0)
        PUT('0')
    else
    {
        if (negative)
            PUT('-');

        for (; point > 0; --point)
            PUT(digitupto >= digitcount ? '0' : digits[digitupto++]);

        if (digitupto < digitcount)
        {
            if (digitupto == 0)
                PUT('0');
            PUT('.');
            printed_point = 1;
            for (; point < 0; ++point)
                PUT('0');
            while (digitupto < digitcount)
                PUT(digits[digitupto++]);
        }

        // backtrack any trailing zeros, and the point itself if nothing is left after it
        if (printed_point)
        {
            while (outbuf[upto - 1] == '0')
                --upto;
            if (outbuf[upto - 1] == '.')
                --upto;
        }
    }
    PUT('"');
#undef PUT
    outbuf[upto++] = '\0';
    return upto;
}

// Standard (3 character) currency code, same character set rippled accepts.
int is_ascii_currency(uint8_t* y)
{
    static const char extra[] = "<>(){}[]|?!@#$%^&*";
    for (int i = 0; i < 12; ++i)
        if (y[i] != 0)
            return 0;
    for (int i = 12; i < 15; ++i)
    {
        char x = y[i];
        if ((x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z') || (x >= '0' && x <= '9'))
            continue;
        if (x != 0 && strchr(extra, x))
            continue;
        return 0;
    }
    for (int i = 15; i < 20; ++i)
        if (y[i] != 0)
            return 0;
    return 1;
}

static int is_zero(const uint8_t* p, int n)
{
    for (int i = 0; i < n; ++i)
        if (p[i])
            return 0;
    return 1;
}

// rippled's noAccount(): 0x000...01, used as the MPT marker inside STIssue
static int is_no_account(const uint8_t* p)
{
    return is_zero(p, 19) && p[19] == 1;
}

static void xd_currency(char dst[41], const uint8_t* c)
{
    if (is_zero(c, 20))
    {
        strcpy(dst, xd_native_currency());
        return;
    }
    if (is_ascii_currency((uint8_t*)c))
    {
        dst[0] = (char)c[12];
        dst[1] = (char)c[13];
        dst[2] = (char)c[14];
        dst[3] = '\0';
        return;
    }
    HEX(dst, c, 20);
    dst[40] = '\0';
}

static int xd_account(char* out, size_t outsz, const uint8_t* acc20)
{
    size_t sz = outsz;
    if (!b58check_enc(out, &sz, 0, acc20, 20))
        return 0;
    out[0] = 'r';
    return 1;
}

static void xd_tabs(char* out, int n)
{
    if (n > 30) n = 30;
    for (int i = 0; i < n; ++i)
        out[i] = '\t';
    out[n] = '\0';
}

// Wire length of an STIssue starting at p. The caller must already have
// made the first 20 bytes available, and the first 40 if not native.
static int xd_issue_len(const uint8_t* p)
{
    if (is_zero(p, 20))
        return 20;
    return is_no_account(p + 20) ? 44 : 40;
}

// STIssue as a JSON object; ind = indent of the closing brace.
static int xd_issue_json(char* out, int outsz, const uint8_t* p, int ind)
{
    char t0[32], t1[32];
    xd_tabs(t0, ind);
    xd_tabs(t1, ind + 1);
    int l = xd_issue_len(p);
    if (l == 20)
    {
        snprintf(out, outsz, "{\n%s\"currency\": \"%s\"\n%s}", t1, xd_native_currency(), t0);
        return l;
    }
    if (l == 44)
    {
        // MPT: issuer(20) | noAccount(20) | sequence(4). The sequence is
        // written byte-reversed relative to the canonical MPTID.
        uint8_t mpt[24];
        mpt[0] = p[43];
        mpt[1] = p[42];
        mpt[2] = p[41];
        mpt[3] = p[40];
        memcpy(mpt + 4, p, 20);
        char hex[49];
        HEX(hex, mpt, 24);
        hex[48] = '\0';
        snprintf(out, outsz, "{\n%s\"mpt_issuance_id\": \"%s\"\n%s}", t1, hex, t0);
        return l;
    }
    char cur[41], acc[64];
    xd_currency(cur, p);
    if (!xd_account(acc, sizeof(acc), p + 20))
        return -1;
    snprintf(out, outsz, "{\n%s\"currency\": \"%s\",\n%s\"issuer\": \"%s\"\n%s}", t1, cur, t1, acc, t0);
    return l;
}

#define APPENDS(params, str) append(params, (str), (int)strlen(str) + 1)

// Reads a VL length prefix into field_len (breaks out of the parse loop on error).
#define READ_VL(field_len)\
{\
    REQUIRE(1);\
    field_len = *n;\
    if (field_len <= 192)\
    {\
        ADVANCE(1);\
    }\
    else if (field_len <= 240)\
    {\
        REQUIRE(2);\
        field_len = 193 + ((field_len - 193) * 256) + *(n+1);\
        ADVANCE(2);\
    }\
    else if (field_len <= 254)\
    {\
        REQUIRE(3);\
        field_len = 12481 + ((field_len - 241) * 65536) + ((*(n+1)) * 256) + *(n+2);\
        ADVANCE(3);\
    }\
    else\
    {\
        fprintf(stderr, "Error: invalid VL length prefix 0x%02X\n", (unsigned)field_len);\
        break;\
    }\
}

int deserialize(
        uint8_t** output,
        uint8_t* input,
        int input_len, 
        int (*fetch_data_func)(uint8_t*, int, int, int), // may be null, refills the input buffer with whatever is available
        int read_fd,    // may be 0 if unused, the fd to pass to fetch_data_func (if applicable)
        int write_fd)   // may be 0 if unused, the fd to write output to, if not specified then *output buffer is used
{

    int remaining = input_len - 1;
    if (input == 0)
    {

        // stream mode
        //
        if (!fetch_data_func)
        {
            fprintf(stderr, "Error: fetch_data_func function ptr must be supplied in stream mode\n");
            return 1;
        }
        input_len = DEFAULT_SIZE;
        input = (uint8_t*)malloc(DEFAULT_SIZE);
        remaining = (*fetch_data_func)(input, input_len, 1, read_fd);
    }

    int len = DEFAULT_SIZE;
    if (output)
    {
        *output = (uint8_t*)malloc(len);
    }
    int upto = 0;

    uint8_t* n = input;
    int object_level = 0;
    int array_level = 0;
    int indent_level = 0;

    uint64_t parent_is_array = 0;

    append(APPENDPARAMS, SBUF("{\n"));

    indent_level++;
    int nocomma = 1;


    while (1)
    {
    
        if (fetch_data_func)
        {
            _REQUIRE(1, 1);
            if (remaining == 0)
                break;
        }
        else if (remaining <= 0)
            break;

        if (array_level < 0)
        {
            fprintf(stderr, "More close arrays than open arrays! at %d\n", upto);
            return 0;
        }
        if (object_level < 0)
        {
            fprintf(stderr, "More close objects than open objects! at %d\n", upto);
            return 0;
        }

        int field_code = -1;
        int type_code = -1;

        if (*n == 0)
        {
            // 3 byte header (typecode >= 16 && field code >= 16)
            REQUIRE(3);
            type_code = *(n+1);
            field_code = *(n+2);
            ADVANCE(3);
        }
        else if ((*n >> 4U) == 0)
        {
            // 2 byte header (typecode >= 16 && field code < 16)
            REQUIRE(2);
            field_code = (*n & 0xFU);
            type_code = *(n+1);
            ADVANCE(2);
        }
        else if ((*n & 0xFU) == 0)
        {
            // 2 byte header (typecode < 16 && field code >= 16)
            REQUIRE(2);
            type_code = (*n >> 4U);
            field_code = *(n+1);
            ADVANCE(2);
        }
        else
        {
            // 1 byte header
            type_code = (*n >> 4U);
            field_code = (*n & 0xFU);
            ADVANCE(1);
        }

        int end_of_object = ((type_code == 14 || type_code == 15) && field_code == 1);
        
        int end_of_array = (parent_is_array & 1 && end_of_object);


        if (!nocomma && !end_of_array && !end_of_object)
            append(APPENDNOINDENT, SBUF(",\n"));

        if (end_of_array || end_of_object)
            append(APPENDNOINDENT, SBUF("\n"));

        if (DEBUG)
            printf("end of array: %d, end of object %d\n", end_of_array, end_of_object);

        if (!end_of_object && !end_of_array)
            _REQUIRE(1,1); 
        
        nocomma = 0;

        if (type_code == 0)
        {
            fprintf(stderr, "Invalid typecode 0 at %d\n", upto);

            return 0;
        }

        // fixed width hex types
        int hex_size =
            ( type_code == 4  ? 16 : // uint128
            ( type_code == 5  ? 32 : // uint256
            ( type_code == 17 ? 20 : // uint160
            ( type_code == 20 ? 12 : // uint96
            ( type_code == 21 ? 24 : // uint192
            ( type_code == 22 ? 48 : // uint384
            ( type_code == 23 ? 64 : // uint512
              0)))))));

        int known_type = hex_size > 0 ||
            (type_code >= 1 && type_code <= 3) ||    // uint16, uint32, uint64
            (type_code >= 6 && type_code <= 11) ||   // amount, vl, account, number, int32, int64
            type_code == 14 || type_code == 15 ||    // object, array
            type_code == 16 ||                       // uint8
            type_code == 18 || type_code == 19 ||    // pathset, vector256
            (type_code >= 24 && type_code <= 26);    // issue, xchain bridge, currency

        if (!known_type)
        {
            fprintf(stderr, "Error: unknown type code %d (field code %d), stopping\n", type_code, field_code);
            break;
        }

        if (parent_is_array & 1 && !end_of_object)
        {
            append(APPENDPARAMS, SBUF("{\n"));
            indent_level++;
        }

        if (!end_of_object)
        {
            // Unknown fields of a known type are still decoded (the wire
            // format only depends on the type), just under a placeholder name.
            char key[96];
            const char* fname = xd_field_name(type_code, field_code);
            if (fname)
                snprintf(key, sizeof(key), "\"%s\": ", fname);
            else
                snprintf(key, sizeof(key), "\"UnknownField_%d_%d\": ", type_code, field_code);
            APPENDS(APPENDPARAMS, key);
        }

        if (type_code == 18)
        {
            append(APPENDNOINDENT, SBUF("[\n"));
            indent_level++;
            append(APPENDPARAMS, SBUF("[\n"));
            indent_level++;

            int paths_complete = 0;
            for (int path_count = 0; 1; ++path_count)
            {
                REQUIRE(1);
                uint8_t path_type = *n;
                ADVANCE(1);
                
                if (path_type == 0x00U)
                {
                    paths_complete = 1;
                    break;
                }

                if (path_type == 0xFFU)
                {
                    append(APPENDNOINDENT, SBUF("\n"));
                    indent_level--;
                    append(APPENDPARAMS, SBUF("],\n"));
                    append(APPENDPARAMS, SBUF("[\n"));
                    indent_level++;
                    path_count = -1;
                    continue;
                }

                if (path_type & ~0x71U)
                {
                    fprintf(stderr, "Error: bad path element type 0x%02X\n", path_type);
                    break;
                }

                int has_account = path_type & 0x01U;
                int has_currency = path_type & 0x10U;
                int has_issuer = path_type & 0x20U;
                int has_mpt = path_type & 0x40U;

                int need = (has_account ? 20 : 0) + (has_currency ? 20 : 0) + (has_mpt ? 24 : 0) + (has_issuer ? 20 : 0);
                REQUIRE(need);

                if (path_count > 0)
                    append(APPENDNOINDENT, SBUF(",\n"));

                append(APPENDPARAMS, SBUF("{\n"));
                indent_level++;

                char line[160];
                snprintf(line, sizeof(line), "\"type\": %d", path_type);
                APPENDS(APPENDPARAMS, line);

                if (has_account)
                {
                    char acc[64];
                    if (!xd_account(acc, sizeof(acc), n))
                    {
                        fprintf(stderr, "Error: could not base58 encode\n");
                        return 0;
                    }
                    snprintf(line, sizeof(line), ",\n");
                    APPENDS(APPENDNOINDENT, line);
                    snprintf(line, sizeof(line), "\"account\": \"%s\"", acc);
                    APPENDS(APPENDPARAMS, line);
                    ADVANCE(20);
                }

                if (has_currency)
                {
                    char currency[41];
                    xd_currency(currency, n);
                    APPENDS(APPENDNOINDENT, ",\n");
                    snprintf(line, sizeof(line), "\"currency\": \"%s\"", currency);
                    APPENDS(APPENDPARAMS, line);
                    ADVANCE(20);
                }

                if (has_mpt)
                {
                    char hex[49];
                    HEX(hex, n, 24);
                    hex[48] = '\0';
                    APPENDS(APPENDNOINDENT, ",\n");
                    snprintf(line, sizeof(line), "\"mpt_issuance_id\": \"%s\"", hex);
                    APPENDS(APPENDPARAMS, line);
                    ADVANCE(24);
                }

                if (has_issuer)
                {
                    char acc[64];
                    if (!xd_account(acc, sizeof(acc), n))
                    {
                        fprintf(stderr, "Error: could not base58 encode\n");
                        return 0;
                    }
                    APPENDS(APPENDNOINDENT, ",\n");
                    snprintf(line, sizeof(line), "\"issuer\": \"%s\"", acc);
                    APPENDS(APPENDPARAMS, line);
                    ADVANCE(20);
                }

                append(APPENDNOINDENT, SBUF("\n"));
                indent_level--;
                append(APPENDPARAMS, SBUF("}"));

            }
            append(APPENDNOINDENT, SBUF("\n"));
            indent_level--;
            append(APPENDPARAMS, SBUF("]\n"));
            indent_level--;
            append(APPENDPARAMS, SBUF("]"));

            if (!paths_complete)
                break;  // malformed or truncated (REQUIRE only exits the inner loop)

        }
        else if (type_code == 14)
        {   // object
            if (field_code == 1)
            {
                indent_level--;
                object_level--;
                append(APPENDPARAMS, SBUF("}"));
                parent_is_array >>= 1U;
                if (parent_is_array & 1)
                {
                    indent_level--;
                    append(APPENDNOINDENT, SBUF("\n"));
                    append(APPENDPARAMS, SBUF("}"));
                }
            }
            else
            {
                append(APPENDNOINDENT, SBUF("{\n"));
                object_level++;
                indent_level++;
                nocomma = 1;
                parent_is_array <<= 1U;
            }
        }
        else if (type_code == 15)
        {   // array
            if (field_code == 1)
            {
                indent_level--;
                array_level--;
                append(APPENDPARAMS, SBUF("]"));
                parent_is_array >>= 1U;
                if (parent_is_array & 1)
                {
                    indent_level--;
                    append(APPENDNOINDENT, SBUF("\n"));
                    append(APPENDPARAMS, SBUF("}"));
                }
            }
            else
            {
                append(APPENDNOINDENT, SBUF("[\n"));
                array_level++;
                indent_level++;
                nocomma = 1;
                parent_is_array <<= 1U;
                parent_is_array |= 1U;
            }
        }
        else if (type_code == 8) // account (variable length, always 20 bytes in practice)
        {
            int acc_len = 0;
            READ_VL(acc_len);
            REQUIRE(acc_len);

            if (acc_len == 20)
            {
                char acc[64];
                if (!xd_account(acc, sizeof(acc), n))
                {
                    fprintf(stderr, "Error: could not base58 encode\n");
                    return 0;
                }
                append(APPENDNOINDENT, SBUF("\""));
                APPENDS(APPENDNOINDENT, acc);
                append(APPENDNOINDENT, SBUF("\""));
            }
            else
            {
                // not a valid account, show what is there
                char hexout[2 * 192 + 1];
                int l = acc_len > 192 ? 192 : (int)acc_len;
                HEX(hexout, n, l);
                hexout[2 * l] = '\0';
                append(APPENDNOINDENT, SBUF("\""));
                APPENDS(APPENDNOINDENT, hexout);
                append(APPENDNOINDENT, SBUF("\""));
            }
            ADVANCE(acc_len);
        }
        else if (hex_size > 0)
        {
            // uint96 .. uint512
            REQUIRE(hex_size);
            
            append(APPENDNOINDENT, SBUF("\""));
            char hexout[129];
            HEX(hexout, n, hex_size);
            append(APPENDNOINDENT, hexout, hex_size*2);
            append(APPENDNOINDENT, SBUF("\""));

            ADVANCE(hex_size);    
        }
        else if (type_code == 7) // blob
        {
            int field_len = 0;
            READ_VL(field_len);
            REQUIRE(field_len);

            append(APPENDNOINDENT, SBUF("\""));
            char hexout[1024];
            int already_printed = 0;
            int to_print = field_len - already_printed;
            while (to_print > 0)
            {
                if (to_print > sizeof(hexout)/2)
                    to_print = sizeof(hexout)/2;
                HEX(hexout, n + already_printed, to_print);
                append(APPENDNOINDENT, hexout, to_print*2);
                already_printed += to_print;
                to_print = field_len - already_printed;
            }

            append(APPENDNOINDENT, SBUF("\""));

            ADVANCE(field_len);
        }
        else if (type_code == 19) // vector256
        {
            int field_len = 0;
            READ_VL(field_len);
            REQUIRE(field_len);

            if (field_len % 32 != 0)
            {
                fprintf(stderr, "Error: Vector256 length %d is not a multiple of 32\n", (int)field_len);
                break;
            }

            append(APPENDNOINDENT, SBUF("[\n"));
            for (int i = 0; i < field_len / 32; ++i)
            {
                char hexout[68];
                hexout[0] = '"';
                HEX(hexout + 1, n + i * 32, 32);
                hexout[65] = '"';
                hexout[66] = '\0';
                if (i > 0)
                    append(APPENDNOINDENT, SBUF(",\n"));
                append(indent_level + 1, output, &upto, &len, write_fd, hexout, 67);
            }
            if (field_len > 0)
                append(APPENDNOINDENT, SBUF("\n"));
            append(APPENDPARAMS, SBUF("]"));

            ADVANCE(field_len);
        }
        else if (type_code == 6) // amount
        {
            REQUIRE(1);
            if ((*n) >> 7U)
            {
                // issued currency
                REQUIRE(48);
                int is_neg = ((*n >> 6U) & 1U) == 0;
                int32_t exp = (int32_t)(((((uint16_t)(*n)) << 8U) | (uint16_t)(*(n+1))) >> 6U & 0xFFU) - 97;
                uint64_t mantissa = be64(n) & 0x003FFFFFFFFFFFFFULL;

                char currency[41];
                xd_currency(currency, n + 8);

                char issuer[64];
                if (!xd_account(issuer, sizeof(issuer), n + 28))
                {
                    fprintf(stderr, "Error: could not base58 encode\n");
                    return 0;
                }

                char str[1024];
                uint8_t fixed[128];
                if (to_fixed_point(fixed, sizeof(fixed), mantissa, exp, is_neg && mantissa) == -1)
                    snprintf((char*)fixed, sizeof(fixed), "\"%s%llue%d\"",
                            (is_neg ? "-" : ""), (unsigned long long)mantissa, exp);

                append(APPENDNOINDENT, SBUF("{\n"));
                snprintf(str, sizeof(str), "\t\"value\": %s,\n", fixed);
                APPENDS(APPENDPARAMS, str);
                snprintf(str, sizeof(str), "\t\"currency\": \"%s\",\n", currency);
                APPENDS(APPENDPARAMS, str);
                snprintf(str, sizeof(str), "\t\"issuer\": \"%s\"\n", issuer);
                APPENDS(APPENDPARAMS, str);
                append(APPENDPARAMS, SBUF("}"));
                ADVANCE(48);
            }
            else if ((*n) & 0x20U)
            {
                // MPT amount: flags(1) | value(8) | MPTID(24)
                REQUIRE(33);
                int is_neg = ((*n >> 6U) & 1U) == 0;
                uint64_t value = be64(n + 1);
                char id[49];
                HEX(id, n + 9, 24);
                id[48] = '\0';

                char str[256];
                append(APPENDNOINDENT, SBUF("{\n"));
                snprintf(str, sizeof(str), "\t\"mpt_issuance_id\": \"%s\",\n", id);
                APPENDS(APPENDPARAMS, str);
                snprintf(str, sizeof(str), "\t\"value\": \"%s%llu\"\n",
                        (is_neg && value ? "-" : ""), (unsigned long long)value);
                APPENDS(APPENDPARAMS, str);
                append(APPENDPARAMS, SBUF("}"));
                ADVANCE(33);
            }
            else
            {
                // native
                REQUIRE(8);
                char str[32];
                int negative = ((*n) >> 6U == 0);
                uint64_t number = be64(n) & 0x3FFFFFFFFFFFFFFFULL;
                int l = snprintf(str, sizeof(str), "\"%s%llu\"", (negative ? "-" : ""), (unsigned long long)number); 
                append(APPENDNOINDENT, str, l + 1);
                ADVANCE(8);
            }
        }
        else if (type_code == 9) // number: int64 mantissa, int32 exponent
        {
            REQUIRE(12);
            int64_t m = (int64_t)be64(n);
            int32_t e = (int32_t)be32(n + 8);
            int neg = m < 0;
            uint64_t um = neg ? (uint64_t)(-(m + 1)) + 1U : (uint64_t)m;

            uint8_t fixed[128];
            if (to_fixed_point(fixed, sizeof(fixed), um, e, neg) == -1)
                snprintf((char*)fixed, sizeof(fixed), "\"%s%llue%d\"", (neg ? "-" : ""), (unsigned long long)um, e);
            APPENDS(APPENDNOINDENT, (char*)fixed);
            ADVANCE(12);
        }
        else if (type_code == 24) // issue
        {
            REQUIRE(20);
            if (!is_zero(n, 20))
            {
                REQUIRE(40);
                if (is_no_account(n + 20))
                    REQUIRE(44);
            }
            char str[512];
            int used = xd_issue_json(str, sizeof(str), n, indent_level);
            if (used < 0)
            {
                fprintf(stderr, "Error: could not decode Issue\n");
                return 0;
            }
            APPENDS(APPENDNOINDENT, str);
            ADVANCE(used);
        }
        else if (type_code == 25) // xchain bridge: account, issue, account, issue
        {
            int off = 0, sides_done = 0;
            int door[2], issue[2];
            for (int side = 0; side < 2; ++side)
            {
                REQUIRE(off + 1);
                if (n[off] != 20)
                {
                    fprintf(stderr, "Error: unexpected XChainBridge door account length %d\n", n[off]);
                    off = -1;
                    break;
                }
                door[side] = off + 1;
                off += 21;
                REQUIRE(off + 20);
                if (!is_zero(n + off, 20))
                {
                    REQUIRE(off + 40);
                    if (is_no_account(n + off + 20))
                        REQUIRE(off + 44);
                }
                issue[side] = off;
                off += xd_issue_len(n + off);
                sides_done = side + 1;
            }
            if (off < 0 || sides_done != 2)
                break;  // malformed or truncated (REQUIRE only exits the inner loop)

            static const char* names[2][2] = {
                { "LockingChainDoor", "LockingChainIssue" },
                { "IssuingChainDoor", "IssuingChainIssue" } };
            char t1[32];
            xd_tabs(t1, indent_level + 1);
            append(APPENDNOINDENT, SBUF("{\n"));
            for (int side = 0; side < 2; ++side)
            {
                char acc[64], iss[512], str[700];
                if (!xd_account(acc, sizeof(acc), n + door[side]) ||
                    xd_issue_json(iss, sizeof(iss), n + issue[side], indent_level + 1) < 0)
                {
                    fprintf(stderr, "Error: could not decode XChainBridge\n");
                    return 0;
                }
                snprintf(str, sizeof(str), "%s\"%s\": \"%s\",\n%s\"%s\": %s%s\n",
                        t1, names[side][0], acc, t1, names[side][1], iss, side == 0 ? "," : "");
                APPENDS(APPENDNOINDENT, str);
            }
            append(APPENDPARAMS, SBUF("}"));
            ADVANCE(off);
        }
        else if (type_code == 26) // currency
        {
            REQUIRE(20);
            char currency[41], str[48];
            xd_currency(currency, n);
            snprintf(str, sizeof(str), "\"%s\"", currency);
            APPENDS(APPENDNOINDENT, str);
            ADVANCE(20);
        }
        else // uint8, uint16, uint32, uint64, int32, int64
        {
            uint64_t number = 0;
            int64_t snumber = 0;
            int is_signed = 0;
            const char* name = 0;

            if (type_code == 1) // uint16
            {
                REQUIRE(2);
                number = ((uint64_t)(*(n+0)) << 8U) + (uint64_t)(*(n+1));
                ADVANCE(2);

                if (field_code == 2)
                    name = xd_tx_name((int)number);       // TransactionType
                else if (field_code == 1)
                    name = xd_le_name((int)number);       // LedgerEntryType
            }
            else if (type_code == 2) // uint32
            {
                REQUIRE(4);
                number = be32(n);
                ADVANCE(4);
            }
            else if (type_code == 3) // uint64
            {
                REQUIRE(8);
                number = be64(n);
                ADVANCE(8);
            }
            else if (type_code == 10) // int32
            {
                REQUIRE(4);
                snumber = (int32_t)be32(n);
                is_signed = 1;
                ADVANCE(4);
            }
            else if (type_code == 11) // int64
            {
                REQUIRE(8);
                snumber = (int64_t)be64(n);
                is_signed = 1;
                ADVANCE(8);
            }
            else // uint8
            {
                REQUIRE(1);
                number = *n;
                ADVANCE(1);

                if (field_code == 3)
                    name = xd_ter_name((int)number);      // TransactionResult
            }

            char str[128];
            if (name)
                snprintf(str, sizeof(str), "\"%s\"", name);
            else if (is_signed)
                snprintf(str, sizeof(str), "%lld", (long long)snumber);
            else
                snprintf(str, sizeof(str), "%llu", (unsigned long long)number);
            APPENDS(APPENDNOINDENT, str);
        }
    }

    

    indent_level--;
    append(APPENDNOINDENT, SBUF("\n"));
    append(APPENDPARAMS, SBUF("}\n"));

    return 1;
}


int stream_refill(uint8_t* input, int input_len, int min_bytes_to_return, int read_fd)
{
    int upto = 0;
    char byte[2];
    int bytes_read = 0;
    do
    {
//        printf("\n  A:\n");
        bytes_read = read(read_fd, &(byte[0]), 1);
        if (bytes_read > 0)
        {
            if (byte[0] == ' ' || byte[0] == '\n' || byte[0] == '\r' || byte[0] == '\t')
                continue;
        }
        else
            break;
        
        half_continue:
//        printf("\n  B:\n");
        bytes_read = read(read_fd, &(byte[1]), 1);
        if (bytes_read > 0)
        {
            if (byte[1] == ' ' || byte[1] == '\n' || byte[1] == '\r' || byte[1] == '\t')
                goto half_continue;
        }
        else
            break;

        // execution to here means two bytes
        
        uint8_t hi = byte[0];
        uint8_t lo = byte[1];

        int error = 0;
        hi =    (hi >= 'A' && hi <= 'F' ? hi - 'A' + 10 :
                (hi >= 'a' && hi <= 'f' ? hi - 'a' + 10 : 
                (hi >= '0' && hi <= '9' ? hi - '0' :
                 (error=1) )));
    
        lo =    (lo >= 'A' && lo <= 'F' ? lo - 'A' + 10 :
                (lo >= 'a' && lo <= 'f' ? lo - 'a' + 10 : 
                (lo >= '0' && lo <= '9' ? lo - '0' :
                 (error=1) )));


        if (error)
        {
            fprintf(stderr, "Error: Garbage (non hex and non whitespace characters) in input stream\n");
            exit(1);
        }

        input[upto++] = (hi << 4U) + lo;
    }
    while (upto < min_bytes_to_return);

    //printf("upto: %d bytes read: %d\n", upto, bytes_read);
    if (bytes_read<= 0 && upto == 0)
        return -1;

    return upto;
}

/*
int main(int argc, char** argv)
{
    b58_sha256_impl = calc_sha_256;
    
    int print_help =
        (argc != 2) ||
        (argc == 2 && (strcmp(argv[1], "--help") == 0));

    if (print_help)
        return fprintf(stderr, "Usage: %s HEXBLOB | hex file | - for stdin\n", argv[0]);

    if (strcmp(argv[1], "-") == 0)
    {
        // stream mode
        return deserialize(0, 0, 0, stream_refill, 0, 1);
    }
    struct stat dummy;
    if (lstat(argv[1], &dummy) != -1)
    {
        // stream mode but from file
        int fd = open(argv[1], O_RDONLY);
        if (fd < 0)
            return fprintf(stderr, "Could not open file `%s`\n", argv[1]);
        return deserialize(0, 0, 0, stream_refill, fd, 1);
    }


    // hex conversion
    int hexlen = strlen(argv[1]);
    if (hexlen % 2 == 1)
        return fprintf(stderr, "Hex length must be even\n");

    int len = hexlen/2 + 1;
    uint8_t* rawbytes = malloc(len);
    uint8_t* rawupto = rawbytes;
    int error = 0;
    for (char* x = argv[1]; *x;  x+=2)
    {
        uint8_t hi = *x;
        uint8_t lo = *(x+1);

        hi =    (hi >= 'A' && hi <= 'F' ? hi - 'A' + 10 :
                (hi >= 'a' && hi <= 'f' ? hi - 'a' + 10 : 
                (hi >= '0' && hi <= '9' ? hi - '0' :
                 (error=1) )));
    
        lo =    (lo >= 'A' && lo <= 'F' ? lo - 'A' + 10 :
                (lo >= 'a' && lo <= 'f' ? lo - 'a' + 10 : 
                (lo >= '0' && lo <= '9' ? lo - '0' :
                 (error=1) )));

        *rawupto++ = (hi << 4U) + lo;
    }
    *rawupto++ = 0; // hacky :(

    if (error)
        return fprintf(stderr, "Non-hex nibble detected\n");

    uint8_t* output = 0;
    if (!deserialize(&output, rawbytes, len, 0, 0, 0))
        return fprintf(stderr, "Could not deserialize\n");

    printf("%s\n", output);

    return 0;
}
*/

}
