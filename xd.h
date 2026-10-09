extern "C" {

// Which network's field / transaction / ledger-entry / result tables the
// deserializer uses. The wire format is shared, the tables are not.
#define XD_NETWORK_XRPL  0
#define XD_NETWORK_XAHAU 1
extern int xd_network;

// "XRP" or "XAH" depending on xd_network
const char* xd_native_currency(void);

extern bool (*b58_sha256_impl)(void *, const void *, size_t);
int deserialize(
    uint8_t** output,
    uint8_t* input,
    int input_len, 
    int (*fetch_data_func)(uint8_t*, int, int, int), // may be null, refills the input buffer with whatever is available
    int read_fd,    // may be 0 if unused, the fd to pass to fetch_data_func (if applicable)
    int write_fd);   // may be 0 if unused, the fd to write output to, if not specified then *output buffer is used
}
