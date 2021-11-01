extern "C" {

extern bool (*b58_sha256_impl)(void *, const void *, size_t);
int deserialize(
    uint8_t** output,
    uint8_t* input,
    int input_len, 
    int (*fetch_data_func)(uint8_t*, int, int, int), // may be null, refills the input buffer with whatever is available
    int read_fd,    // may be 0 if unused, the fd to pass to fetch_data_func (if applicable)
    int write_fd);   // may be 0 if unused, the fd to write output to, if not specified then *output buffer is used
}
