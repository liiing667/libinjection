#ifndef LIBINJECTION_XSS
#define LIBINJECTION_XSS

#ifdef __cplusplus
extern "C" {
#endif

/**
 * HEY THIS ISN'T DONE
 */

/* pull in size_t */

#include <string.h>

  int libinjection_is_xss(const char* s, size_t len, int flags);

/*
 * Reassemble stream chunks and classify the complete bytes with the same
 * libinjection_xss() entry point used by a fresh/cold scan.  feed() returns
 * the current verdict (0 or 1), or -1 if reassembly ran out of memory.
 */
typedef struct libinjection_xss_stream {
    char* buffer;
    size_t len;
    size_t cap;
    int verdict;
} libinjection_xss_stream_t;

void libinjection_xss_stream_init(libinjection_xss_stream_t* stream);
int libinjection_xss_stream_feed(libinjection_xss_stream_t* stream,
                                const char* chunk, size_t chunk_len);
int libinjection_xss_stream_result(const libinjection_xss_stream_t* stream);
void libinjection_xss_stream_destroy(libinjection_xss_stream_t* stream);

#ifdef __cplusplus
}
#endif
#endif
