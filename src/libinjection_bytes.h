#ifndef LIBINJECTION_BYTES_H
#define LIBINJECTION_BYTES_H

#include <stddef.h>

/*
 * Reject NUL bytes and incomplete/malformed UTF-8 lead sequences.
 *
 * The analyzers historically treat their input as arbitrary bytes.
 * Standalone continuation bytes and legacy encodings therefore remain
 * valid binary input, but a lead byte must have all of its expected
 * continuation bytes so different callers do not split a character at
 * different parser boundaries.
 */
static int libinjection_bytes_are_safe(const char* s, size_t len)
{
    size_t i = 0;

    if (s == NULL) {
        return len == 0;
    }

    while (i < len) {
        unsigned char c = (unsigned char) s[i];
        size_t expected;
        size_t j;

        if (c == 0) {
            return 0;
        }

        if (c < 0x80) {
            i += 1;
            continue;
        }

        if (c < 0xC2) {
            /* C0/C1 overlong leads and standalone continuation bytes:
             * preserve legacy binary handling for these fixed-width
             * byte inputs.
             */
            i += 1;
            continue;
        } else if (c < 0xE0) {
            expected = 1;
        } else if (c < 0xF0) {
            expected = 2;
        } else if (c < 0xF5) {
            expected = 3;
        } else {
            /* Invalid UTF-8 lead, but still a complete single byte in
             * the library's traditional binary input model.
             */
            i += 1;
            continue;
        }

        if (len - i - 1 < expected) {
            return 0;
        }

        for (j = 1; j <= expected; ++j) {
            unsigned char next = (unsigned char) s[i + j];
            if (next < 0x80 || next > 0xBF) {
                return 0;
            }
        }

        i += expected + 1;
    }

    return 1;
}

#endif
