#include <assert.h>
#include <stdio.h>

#include "libinjection.h"
#include "libinjection_sqli.h"
#include "libinjection_html5.h"
#include "libinjection_xss.h"

struct byte_input {
    const char* name;
    const unsigned char* data;
    size_t len;
};

static void assert_sqli_safe_failure(const struct byte_input* input)
{
    sfilter state;
    char fingerprint[8];

    fingerprint[0] = 'x';
    assert(libinjection_sqli((const char*) input->data, input->len,
                             fingerprint) == 0);
    assert(fingerprint[0] == '\0');

    libinjection_sqli_init(&state, (const char*) input->data, input->len, 0);
    assert(state.input_valid == 0);
    assert(libinjection_is_sqli(&state) == 0);
    assert(state.fingerprint[0] == '\0');
    assert(libinjection_sqli_tokenize(&state) == 0);
    assert(libinjection_sqli_fold(&state) == 0);
    assert(libinjection_sqli_fingerprint(&state, 0)[0] == '\0');
    assert(libinjection_sqli_blacklist(&state) == 0);
    assert(libinjection_sqli_not_whitelist(&state) == 0);
    assert(libinjection_sqli_check_fingerprint(&state) == 0);
}

static void assert_xss_safe_failure(const struct byte_input* input)
{
    h5_state_t html;

    assert(libinjection_xss((const char*) input->data, input->len) == 0);
    assert(libinjection_is_xss((const char*) input->data, input->len,
                               DATA_STATE) == 0);

    libinjection_h5_init(&html, (const char*) input->data, input->len,
                         DATA_STATE);
    assert(html.input_valid == 0);
    assert(libinjection_h5_next(&html) == 0);
}

int main(void)
{
    static const unsigned char nul_sqli[] = {
        '1', 0, 'O', 'R', 0, '1', '=', 0, '1'
    };
    static const unsigned char nul_xss[] = {
        '<', 0, 's', 'c', 'r', 'i', 'p', 't', '>'
    };
    static const unsigned char truncated_two[] = { '1', 0xC2, ' ' };
    static const unsigned char truncated_three[] = { 0xE2, 0x82 };
    static const unsigned char truncated_four[] = { 0xF0, 0x9F, 0x98 };
    static const unsigned char standalone_high_byte[] = { 0xA0 };
    static const unsigned char valid_utf8[] = {
        '1', ' ', 0xC2, 0xA9, ' ', 0xE2, 0x82, 0xAC, ' ',
        0xF0, 0x9F, 0x98, 0x80
    };
    static const unsigned char legacy_binary[] = {
        '1', 0xA0, 'U', 'N', 'I', 'O', 'N', 0xA0,
        'S', 'E', 'L', 'E', 'C', 'T', 0xA0, '2', '-', '-'
    };
    static const unsigned char binary_literal[] = "b'1010'";
    static const unsigned char xss_utf8[] = {
        '<', 0xC2, 0xA9, ' ', 'o', 'n', 'e', 'r', 'r', 'o', 'r',
        '=', 'a', 'l', 'e', 'r', 't', '(', '1', ')', '>'
    };
    static const struct byte_input invalid[] = {
        { "embedded NUL in SQL", nul_sqli, sizeof(nul_sqli) },
        { "embedded NUL in HTML", nul_xss, sizeof(nul_xss) },
        { "truncated two-byte UTF-8", truncated_two,
          sizeof(truncated_two) },
        { "truncated three-byte UTF-8", truncated_three,
          sizeof(truncated_three) },
        { "truncated four-byte UTF-8", truncated_four,
          sizeof(truncated_four) }
    };
    sfilter sqli;
    h5_state_t html;
    h5_state_t legacy_html;
    size_t i;
    int token_count;

    for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        assert_sqli_safe_failure(&invalid[i]);
        assert_xss_safe_failure(&invalid[i]);
    }

    /* Complete UTF-8 sequences still use the ordinary byte parser. */
    libinjection_sqli_init(&sqli, (const char*) valid_utf8,
                           sizeof(valid_utf8), 0);
    assert(sqli.input_valid == 1);
    token_count = 0;
    while (libinjection_sqli_tokenize(&sqli)) {
        token_count += 1;
    }
    assert(token_count == 4);

    /* Legacy single high bytes and SQL binary literals remain unchanged. */
    libinjection_sqli_init(&sqli, (const char*) legacy_binary,
                           sizeof(legacy_binary), 0);
    assert(sqli.input_valid == 1);
    token_count = 0;
    while (libinjection_sqli_tokenize(&sqli)) {
        token_count += 1;
    }
    assert(token_count == 5);

    /* High bytes not introduced by a UTF-8 lead remain binary input. */
    libinjection_sqli_init(&sqli, (const char*) standalone_high_byte,
                           sizeof(standalone_high_byte), 0);
    assert(sqli.input_valid == 1);
    libinjection_h5_init(&legacy_html, (const char*) standalone_high_byte,
                         sizeof(standalone_high_byte), DATA_STATE);
    assert(legacy_html.input_valid == 1);

    libinjection_sqli_init(&sqli, (const char*) binary_literal,
                           sizeof(binary_literal) - 1, 0);
    assert(sqli.input_valid == 1);
    assert(libinjection_sqli_tokenize(&sqli) == 1);
    assert(sqli.current->type == '1');

    libinjection_h5_init(&html, (const char*) xss_utf8, sizeof(xss_utf8),
                         DATA_STATE);
    assert(html.input_valid == 1);
    assert(libinjection_xss((const char*) xss_utf8,
                            sizeof(xss_utf8)) == 1);

    printf("input safety tests passed\n");
    return 0;
}
