#include "libinjection.h"
#include "libinjection_html5.h"
#include "libinjection_xss.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(int condition, const char* message)
{
    if (!condition) {
        printf("FAIL: %s\n", message);
        failures++;
    }
}

static size_t min_size(size_t a, size_t b)
{
    return a < b ? a : b;
}

/*
 * Feeds every possible two-chunk split.  The final streaming result must be
 * identical to a fresh cold call on the reassembled byte string.
 */
static void check_all_splits(const char* input, int expected,
                             const char* label)
{
    size_t total = strlen(input);
    size_t split;

    check(libinjection_xss(input, total) == expected, label);

    for (split = 1; split < total; ++split) {
        libinjection_xss_stream_t stream;
        char message[256];
        int first_result;
        int second_result;

        libinjection_xss_stream_init(&stream);

        first_result = libinjection_xss_stream_feed(&stream, input, split);
        check(first_result == libinjection_xss(input, split),
              "partial chunk result did not match its cold scan");

        second_result = libinjection_xss_stream_feed(
            &stream, input + split, total - split);

        snprintf(message, sizeof(message),
                 "%s: split at %u changed the XSS result",
                 label, (unsigned) split);
        check(second_result == expected, message);
        check(libinjection_xss_stream_result(&stream) == expected, message);
        check(libinjection_xss(stream.buffer, stream.len) == expected,
              "cold review did not see the reassembled XSS state");

        libinjection_xss_stream_destroy(&stream);
    }
}

static void check_h5_resume(void)
{
    static const char input[] = "<script>alert(1)</script>";
    size_t total = sizeof(input) - 1;
    size_t split;

    /* Split inside the tag name, before the six-byte "script" is complete. */
    split = (size_t) ((const char*) memchr(input, 'r', total) - input);
    {
        h5_state_t h5;
        int saw_script = 0;

        libinjection_h5_init(&h5, input, split, DATA_STATE);
        while (libinjection_h5_next(&h5)) {
            /* Drain the provisional chunk-end tokens. */
        }

        libinjection_h5_attach(&h5, input, total);
        while (libinjection_h5_next(&h5)) {
            if (h5.token_type == TAG_NAME_OPEN &&
                h5.token_len == 6 &&
                strncmp(h5.token_start, "script",
                        min_size(h5.token_len, 6)) == 0) {
                saw_script = 1;
            }
        }
        check(saw_script, "HTML5 tokenizer did not resume a split tag name");
    }
}

int main(void)
{
    static const char* attacks[] = {
        "<script>alert(1)</script>",
        "<scr" "ipt>alert(1)</scr" "ipt>",
        "<img src=x onerror=alert(1)>",
        "<a href=\"javascript:alert(1)\">click</a>",
        NULL
    };
    static const char* benign[] = {
        "script text is ordinary",
        "if (a < b && c > d) { script(); }",
        "<scriptx>ordinary text</scriptx>",
        "<p>normal HTML paragraph</p>",
        "<div class=\"note\">2 < 3 and 4 > 1</div>",
        "<button type=\"button\">Save</button>",
        NULL
    };
    size_t i;

    for (i = 0; attacks[i] != NULL; ++i) {
        check_all_splits(attacks[i], 1, "XSS attack");
    }
    for (i = 0; benign[i] != NULL; ++i) {
        check_all_splits(benign[i], 0, "benign input");
    }
    check_h5_resume();

    if (failures != 0) {
        printf("%d chunk XSS check(s) failed\n", failures);
        return 1;
    }
    printf("chunk XSS checks passed\n");
    return 0;
}
