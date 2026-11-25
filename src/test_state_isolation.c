/*
 * Regression tests for per-request state isolation.
 *
 * A long running scanner reuses the same state structure for many
 * inputs.  Nothing produced while scanning one input may leak into the
 * next one:
 *
 *   * the HTML5 parser must always end in its terminal state so a
 *     truncated tag can not leave a live state function behind that
 *     would be re-entered against the next input;
 *   * the SQLi detection entry points must reset every field (tokens,
 *     fingerprint, counters and the current-token pointer) on each run;
 *   * repeated ("replayed") detections on one input must keep returning
 *     identical results.
 */
#include <stdio.h>
#include <string.h>

#include "libinjection.h"
#include "libinjection_sqli.h"
#include "libinjection_html5.h"
#include "libinjection_xss.h"

static int test_html5_terminal_state(void)
{
    /* every input that ends inside an unfinished tag must still park
     * the state machine on h5_state_eof */
    static const char* truncated[] = {
        "<",
        "</",
        "<a ",
        "<a/",
        "<a x",
        "<a x=",
        "<a x='",
        "<a x=\"",
        "<?foo",
        NULL
    };

    h5_state_t hs;
    int i;

    for (i = 0; truncated[i] != NULL; ++i) {
        libinjection_h5_init(&hs, truncated[i], strlen(truncated[i]),
                             DATA_STATE);
        while (libinjection_h5_next(&hs)) {
            /* drain the whole scan */
        }

        /* once a scan reports completion it must stay completed */
        if (libinjection_h5_next(&hs) != 0) {
            fprintf(stderr, "h5 scan of '%s' did not terminate\n",
                    truncated[i]);
            return 1;
        }

        /* simulate a scanner that only rewinds position for the next
         * input: the stale terminal state must keep returning 0 rather
         * than mis-tokenizing the new buffer */
        hs.s = "plain text";
        hs.len = strlen(hs.s);
        hs.pos = 0;
        if (libinjection_h5_next(&hs) != 0) {
            fprintf(stderr, "stale h5 state leaked into new input "
                    "after scanning '%s'\n", truncated[i]);
            return 1;
        }
    }

    /* a properly re-initialized scan still works after a truncated one */
    libinjection_h5_init(&hs, "plain text", 10, DATA_STATE);
    if (! libinjection_h5_next(&hs) ||
        hs.token_type != DATA_TEXT ||
        hs.token_len != 10) {
        fprintf(stderr, "h5 re-initialization lost the fresh input\n");
        return 1;
    }
    return 0;
}

static int test_sqli_state_isolation(void)
{
    sfilter sf;
    const char* attack = "1' UNION SELECT password FROM users-- x";
    const char* benign = "hello world";
    char fingerprint[8];

    /* first request leaves a fully populated state behind */
    libinjection_sqli_init(&sf, attack, strlen(attack), 0);
    if (! libinjection_is_sqli(&sf)) {
        fprintf(stderr, "sanity check failed: attack not detected\n");
        return 1;
    }
    if (sf.fingerprint[0] == '\0' || sf.stats_tokens == 0) {
        fprintf(stderr, "sanity check failed: state not populated\n");
        return 1;
    }

    /* an empty request on the reused state must wipe the prior run */
    sf.s = "";
    sf.slen = 0;
    if (libinjection_is_sqli(&sf) != 0) {
        fprintf(stderr, "empty input reported as SQLi\n");
        return 1;
    }
    if (sf.fingerprint[0] != '\0' || sf.stats_tokens != 0 ||
        sf.pos != 0 || sf.current != &(sf.tokenvec[0])) {
        fprintf(stderr, "empty input did not isolate prior SQLi state\n");
        return 1;
    }

    /* a benign request must produce the same answer whether the state
     * is brand new or reused from the attack/empty sequence */
    libinjection_sqli_init(&sf, benign, strlen(benign), 0);
    if (libinjection_is_sqli(&sf) != 0 ||
        strcmp(sf.fingerprint, "nn") != 0) {
        fprintf(stderr, "benign input affected by previous SQLi state\n");
        return 1;
    }

    if (libinjection_sqli(benign, strlen(benign), fingerprint) != 0 ||
        fingerprint[0] != '\0') {
        fprintf(stderr, "one-shot SQLi API returned stale result\n");
        return 1;
    }
    return 0;
}

static int test_sqli_streaming_restart(void)
{
    sfilter sf;
    const char* first = "1 union select a from b";
    const char* second = "dog";

    /* stop the first scan partway through, like a segment boundary */
    libinjection_sqli_init(&sf, first, strlen(first), 0);
    (void) libinjection_sqli_tokenize(&sf);
    (void) libinjection_sqli_tokenize(&sf);

    /* starting a fresh detection must write from tokenvec[0] again */
    libinjection_sqli_init(&sf, second, strlen(second), 0);
    if (! libinjection_sqli_tokenize(&sf)) {
        fprintf(stderr, "restarted tokenizer produced no token\n");
        return 1;
    }
    if (sf.current != &(sf.tokenvec[0]) ||
        sf.current->type != 'n' ||
        strcmp(sf.current->val, "dog") != 0) {
        fprintf(stderr, "restarted tokenizer did not begin at token 0\n");
        return 1;
    }
    return 0;
}

static int test_replays_are_stable(void)
{
    static const char* inputs[] = {
        "1 union select * from foo",
        "1' or '1'='1",
        "just some normal text",
        "<script>alert(1)</script>",
        "<b>bold</b>",
        NULL
    };
    int i;

    for (i = 0; inputs[i] != NULL; ++i) {
        char fp_a[8];
        char fp_b[8];
        int sqli_a = libinjection_sqli(inputs[i], strlen(inputs[i]), fp_a);
        int sqli_b = libinjection_sqli(inputs[i], strlen(inputs[i]), fp_b);
        int xss_a = libinjection_xss(inputs[i], strlen(inputs[i]));
        int xss_b = libinjection_xss(inputs[i], strlen(inputs[i]));

        if (sqli_a != sqli_b || strcmp(fp_a, fp_b) != 0) {
            fprintf(stderr, "SQLi replay mismatch for '%s'\n", inputs[i]);
            return 1;
        }
        if (xss_a != xss_b) {
            fprintf(stderr, "XSS replay mismatch for '%s'\n", inputs[i]);
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    if (test_html5_terminal_state() != 0) {
        return 1;
    }
    if (test_sqli_state_isolation() != 0) {
        return 1;
    }
    if (test_sqli_streaming_restart() != 0) {
        return 1;
    }
    if (test_replays_are_stable() != 0) {
        return 1;
    }
    printf("state isolation tests passed\n");
    return 0;
}
