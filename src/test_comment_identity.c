#include <stdio.h>
#include <string.h>

#include "libinjection.h"

struct identity_case {
    const char *input;
    int attack;
    const char *fingerprint;
};

static int failures = 0;

static void check_identity(const struct identity_case *test)
{
    int call;

    /*
     * Repeated calls use a fresh state inside libinjection_sqli().  Filling
     * the output buffer first also proves the public API commits a NUL for
     * both detections and non-detections.
     */
    for (call = 0; call < 3; ++call) {
        char fingerprint[8];
        int actual;

        memset(fingerprint, 'X', sizeof(fingerprint));
        actual = libinjection_sqli(test->input, strlen(test->input),
                                  fingerprint);

        if (actual != test->attack) {
            printf("FAIL comment identity: expected %d got %d for %s\n",
                   test->attack, actual, test->input);
            ++failures;
            return;
        }

        if (test->attack) {
            if (strcmp(fingerprint, test->fingerprint) != 0) {
                printf("FAIL comment identity: expected %s got %s for %s\n",
                       test->fingerprint, fingerprint, test->input);
                ++failures;
                return;
            }
        } else if (fingerprint[0] != '\0') {
            printf("FAIL comment identity: expected empty fingerprint got %s "
                   "for %s\n", fingerprint, test->input);
            ++failures;
            return;
        }
    }

    printf("PASS comment identity: %s\n", test->input);
}

int main(void)
{
    static const struct identity_case tests[] = {
        { "' OR 1=1 --", 1, "s&1c" },
        { "' OR 1=1 --   \t", 1, "s&1c" },
        { "' OR 1=1 --\r\n", 1, "s&1c" },
        { "admin'--", 1, "sc" },
        { "admin'--   \t", 1, "sc" },
        { "admin'--\r\n", 1, "sc" },
        { "1 OR 1=1 -- ", 1, "1&1c" },
        { "regular product description", 0, "" },
        { "-- ordinary SQL comment", 0, "" },
        { "/* ordinary SQL comment */", 0, "" },
        { "SELECT 1 -- ordinary SQL comment", 0, "" },
        { "please review -- this is an ordinary note", 0, "" },
        { "x'-- release notes for this build", 0, "" },
        { "a--b is ordinary text", 0, "" }
    };
    size_t i;

    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
        check_identity(&tests[i]);
    }

    if (failures != 0) {
        printf("comment identity failures: %d\n", failures);
        return 1;
    }

    return 0;
}
