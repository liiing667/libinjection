#!/bin/sh
#
# Each sqli invocation is a fresh process.  This checks that a policy
# consumer restart sees the same attack identity as the public API call.

cd "$(dirname "$0")" || exit 2

failures=0

check_fingerprint() {
    expected="$1"
    input="$2"

    first=$(./sqli -d "$input")
    second=$(./sqli -d "$input")

    if [ "$first" != "$expected" ] || [ "$second" != "$expected" ]; then
        printf 'FAIL policy identity: expected %s, got "%s" and "%s" for %s\n' \
            "$expected" "$first" "$second" "$input"
        failures=$((failures + 1))
    else
        printf 'PASS policy identity: %s\n' "$input"
    fi
}

check_safe() {
    input="$1"

    first=$(./sqli -d "$input")
    second=$(./sqli -d "$input")

    if [ -n "$first" ] || [ -n "$second" ]; then
        printf 'FAIL policy identity: expected safe, got "%s" and "%s" for %s\n' \
            "$first" "$second" "$input"
        failures=$((failures + 1))
    else
        printf 'PASS policy identity: %s\n' "$input"
    fi
}

check_fingerprint 's&1c' "' OR 1=1 --"
check_fingerprint 's&1c' "' OR 1=1 --   "
check_fingerprint 'sc' "admin'--"
check_fingerprint 'sc' "admin'-- "
check_fingerprint '1&1c' '1 OR 1=1 -- '
check_safe 'regular product description'
check_safe '-- ordinary SQL comment'
check_safe '/* ordinary SQL comment */'
check_safe 'SELECT 1 -- ordinary SQL comment'
check_safe 'please review -- this is an ordinary note'
check_safe "x'-- release notes for this build"
check_safe 'a--b is ordinary text'

exit "$failures"
