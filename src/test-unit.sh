#!/bin/sh
set -e
cd ../tests
pwd

../src/teststateisolation

find . -name 'test*.txt' | xargs ${VALGRIND} ../src/testdriver
