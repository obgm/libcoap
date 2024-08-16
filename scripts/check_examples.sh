#!/bin/bash

rm -f man/tmp/*.c
man/examples-code-check man
EXIT1=$?
git add -f man/tmp/*.c
pre-commit run --all-files
EXIT2=$?
git diff man/tmp/*.c > man/tmp/diff-check
git restore man/tmp/*.c
git restore --staged man/tmp/*.c
cat man/tmp/diff-check
WC=`cat man/tmp/diff-check | wc -l`
if test "$EXIT1" != "0" || test "$EXIT2" != "0" || test "$WC" != "0" ; then
	exit 1
else
	exit 0
fi
