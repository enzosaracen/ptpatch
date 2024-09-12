#!/bin/bash

INP="stub.c"
OUT1="stub-p1.c"
OUT2="stub-p2.c"
OUT3="stub-p3.c"

sed '/\/\/ add hooks here/,$d' $INP > $OUT1
sed -n '/\/\/ add hooks here/,/\/\/ add breakpoints here/{//!p}' $INP > $OUT2
sed -n '/\/\/ add breakpoints here/,$p' $INP | sed '1d' > $OUT3
