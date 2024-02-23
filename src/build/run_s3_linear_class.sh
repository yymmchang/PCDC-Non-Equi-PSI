#!/bin/bash
#supply log of number of elements as first command line argument
./s3_linear-mismatch $1 1 &\
./s3_linear-mismatch $1 2
