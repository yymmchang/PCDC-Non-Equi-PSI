#!/bin/bash
#supply log of number of elements as first command line argument
./s6 $1 1 $2 &\
./s6 $1 2 $2
