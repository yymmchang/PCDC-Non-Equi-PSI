#ifndef include__H
#define include__H

#include <math.h>
#include <stdio.h>


#undef PROGRESS
#undef INTERIMS
#define INTERIMS
//include "include-10.h"

#define UTYPE uint64_t

#define SIGMA 40
#define SENDER 1
#define RECEIVER 2

#define BLOCKLENGTH 16
#define HASHLENGTH 20

#define STRETCHFACTOR (1.27)
#define STRETCHFACTORSMALL (1.3)


#define PARTY(x) (((x==1)?"Sender" : "Receiver"))

//Blake2 _hash(HASHLENGTH);

//x = destination, y = source
#define extract128(x,y) (_mm_store_si128((__m128i*)x, y.mData))

#define store128(x) (_mm_loadu_si128((__m128i_u*)(x)))

//#define HASH(dest, src, length) (md_map_b2s160((uint8_t*) dest, (uint8_t*)src, length))
#define HASH(dest, src, length) {_hash.Reset(); _hash.Update(src, length); _hash.Final(dest);}

#define myM(n) size_t(ceil((double)n * STRETCHFACTOR))

#define myMSmall(n) size_t(ceil((double)n * STRETCHFACTORSMALL))


size_t searchBeta(size_t n, double c, size_t h);
double buckets(size_t n, size_t k, double c, size_t h);
double logTwo(double x);
double binom(double n, size_t k);


inline void printHex(unsigned char* str, int length) {
  for (int tmp = length - 1; tmp >= 0; tmp--) {
    printf("%02x", str[tmp]);
  }
}

inline void printHexnl(unsigned char* str, int length) {
  printHex(str, length);
  printf("\n");
}


inline void fprintHex(FILE* file, unsigned char* str, int length) {
  for (int tmp = length - 1; tmp >= 0; tmp--) {
    fprintf(file, "%02X", str[tmp]);
  }
}


inline void memXOR(unsigned char* dest, unsigned char* src1, unsigned char* src2, unsigned char length) {
  for (unsigned char __i = 0; __i < length; __i++) {
    dest[__i] = src1[__i] ^ src2[__i];
  }
}




#endif
