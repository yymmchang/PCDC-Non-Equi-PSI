#ifndef psi_lib_H
#define psi_lib_H

#define POINTBYTESIZE 33

#include <omp.h>
#include <unordered_map>
#include "progressbar.hpp"
#include "cryptoTools/Crypto/PRNG.h"

#include "include.h"

using namespace std;
using namespace osuCrypto;



#define FRAC(x) {(1+x / (10*omp_get_max_threads()))}

#define BAR {if (100 * i / frac % 10 == 0) {\
      if (omp_get_thread_num() == 0) {	     \
        bar.update();\
      }\
    }}


inline void hashPoints(char* bigBuf, ep_t* maskedServerPoints, size_t n) {

  for (size_t i = 0; i < n ; i++) {
    char buf[POINTBYTESIZE];
    ep_write_bin((uint8_t*)buf, POINTBYTESIZE, maskedServerPoints[i], 1);
    md_map_b2s160((uint8_t*) & (bigBuf[i * HASHLENGTH]), (uint8_t*)buf, POINTBYTESIZE);
  }

}


inline void fetchConvertedPoints(ep_t* points, size_t n, char* fname) {

  char* buf = (char*) malloc(n * POINTBYTESIZE);
  auto inFile = fopen(fname, "rb");

  for (size_t i = 0; i < n; i++) {
    fread(&buf[i * POINTBYTESIZE], POINTBYTESIZE, 1, inFile);
  }

  #pragma omp parallel for

  for (size_t i = 0; i < n; i++) {
    ep_read_bin(points[i], (uint8_t*) &buf[i * POINTBYTESIZE], POINTBYTESIZE);
  }

  fclose(inFile);

  free(buf);
}


inline void printPoints(ep_t* points, size_t n) {
  for  (size_t i = 0; i < n; i++) {
    printf("%lu:\n", i);
    ep_print(points[i]);
    printf("-----------\n");

  }
}

inline size_t myGetRandom(size_t lower, size_t upper, PRNG &prng) {
  size_t tmp;
  prng.get(&tmp, 1);
  tmp = tmp % (upper - lower + 1);
  tmp += lower;
  return tmp;
}


inline void shufflePoints(ep_t* array, size_t n, PRNG &prng) {
  ep_t temp;

  for (size_t i = 0; i < n - 1; i++) {
    size_t k = myGetRandom(i, n-1, prng);
    ep_copy(temp, array[i]);
    ep_copy(array[i], array[k]);
    ep_copy(array[k], temp);
  }
}

inline void shufflePointsPerDelta(ep_t* points, size_t n, size_t delta) {
  PRNG prng(osuCrypto::block(42546, 343456));

  for (size_t i = 0; i < n; i++) {
    //Shuffle delta entries
    shufflePoints(&points[i*delta], delta, prng);
  }
}

inline void getRandomPoints(ep_t* points, size_t n) {
  for (size_t i = 0; i < n ; i++) {
    size_t r = i;
    ep_map(points[i], (const uint8_t*) &r, sizeof(size_t));
  }
}

//Multiply points with secret
inline void maskPoints(ep_t* outPoints, ep_t* inPoints, bn_t secret, size_t n) {
  size_t frac = FRAC(n);
  progressbar bar(frac);

  #pragma omp parallel for

  for (size_t i = 0; i < n; i++) {
    //ep_mul_basic(outPoints[i], inPoints[i], secret);
    ep_mul_lwnaf(outPoints[i], inPoints[i], secret);
#ifdef PROGRESS
    BAR
#endif
  }
}

inline void sendPoint(emp::NetIO* io, ep_t point) {
  //uint8_t s = ep_size_bin(point, 1);
  //char* buf = (char*) malloc(s);
  char buf[POINTBYTESIZE];

  //ep_write_bin((uint8_t*)buf, s, point, 1);
  ep_write_bin((uint8_t*)buf, POINTBYTESIZE, point, 1);

  io->send_data(buf, POINTBYTESIZE);
}

inline void sendPoints(emp::NetIO* io, ep_t* points, size_t n) {
  for (size_t i = 0; i < n; i++) {
    sendPoint(io, points[i]);
  }
}



inline void receivePoint(emp::NetIO* io, ep_t point) {
  char buf[POINTBYTESIZE];

  io->recv_data(buf, POINTBYTESIZE);
  ep_read_bin(point, (const uint8_t*)buf, POINTBYTESIZE);

}

inline void receivePoints(emp::NetIO* io, ep_t* points, size_t n) {
  for (size_t i = 0; i < n; i++) {
    receivePoint(io, points[i]);
  }
}


inline size_t findMatches(char* serverBuf, char* clientBuf, size_t n, vector<size_t>* matches) {
  size_t count = 0;

  std::unordered_map<string, int> ht;

  std::string mystr;

  for (size_t i = 0; i < n ; i++) {
    std::stringstream ss;

    for (int j = 0; j < HASHLENGTH; ++j) {
      ss << std::hex << (int)serverBuf[i * HASHLENGTH + j];
    }

    mystr = ss.str();
    ht[mystr] = 99;
  }

  for (size_t i = 0; i < n ; i++) {
    std::stringstream ss;

    for (int j = 0; j < HASHLENGTH; ++j) {
      ss << std::hex << (int)clientBuf[i * HASHLENGTH + j];
    }

    mystr = ss.str();

    if (ht[mystr] == 99) {
      matches->push_back(i);
      count++;
    }

  }

  return count;
}


/*size_t findMatches(ep_t* finalServerPoints, ep_t* finalClientPoints, size_t n, vector<size_t>* matches) {
  size_t count = 0;

  std::unordered_map<string, int> ht;

  for (size_t i = 0; i < n; i++) {
    char str[256], str2[256], str3[256];
    fp_write_str(str, 255, finalServerPoints[i]->x, 16);
    fp_write_str(str2, 255, finalServerPoints[i]->y, 16);
    fp_write_str(str3, 255, finalServerPoints[i]->z, 16);
    string s = string(str);
    s = s + string(str2);
    s = s + string(str3);
    ht[s] = 99;
  }

  for (size_t i = 0; i < n; i++) {
    char str[256], str2[256], str3[256];
    fp_write_str(str, 255, finalClientPoints[i]->x, 16);
    fp_write_str(str2, 255, finalClientPoints[i]->y, 16);
    fp_write_str(str3, 255, finalClientPoints[i]->z, 16);
    string s = string(str);
    s = s + string(str2);
    s = s + string(str3);

    if (ht[s] == 99) {
      matches->push_back(i);
      count++;
    }
  }

  return count;
  }*/

#endif
