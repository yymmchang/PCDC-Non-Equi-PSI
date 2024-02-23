#include <unordered_map>
#include "psi-lib.h"

#define MYHASHLENGTH (8)

using namespace osuCrypto;

inline void ristReEnc(unsigned char *outputCT, unsigned char *publicKey, unsigned char *inputCT) {
  unsigned char r[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(r);

  unsigned char buf[crypto_core_ristretto255_BYTES];
  crypto_scalarmult_ristretto255_base(buf, r);

  crypto_core_ristretto255_add(outputCT, buf, inputCT);

if (crypto_scalarmult_ristretto255(buf, r, publicKey) != 0) {
    cout << "ristreenc: Scalar mult does not work." << endl;
    exit(1);
  }

  crypto_core_ristretto255_add(&outputCT[crypto_core_ristretto255_BYTES], buf, &inputCT[crypto_core_ristretto255_BYTES]);
  
}

inline void ristPRFElgamal(unsigned char *outputCT, unsigned char *secretKey, unsigned char *inputCT) {
if (crypto_scalarmult_ristretto255(outputCT, secretKey, inputCT) != 0) {
    cout << "ristPRFElgamal 1: Scalar mult does not work." << endl;
    exit(1);
  }
  
if (crypto_scalarmult_ristretto255(&outputCT[crypto_core_ristretto255_BYTES], secretKey, &inputCT[crypto_core_ristretto255_BYTES]) != 0) {
    cout << "ristPRFElgamal 1: Scalar mult does not work." << endl;
    exit(1);
  }

}

inline void ristPartElgamalDec(unsigned char *outputCT, unsigned char *mySecret, unsigned char *inputCT) {
  memcpy(outputCT, inputCT, crypto_core_ristretto255_BYTES);
  
  unsigned char iSecretKey[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_negate(iSecretKey, mySecret);

  unsigned char buf[crypto_core_ristretto255_BYTES];
  if (crypto_scalarmult_ristretto255(buf, iSecretKey, inputCT) != 0) {
    cout << "ElgamalPartDec: Scalar mult does not work." << endl;
    exit(1);
  }
  crypto_core_ristretto255_add(&outputCT[crypto_core_ristretto255_BYTES], buf, &inputCT[crypto_core_ristretto255_BYTES]);

}

inline void ristUnMask(unsigned char* outputPRF, unsigned char* mySecretKeyINVERSE, unsigned char* inputPRF) {
  if (crypto_scalarmult_ristretto255(outputPRF, mySecretKeyINVERSE, inputPRF) != 0) {
    cout << "unMask scalar mult fail." << endl;
  }
}

inline void ristAddEnc(unsigned char* outputCiphertext, unsigned char* myPrivateKey, unsigned char* myPublicKey, unsigned char* otherPublicKey, unsigned char* inputCT) {
  unsigned char r2[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(r2);

  unsigned char buf1[crypto_core_ristretto255_BYTES];
  unsigned char buf2[crypto_core_ristretto255_BYTES];
  unsigned char buf3[crypto_core_ristretto255_BYTES];

  crypto_scalarmult_ristretto255_base(buf1, r2);

  crypto_core_ristretto255_add(outputCiphertext, buf1, inputCT);

  //1)
  if (crypto_scalarmult_ristretto255(buf1, myPrivateKey, inputCT) != 0) {
    cout << "Scalar mult fail." << endl;
  }

  //2)
  if (crypto_scalarmult_ristretto255(buf2, r2, otherPublicKey) != 0) {
    cout << "Scalar mult fail." << endl;
  }

  //3
  if (crypto_scalarmult_ristretto255(buf3, r2, myPublicKey) != 0) {
    cout << "Scalar mult fail." << endl;
  }

  crypto_core_ristretto255_add(&outputCiphertext[crypto_core_ristretto255_BYTES], buf1, &inputCT[crypto_core_ristretto255_BYTES]);
  crypto_core_ristretto255_add(&outputCiphertext[crypto_core_ristretto255_BYTES], buf2, &outputCiphertext[crypto_core_ristretto255_BYTES]);
  crypto_core_ristretto255_add(&outputCiphertext[crypto_core_ristretto255_BYTES], buf3, &outputCiphertext[crypto_core_ristretto255_BYTES]);

}

inline void ristElgamalEnc(unsigned char* ciphertext, unsigned char* publicKey, unsigned char* plaintext) {
  unsigned char r[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(r);

  crypto_scalarmult_ristretto255_base(ciphertext, r);

  unsigned char buf[crypto_core_ristretto255_BYTES];

  if (crypto_scalarmult_ristretto255(buf, r, publicKey) != 0) {
    cout << "ElgamalEnc: Scalar mult fail." << endl;
    exit(1);
  }

  crypto_core_ristretto255_add(&ciphertext[crypto_core_ristretto255_BYTES], buf, plaintext);
}

inline void ristElgamalDec(unsigned char* plaintext, unsigned char* secretKey, unsigned char* ciphertext) {
  unsigned char iSecretKey[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_negate(iSecretKey, secretKey);

  unsigned char buf[crypto_core_ristretto255_BYTES];

  if (crypto_scalarmult_ristretto255(buf, iSecretKey, ciphertext) != 0) {
    cout << "ElgamalDec: Scalar mult does not work." << endl;
    exit(1);
  }

  crypto_core_ristretto255_add(plaintext, buf, &ciphertext[crypto_core_ristretto255_BYTES]);

}

inline void ristPRF(unsigned char* output, unsigned char* keyScalar, unsigned char* inputPoint) {
  if ( crypto_scalarmult_ristretto255(output, keyScalar, inputPoint) != 0) {
    cout << "PRF: Scalar mult failed." << endl;
    exit(1);
  }
}


inline void hashedRistPRF(unsigned char* output, unsigned char* keyScalar, unsigned char* inputPoint) {
  unsigned char buf[crypto_core_ristretto255_BYTES];

  if ( crypto_scalarmult_ristretto255(buf, keyScalar, inputPoint) != 0) {
    cout << "PRF: Scalar mult failed." << endl;
    exit(1);
  }

  memcpy(output, buf, MYHASHLENGTH);
}


inline size_t RistFindMatches(char* serverBuf, char* clientBuf, size_t n, vector<size_t>* matches) {
  size_t count = 0;

  std::unordered_map<string, int> ht;

  std::string mystr;

  for (size_t i = 0; i < n ; i++) {
    std::stringstream ss;

    for (int j = 0; j < MYHASHLENGTH; ++j) {
      ss << std::hex << (int)serverBuf[i * MYHASHLENGTH + j];
    }

    mystr = ss.str();
    ht[mystr] = 99;
  }

  for (size_t i = 0; i < n ; i++) {
    std::stringstream ss;

    for (int j = 0; j < MYHASHLENGTH; ++j) {
      ss << std::hex << (int)clientBuf[i * MYHASHLENGTH + j];
    }

    mystr = ss.str();

    if (ht[mystr] == 99) {
      matches->push_back(i);
      count++;
    }

  }

  return count;
}


inline void RistShufflePoints(unsigned char* array, size_t n, PRNG &prng) {
  unsigned char temp[crypto_core_ristretto255_BYTES];

  for (size_t i = 0; i < n - 1; i++) {
    size_t k = myGetRandom(i, n - 1, prng);
    memcpy(temp, &array[i * crypto_core_ristretto255_BYTES], crypto_core_ristretto255_BYTES);
    memcpy(&array[i * crypto_core_ristretto255_BYTES], &array[k * crypto_core_ristretto255_BYTES], crypto_core_ristretto255_BYTES);
    memcpy(&array[k * crypto_core_ristretto255_BYTES], temp, crypto_core_ristretto255_BYTES);

    /*ep_copy(temp, array[i]);
    ep_copy(array[i], array[k]);
    ep_copy(array[k], temp);*/
  }
}


inline void RistShufflePointsPerDelta(unsigned char* points, size_t n, size_t delta) {
  PRNG prng(osuCrypto::block(42546, 343456));

  for (size_t i = 0; i < n; i++) {
    //Shuffle delta entries
    RistShufflePoints(&points[i * crypto_core_ristretto255_BYTES * delta], delta, prng);
  }
}


inline void RistHashPoints(char* bigBuf, unsigned char* maskedServerPoints, size_t n) {
  for (size_t i = 0; i < n ; i++) {
    unsigned char buf[HASHLENGTH];
    md_map_b2s160(buf, &maskedServerPoints[i * crypto_core_ristretto255_BYTES], crypto_core_ristretto255_BYTES);
    memcpy(&bigBuf[i * MYHASHLENGTH], buf, MYHASHLENGTH);
  }
}


inline void RistReceivePoint(emp::NetIO* io, unsigned char* point) {

  io->recv_data(point, crypto_core_ristretto255_BYTES);

}

inline void RistReceivePoints(emp::NetIO* io, unsigned char* points, size_t n) {
  for (size_t i = 0; i < n; i++) {
    RistReceivePoint(io, &points[i * crypto_core_ristretto255_BYTES]);
  }
}



//Multiply points with secret
inline void RistMaskPoints(unsigned char* outPoints, unsigned char* inPoints, unsigned char* secret, size_t n) {
  size_t frac = FRAC(n);
  progressbar bar(frac);

  #pragma omp parallel for

  for (size_t i = 0; i < n; i++) {

    //ep_mul_lwnaf(outPoints[i], inPoints[i], secret);
    crypto_scalarmult_ristretto255(&outPoints[i * crypto_core_ristretto255_BYTES], secret, &inPoints[i * crypto_core_ristretto255_BYTES]);
#ifdef PROGRESS
    BAR
#endif
  }
}


inline void RistSendPoint(emp::NetIO* io, unsigned char* point) {
  io->send_data(point, crypto_core_ristretto255_BYTES);
}


inline void RistSendPoints(emp::NetIO* io, unsigned char* points, size_t n) {
  for (size_t i = 0; i < n; i++) {
    RistSendPoint(io, &points[i * crypto_core_ristretto255_BYTES]);
  }
}
