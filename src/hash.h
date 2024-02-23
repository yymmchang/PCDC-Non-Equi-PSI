#ifndef include_hash__h
#define include_hash__h
#include "include.h"


using namespace std;
using namespace osuCrypto;

extern AES aesHash;

extern AES aesHash1;
extern AES aesHash2;
extern AES aesHash3;

//AES aesHash(osuCrypto::block(4253465, 3434565));
#define hashBlock2u64(dst, src) {char b[128/8];	\
    extract128(b, aesHash.ecbEncBlock(src));\
    dst = *((size_t *) b);}


#define hashBlock2u64_1(dst, src) {char b[128/8];	\
    extract128(b, aesHash1.ecbEncBlock(src));\
    dst = *((size_t *) b);}

#define hashBlock2u64_2(dst, src) {char b[128/8];	\
    extract128(b, aesHash2.ecbEncBlock(src));		\
    dst = *((size_t *) b);}

#define hashBlock2u64_3(dst, src) {char b[128/8];	\
    extract128(b, aesHash3.ecbEncBlock(src));		\
    dst = *((size_t *) b);}


#define threeChoiceHash(dst,src,modulo,choice) {if (choice==0) {	\
	hashBlock2u64_1(dst,src);\
    } else if (choice==1) {\
	hashBlock2u64_2(dst,src);\
      } else {\
	hashBlock2u64_3(dst,src);\
      }dst = dst % modulo;}


#define printThreeChoices(x,modulo) {size_t index; threeChoiceHash(index,x,modulo,0); cout <<size_t(index)<<" ";threeChoiceHash(index,x,modulo,1); cout <<size_t(index)<<" ";threeChoiceHash(index,x,modulo,2); cout <<size_t(index);}

class bucket {
public:
  
  vector<block> x;
  vector<UTYPE> u;
  uint8_t load = 0;
  bucket(size_t beta);
  ~bucket();
};


class cuckooBucket {
public:
  
  block x;
  uint64_t u = 0;
  uint8_t load = 0;
  uint8_t choice = 0;
  size_t item = 0;

  cuckooBucket();
  ~cuckooBucket();
};


class simpleHashTable {
 public:
  size_t m;
  size_t beta;
  
  vector<bucket> table;

  void printTable();
  simpleHashTable(size_t mySize, size_t beta);
  
  ~simpleHashTable();

  void computeSimpleTripleHashTable(vector<osuCrypto::block> x, vector<uint64_t> u);

  void computeSimpleTripleHashTable(vector<osuCrypto::block> x);

  
  void computeSimpleHashTable(vector<osuCrypto::block> x, vector<uint64_t> u);
  
};


class cuckooHashTable {
 public:
  size_t m;
  
  vector<cuckooBucket> table;

  void printTable();
  void printLoads();
  
  cuckooHashTable(size_t mySize);
  
  ~cuckooHashTable();

  void computeCuckooHashTable(vector<osuCrypto::block> x, vector<uint64_t> u);

  void computeCuckooHashTable(vector<osuCrypto::block> x);

  
};


#endif
