#ifndef OPRF_DEF
#define OPRF_DEF

#include "cryptoTools/Network/IOService.h"

#include <vector>

using namespace std;


class OPRFSender {

 public:
  //Compute local (O)PRF
 virtual void PRF(vector<osuCrypto::block> inputs, vector<osuCrypto::block> &output, size_t n) {}; 

 //Reply to receiver's request
 virtual void reply(size_t n) {}; 
  
};

class OPRFReceiver {

 public:
  //Input: receiver's input
  //Output: OPRFs of receiver's input
  virtual void query(vector<osuCrypto::block> inputs, vector<osuCrypto::block> &output, size_t n) {};
};

#endif
