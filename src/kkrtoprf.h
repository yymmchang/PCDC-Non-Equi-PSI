#include "cryptoTools/Network/IOService.h"

#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

#include "oprf.h"

using namespace std;



class KKRTSender:public OPRFSender {
 public:
  int party;
  size_t OTsSent;
  //size_t OTsReady;
  size_t numOTs;
  size_t OTsConsumed;
  
  osuCrypto::Channel sendChl;
  //osuCrypto::Session* ep0;
  osuCrypto::KkrtNcoOtSender sender;
  osuCrypto::PRNG* prng1, *prng0;

  vector<osuCrypto::block>* baseRecv;
  osuCrypto::BitVector* baseChoice;
  //osuCrypto::IOService* ios;

  void PRF(vector<osuCrypto::block> inputs, vector<osuCrypto::block> &output, size_t n);
  void specificPRF(osuCrypto::block *input, osuCrypto::block *output, size_t index); 
  void specificPRFs(vector<osuCrypto::block> inputs, vector<osuCrypto::block> &output, size_t index, size_t n); 
  void reply(size_t n); 
  
  KKRTSender (size_t n, osuCrypto::Channel &chann); 
  
  ~KKRTSender(); 
};

class KKRTReceiver:public OPRFReceiver {
 public:
  int party;
  size_t OTsReceived;
  
  //osuCrypto::IOService* ios;
  osuCrypto::Channel recvChl;
  //osuCrypto::Session* ep1;
  osuCrypto::PRNG* prng2, *prng0;
  vector<array<osuCrypto::block, 2>>* baseSend;

  osuCrypto::KkrtNcoOtReceiver recv;
  size_t numOTs;

  KKRTReceiver(size_t n, osuCrypto::Channel &chann);
  ~KKRTReceiver();
  void query(vector<osuCrypto::block> inputs, vector<osuCrypto::block> &output, size_t n);
};
