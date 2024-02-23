#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"

#include "include.h"
#include "kkrtoprf.h"

using namespace std;
using namespace osuCrypto;


void KKRTSender::specificPRF(osuCrypto::block *input, osuCrypto::block *output, size_t index) {

  sender.encode(index, (u8*)input, (u8*)output, sizeof(block));
  
}

void KKRTSender::specificPRFs(vector<osuCrypto::block> inputs, vector<osuCrypto::block> &output, size_t index, size_t n) {

  for (u64 i = 0; i < n; i ++) {
    sender.encode(index + i, &inputs[i], (u8*)&output[i], sizeof(block));
  }


}


void KKRTSender::PRF(vector<block> inputs, vector<block> &output, size_t n) {

// the sender can now call encode(i, ...) for k \in {0, ..., i}.
  // Lets encode the same input and then we should expect to
  // get the same encoding.

  for (u64 i = 0; i < n; i ++) {
    sender.encode(OTsConsumed + i, &inputs[i], (u8*)&output[i], sizeof(block));
  }

  OTsConsumed += n;
}

void KKRTSender::reply(size_t n) {

  sender.recvCorrection(sendChl, n);

  OTsSent += n;
}

KKRTSender::KKRTSender (size_t n, osuCrypto::Channel &chann) {
  //cout << "Recall that the order of invocations matter for the KKRT OPRF!" << endl;
  OTsSent = 0;
  //OTsReady = 0;
  OTsConsumed = 0;
  numOTs = n;
  party = SENDER;

  //ios = new IOService;
  //ep0 = new Session(*ios, "localhost", 1212, SessionMode::Server);
  sendChl = chann;

  // get up the parameters and get some information back.
  //  1) false = semi-honest
  //  2) 40  =  statistical security param.
  //  3) numOTs = number of OTs that we will perform
  sender.configure(false, 40, 128);
  // the number of base OT that need to be done
  u64 baseCount = sender.getBaseOTCount();
  sendChl.send(baseCount);
  //cout << baseCount << endl;

  prng0 = new PRNG(block(4253465, 3434565));
  prng1 = new PRNG(block(42532335, 334565));

  // Fake some base OTs
  baseRecv = new vector<block>(baseCount);
  vector<array<block, 2>> baseSend (baseCount);
  baseChoice = new BitVector(baseCount);
  baseChoice->randomize(*prng0);
  prng0->get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());

  for (u64 i = 0; i < baseCount; ++i) {
    (*baseRecv)[i] = baseSend[i][(*baseChoice)[i]];
  }

  // set the base OTs
  sender.setBaseOts(*baseRecv, *baseChoice);
  sender.init(numOTs, *prng1, sendChl);
}

KKRTSender::~KKRTSender() {
  /*cout << PARTY(party) << " sent: " << (double) sendChl.getTotalDataSent() / (1024 * 1024) << "MByte, per OT: " << (double) sendChl.getTotalDataSent() / OTsSent << " Byte" << std::endl;
  cout << PARTY(party) << " received: " << (double )sendChl.getTotalDataRecv() / (1024 * 1024) << " MByte, per OT: " << (double )sendChl.getTotalDataRecv() / OTsSent << " Byte" << std::endl;
  */

  delete prng0;
  delete prng1;
  delete baseRecv;
  delete baseChoice;
  //sendChl.close();
  //delete ep0;
  //delete ios;

}

KKRTReceiver::KKRTReceiver(size_t n, osuCrypto::Channel &chann) {
  //cout <<"x"<<endl;
  
  OTsReceived = 0;
  numOTs = n;
  party = RECEIVER;

  //ios = new IOService;
  //ep1 = new Session(*ios, "localhost", 1212, SessionMode::Client);
  recvChl = chann;

  prng0 = new PRNG(block(4253465, 3434565));
  prng2 = new PRNG(block(42532335, 334565));

  recv.configure(false, 40, 128);

  u64 baseCount = 0;
  recvChl.recv(baseCount);
  //cout << baseCount << endl;

  // Fake some base OTs
  vector<block> baseRecv(baseCount);
  baseSend = new vector<array<block, 2>>(baseCount);
  BitVector baseChoice(baseCount);
  baseChoice.randomize(*prng0);
  prng0->get((u8*)baseSend->data()->data(), sizeof(block) * 2 * baseSend->size());

  for (u64 i = 0; i < baseCount; ++i) {
    baseRecv[i] = (*baseSend)[i][baseChoice[i]];
  }

  recv.setBaseOts(*baseSend);
  recv.init(numOTs, *prng2, recvChl);

}

KKRTReceiver::~KKRTReceiver() {

  /*  cout << PARTY(party) << " sent: " << (double) recvChl.getTotalDataSent() / (1024 * 1024) << "MByte, per OT: " << (double) recvChl.getTotalDataSent() / OTsReceived << " Byte" << std::endl;
  cout << PARTY(party) << " received: " << (double )recvChl.getTotalDataRecv() / (1024 * 1024) << " MByte, per OT: " << (double )recvChl.getTotalDataRecv() / OTsReceived << " Byte" << std::endl;
  */
  
  delete prng2;
  delete prng0;
  delete baseSend;
  //recvChl.close();
  //delete ep1;
  //delete ios;

}



void KKRTReceiver::query(vector<block> inputs, vector<block> &encoding, size_t n) {
  /*  cout <<"n = "<<size_t(n)<<", OTsReceived = "<<size_t(OTsReceived)<<", numOTs = "<<size_t(numOTs)<<endl;
  if (n + OTsReceived > numOTs) {
    cout << "You want to receive more OTs than initialized." << endl;
    }

if (n + OTsReceived > numOTs) {
    cout << "You want to receive more OTs than initialized." << endl;
    }*/
  
  for (u64 i = 0; i < n; i ++) {

    // The receiver MUST encode before the sender. Here we are only calling encode(...)
    // for a single i. But the receiver can also encode many i, but should only make one
    // call to encode for any given value of i.
    recv.encode(OTsReceived + i, &inputs[i], (u8*)&encoding[i], sizeof(block));

  }

  // This call will send to the other party the next "stepSize" corrections to the sender.
  // If we had made more or less calls to encode above (for contigious i), then we should replace
  // stepSize with however many calls we made. In an extreme case, the reciever can perform
  // encode for i \in {0, ..., numOTs - 1}  and then call sendCorrection(recvChl, numOTs).
  recv.sendCorrection(recvChl, n);

  OTsReceived += n;
}





