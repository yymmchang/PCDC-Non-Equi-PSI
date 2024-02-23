#include <stdio.h>
#include <stdlib.h>

#include <iostream>

#include "emp-tool/emp-tool.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "include.h"
#include "mismatch.h"
#include <cryptoTools/Crypto/Blake2.h>
#include "hash.h"
#include "kkrtoprf.h"


using namespace std;
using namespace osuCrypto;


void printTimings(string prefix, vector<string> s, vector<double>t) {
  for (size_t i = 0; i<s.size();i++) {
    cout <<prefix<<" "<<s[i]<<": "<<t[i]/1000<<" ms"<<endl;
  }
  
}

void myRun(int party, int port, unsigned char logn, size_t DELTA) {
  vector<string> myDesc;
  vector<double> myTime;
  
  size_t n = 1 << logn;
  //LAMBDA is in bytes, 40/8=5
  unsigned char LAMBDA = 5 + (unsigned char) ceil((double)logn / (double)8);
  IOService ios;
  auto ip = std::string("127.0.0.1");
  std::string serversIpAddress = ip + ':' + std::to_string(port);
  std::string sessionHint = "party0_party1";
  std::string senderIsSender = "_senderIsSender";
  std::string receiverIsSender = "_receiverIsSender";
  size_t m = myM(n);
  osuCrypto::PRNG prng0(osuCrypto::block(4253465, 2434566));

  osuCrypto::PRNG prngx(osuCrypto::block(4253465, 3434565));
  osuCrypto::PRNG prngu(osuCrypto::block(425346, 434565));

  osuCrypto::PRNG prngy(osuCrypto::block(4253465, 3434565));
  //ALL MATCHES osuCrypto::PRNG prngv(osuCrypto::block(425346, 434564));
  //NO MATCHES osuCrypto::PRNG prngv(osuCrypto::block(425346, 434565));
  osuCrypto::PRNG prngv(osuCrypto::block(425346, 434565));
  
  if (party == SENDER) {
    Session sender(ios, serversIpAddress, SessionMode::Server, sessionHint);

    Channel chanSenderIsSender = sender.addChannel(senderIsSender);
    Channel chanReceiverIsSender = sender.addChannel(receiverIsSender);

    KKRTSender Sender(m * DELTA, chanSenderIsSender);
    KKRTReceiver Receiver(m * DELTA, chanReceiverIsSender);
    
    //Compute my input
    std::vector<osuCrypto::block> x(n);
    std::vector<UTYPE> u(n);
    prngx.get(x.data(), x.size());
    prngu.get(u.data(), u.size());
    auto grandTotalStart = emp::clock_start();
    auto runTime = grandTotalStart;
    
    cout << PARTY(party) << ": Step 1" << endl;
    //Step 1
    cuckooHashTable T_S(m);
    T_S.computeCuckooHashTable(x, u);

    //Clear space
    u = std::vector<UTYPE>();
    //Space for x_i||prefix||counter
    unsigned char buf[BLOCKLENGTH + sizeof(uint64_t) + 1];
    unsigned char hashBuf[HASHLENGTH];
    vector<block> h(m * DELTA);

    //Compute inputs for OPRF(H(x_i, PREFIX_i,j(u_i)));
    //There might be dummy elements
    //Note that we need to do paddying, i.e., add the counter as the last byte

    for (size_t i = 0; i < m; i++) {
      Blake2 _hash(HASHLENGTH);

      if (T_S.table[i].load == 0) {
        //bzero(buf, BLOCKLENGTH);
        extract128(buf, prng0.get<block>());
      } else {
        extract128(buf, T_S.table[i].x);
      }

      UTYPE theu = T_S.table[i].u;

      for (size_t j = 0; j < DELTA; j++) {
        //*(uint64_t*)&buf[BLOCKLENGTH] = XORPREFIX64(u, j + 1);
        *(uint64_t*)&buf[BLOCKLENGTH] = PREFIX64(theu, j + 1);
        *(uint8_t*)&buf[BLOCKLENGTH + sizeof(uint64_t)] =  j;
        HASH(hashBuf, buf, BLOCKLENGTH + sizeof(uint64_t) + 1);

	#pragma omp critical
        h[i * DELTA + j] = store128(hashBuf);
      }
    }

    myDesc.push_back("Step 1");
    myTime.push_back(emp::time_from(runTime));
    runTime = emp::clock_start();
    
    cout << PARTY(party) << ": Step 2" << endl;
    //Step 2a
    std::vector<osuCrypto::block> z(m * DELTA);
    Receiver.query(h, z, m * DELTA);

    myDesc.push_back("Step 2a");
    myTime.push_back(emp::time_from(runTime));
    runTime = emp::clock_start();

    
    //Step 2b
    Sender.reply(m * DELTA);

    myDesc.push_back("Step 2b");
    myTime.push_back(emp::time_from(runTime));
    runTime = emp::clock_start();

    
    //Step 3 is empty for the sender

    //Step 4
    cout << PARTY(party) << ": Step 4" << endl;
    unsigned char* T_STAR = (unsigned char*) malloc(m * DELTA * 3 * LAMBDA);
    chanSenderIsSender.recv(T_STAR, m * DELTA * 3 * LAMBDA);


    myDesc.push_back("Step 4");
    myTime.push_back(emp::time_from(runTime));
    runTime = emp::clock_start();

    
    //Step 5
    cout << PARTY(party) << ": Step 5" << endl;
    unsigned char* S = (unsigned char*) malloc(n * DELTA * 3 * LAMBDA);

    #pragma omp parallel for
    for (size_t i = 0 ; i < n; i++) {
      auto x_i = x[i];
      size_t H1, H2, H3;
      hashBlock2u64_1(H1, x_i);
      hashBlock2u64_2(H2, x_i);
      hashBlock2u64_3(H3, x_i);
      H1 = H1 % m;
      H2 = H2 % m;
      H3 = H3 % m;
      size_t H_IDX = 0;
      unsigned char IDX_x_i = 0;

      if (T_S.table[H1].x == x_i) {
        H_IDX = H1;
        IDX_x_i = 0;
      } else if (T_S.table[H2].x == x_i) {
        H_IDX = H2;
        IDX_x_i = 1;
      } else {
        H_IDX = H3;
        IDX_x_i = 2;
      }

      for (size_t  k = 0; k < DELTA; k++) {
        block myPRF1, myPRF2, myPRF3;
        Sender.specificPRF(&h[H_IDX * DELTA + k], &myPRF1, H1 * DELTA + k);
        Sender.specificPRF(&h[H_IDX * DELTA + k], &myPRF2, H2 * DELTA + k);
        Sender.specificPRF(&h[H_IDX * DELTA + k], &myPRF3, H3 * DELTA + k);
        unsigned char buf[BLOCKLENGTH];
        extract128(buf, z[i * DELTA + k]^ myPRF1);
        memXOR(&S[i * DELTA * LAMBDA], buf, &T_STAR[H1 * DELTA * 3 * LAMBDA + IDX_x_i * LAMBDA], LAMBDA);
        extract128(buf, z[i * DELTA + k]^ myPRF2);
        memXOR(&S[i * DELTA * LAMBDA + LAMBDA], buf, &T_STAR[H2 * DELTA * 3 * LAMBDA + IDX_x_i * LAMBDA], LAMBDA);
        extract128(buf, z[i * DELTA + k]^ myPRF3);
        memXOR(&S[i * DELTA * LAMBDA + 2 * LAMBDA], buf, &T_STAR[H3 * DELTA * 3 * LAMBDA + IDX_x_i * LAMBDA], LAMBDA);
      }
    }

    x = std::vector<osuCrypto::block>();
    free(T_STAR);
    myDesc.push_back("Step 5");
    myTime.push_back(emp::time_from(runTime));
    runTime = emp::clock_start();

    
    //Step 6: Shuffle S
    cout << PARTY(party) << ": Step 6" << endl;
    chanSenderIsSender.send(S, n * DELTA * 3 * LAMBDA);
    free(S);
    
    myDesc.push_back("Step 6");
    myTime.push_back(emp::time_from(runTime));
    runTime = emp::clock_start();

    
    //No Step 7 for Sender
    
    chanSenderIsSender.close();
    chanReceiverIsSender.close();
    sender.stop();
    auto elapsed = emp::time_from(grandTotalStart);
    cout << PARTY(party) << " total time: " << elapsed / 1000 << "ms" << endl;

    printTimings("Sender", myDesc, myTime);

  } else { //Receiver
    
    cout << "n = " << size_t(n) << ", m = " << size_t(m) << ", LAMBDA = " << size_t(LAMBDA) <<", DELTA = "<<size_t(DELTA)<< endl;
    cout << "Number of OPRFs per party: " << size_t(m * DELTA) << endl;

    Session receiver(ios, serversIpAddress, SessionMode::Client, sessionHint);
    Channel chanSenderIsSender = receiver.addChannel(senderIsSender);
    Channel chanReceiverIsSender = receiver.addChannel(receiverIsSender);

    KKRTReceiver Receiver(m * DELTA, chanSenderIsSender);
    KKRTSender Sender(m * DELTA, chanReceiverIsSender);

    std::vector<osuCrypto::block> y(n);
    std::vector<UTYPE> v(n);

    prngy.get(y.data(), y.size());
    prngv.get(v.data(), v.size());

    auto K_STAR = prng0.get<block>();
    AES prf_k_star(K_STAR);
    auto grandTotalStart = emp::clock_start();
    auto runTime = grandTotalStart;


    cout << PARTY(party) << ": Step 1" << endl;
    //Step 1
    cuckooHashTable T_R(m);
    T_R.computeCuckooHashTable(y, v);

    //Clear space
    v = std::vector<UTYPE>();
    y = std::vector<osuCrypto::block>();
    
    //Space for y_i||prefix||counter
    unsigned char buf[BLOCKLENGTH + sizeof(uint64_t) + 1];
    unsigned char hashBuf[HASHLENGTH];
    vector<block> h_prime(m * DELTA);

    //Compute inputs for OPRF(H(y_i, PREFIX_i,j(v_i)));
    //There might be dummy elements
    //Note that we need to do paddying, i.e., add the counter as the last byte

    for (size_t i = 0; i < m; i++) {
      Blake2 _hash(HASHLENGTH);

      if (T_R.table[i].load == 0) {
        //bzero(buf, BLOCKLENGTH);
        extract128(buf, prng0.get<block>());
      } else {
        extract128(buf, T_R.table[i].x);
      }

      UTYPE thev = T_R.table[i].u;

      for (size_t j = 0; j < DELTA; j++) {
        //*(uint64_t*)&buf[BLOCKLENGTH] = XORPREFIX64(v, j + 1);
        *(uint64_t*)&buf[BLOCKLENGTH] = PREFIX64(thev, j + 1);
        *(uint8_t*)&buf[BLOCKLENGTH + sizeof(uint64_t)] =  j;
        HASH(hashBuf, buf, BLOCKLENGTH + sizeof(uint64_t) + 1);

	#pragma omp critical
	h_prime[i * DELTA + j] = store128(hashBuf);
      }
    }

    myDesc.push_back("Step 1");
    myTime.push_back(emp::time_from(runTime));
    runTime = emp::clock_start();

    
    cout << PARTY(party) << ": Step 2a" << endl;
    //Step 2a
    Sender.reply(m * DELTA);
    
    myDesc.push_back("Step 2a");
    myTime.push_back(emp::time_from(runTime));
    runTime = emp::clock_start();

    cout << PARTY(party) << ": Step 2b" << endl;
    //Step 2b
    std::vector<osuCrypto::block> z_prime(m * DELTA);
    Receiver.query(h_prime, z_prime, m * DELTA);

    myDesc.push_back("Step 2b");
    myTime.push_back(emp::time_from(runTime));
    runTime = emp::clock_start();

    
    //Step 3
    cout << PARTY(party) << ": Step 3" << endl;
    unsigned char* T_STAR = (unsigned char*) malloc(m * DELTA * 3 * LAMBDA);

    std::vector<osuCrypto::block> prf_k_star_list;
    std::vector<size_t> prf_k_star_list_indices;

    unsigned char* randBuf = (unsigned char*) malloc(m * DELTA * 3 * LAMBDA);
    prngy.implGet(randBuf,m * DELTA * 3 * LAMBDA);
    
    #pragma omp parallel for
    for (size_t j = 0; j < m; j++) {
      if (T_R.table[j].load == 0) {
	memcpy(&T_STAR[j * DELTA * 3 * LAMBDA], &randBuf[j * DELTA * 3 * LAMBDA], DELTA * 3 * LAMBDA);
	//prngy.get(&T_STAR[j * DELTA * 3 * LAMBDA], DELTA * 3 * LAMBDA);
      } else {
        auto y_i = T_R.table[j].x;

	block myPRF = prf_k_star.ecbEncBlock(y_i);

	#pragma omp critical
	{
        prf_k_star_list.push_back(myPRF);
	prf_k_star_list_indices.push_back(T_R.table[j].item);
	}
	
	size_t H1, H2, H3;
        hashBlock2u64_1(H1, y_i);
        hashBlock2u64_2(H2, y_i);
        hashBlock2u64_3(H3, y_i);
        H1 = H1 % m;
        H2 = H2 % m;
        H3 = H3 % m;

        for (unsigned char k = 0; k < DELTA; k++) {
          block myPRF1, myPRF2, myPRF3;
          Sender.specificPRF(&h_prime[j * DELTA + k], &myPRF1, H1 * DELTA + k);
          Sender.specificPRF(&h_prime[j * DELTA + k], &myPRF2, H2 * DELTA + k);
          Sender.specificPRF(&h_prime[j * DELTA + k], &myPRF3, H3 * DELTA + k);
          auto cjk1 = z_prime[j * DELTA + k] ^ myPRF1 ^ myPRF;
          auto cjk2 = z_prime[j * DELTA + k] ^ myPRF2 ^ myPRF;
          auto cjk3 = z_prime[j * DELTA + k] ^ myPRF3 ^ myPRF;
          char buf[BLOCKLENGTH];
          extract128(buf, cjk1);
          memcpy(&T_STAR[j * DELTA * 3 * LAMBDA + k * 3 * LAMBDA], buf, LAMBDA);
          extract128(buf, cjk2);
          memcpy(&T_STAR[j * DELTA * 3 * LAMBDA + k * 3 * LAMBDA + LAMBDA], buf, LAMBDA);
          extract128(buf, cjk3);
          memcpy(&T_STAR[j * DELTA * 3 * LAMBDA + k * 3 * LAMBDA + 2 * LAMBDA], buf, LAMBDA);
        }
      }
    }

    myDesc.push_back("Step 3");
    myTime.push_back(emp::time_from(runTime));
    runTime = emp::clock_start();

    free(randBuf);
    
    //Step 4
    cout << PARTY(party) << ": Step 4" << endl;
    chanSenderIsSender.send(T_STAR, m * DELTA * 3 * LAMBDA);

    free(T_STAR);
    
    myDesc.push_back("Step 4");
    myTime.push_back(emp::time_from(runTime));
    runTime = emp::clock_start();

    
    //No Step 5 for receiver

    //Step 6
    cout << PARTY(party) << ": Step 6" << endl;
    unsigned char* S = (unsigned char*) malloc(n * DELTA * 3 * LAMBDA);
    chanSenderIsSender.recv(S, n * DELTA * 3 * LAMBDA);

    myDesc.push_back("Step 6");
    myTime.push_back(emp::time_from(runTime));
    runTime = emp::clock_start();
    
    //Step 7
    cout << PARTY(party) << ": Step 7" << endl;

    //Fill hashtable
    std::unordered_map<uint64_t, int> ht;
    ht.reserve(n);
    
    size_t count = 0;
    
    for (size_t i = 0; i < n * DELTA * 3 ; i++) {
      uint64_t *x = (uint64_t *) &S[i*LAMBDA];
      ht[*x] = 99;
    }

  for (size_t i = 0; i < n ; i++) {
    unsigned char buf[BLOCKLENGTH];
    
    extract128(buf, prf_k_star_list[i]);
    
    uint64_t *x = (uint64_t*) buf;
    if (ht[*x] == 99) {
      count ++;
    }

  }

    myDesc.push_back("Step 7");
    myTime.push_back(emp::time_from(runTime));
    runTime = emp::clock_start();
    
    //Done
    chanSenderIsSender.close();
    chanReceiverIsSender.close();
    receiver.stop();
    auto elapsed = emp::time_from(grandTotalStart);
    auto chan1 = (double) chanSenderIsSender.getTotalDataSent() + (double) chanSenderIsSender.getTotalDataRecv();
    chan1 +=  (double) chanReceiverIsSender.getTotalDataSent() + (double) chanReceiverIsSender.getTotalDataRecv();
    cout << PARTY(party) << " total communication: " << (chan1 / (1024 * 1024)) << "MByte" << endl;
    cout << PARTY(party) << " total time to compute mismatch including waiting: " << elapsed / (1000 * 1000) << "s." << endl;

    printTimings("Receiver", myDesc, myTime);
    cout <<"+++"<<(chan1 / (1024 * 1024))<<","<<elapsed / (1000 * 1000)<<endl;
  }
}


int main(int argc, char** argv) {
  int port = 9876;

  if (argc != 4) {
    printf("Must supply log of number of elements, party number, and DELTA\n");
    return -1;
  }

  unsigned char logn = (atoi(argv[1]));
  int party = atoi(argv[2]);
  int delta = atoi(argv[3]);
  myRun(party, port, logn, delta);
  return 0;
}
