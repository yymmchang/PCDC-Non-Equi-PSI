#include <stdio.h>
#include <stdlib.h>

#include <iostream>

#include "emp-tool/emp-tool.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "include.h"
#include "mismatch.h"
#include <cryptoTools/Crypto/Blake2.h>

extern "C" {
#include "relic.h"
}

#include <sodium.h>
#include "rist-lib.h"
#include "bytesHash.h"

using namespace std;

void myRun(int party, int port, size_t n) {

  if (sodium_init() < 0) {
    cout << "panic! the library couldn't be initialized; it is not safe to use" << endl;
  }

  std::random_device rd;
  std::mt19937 g(rd());
    
  osuCrypto::PRNG prngx(osuCrypto::block(4253465, 3434565));
  osuCrypto::PRNG prngu(osuCrypto::block(425346, 434565));
  osuCrypto::PRNG prngy(osuCrypto::block(4253465, 3434565));
  osuCrypto::PRNG prngv(osuCrypto::block(425346, 434564));


  if (party == SENDER) {
    unsigned char alpha1[crypto_core_ristretto255_HASHBYTES];
    unsigned char alpha2[crypto_core_ristretto255_HASHBYTES];
    unsigned char galpha1[crypto_core_ristretto255_BYTES];
    unsigned char galpha2[crypto_core_ristretto255_BYTES];

    crypto_core_ristretto255_scalar_random(alpha1);
    crypto_scalarmult_ristretto255_base(galpha1, alpha1);

    crypto_core_ristretto255_scalar_random(alpha2);
    crypto_scalarmult_ristretto255_base(galpha2, alpha2);


    //Compute my input
    std::vector<osuCrypto::block> x(n);
    std::vector<uint64_t> u(n);
    prngx.get(x.data(), x.size());
    prngu.get(u.data(), u.size());
    u[0] = 3;

    unsigned char* X = (unsigned char*) malloc(n * crypto_core_ristretto255_BYTES);
    unsigned char* PSI = (unsigned char*) malloc(n * crypto_core_ristretto255_BYTES);

    cout << "Sender connecting..." << endl;
    auto io = new emp::NetIO(nullptr, port);

    auto grandTotalStart = emp::clock_start();

    cout <<PARTY(party)<<": hashing to curve"<<endl;
    #pragma omp parallel for
    for (size_t i = 0; i < n; i++) {
      unsigned char buf[crypto_core_ristretto255_HASHBYTES];
      bzero(buf, crypto_core_ristretto255_HASHBYTES);
      extract128(buf, x[i]);
      crypto_core_ristretto255_from_hash(&X[i * crypto_core_ristretto255_BYTES], buf);
      memcpy(&buf[16], &u[i], sizeof(uint64_t));
      crypto_core_ristretto255_from_hash(&PSI[i * crypto_core_ristretto255_BYTES], buf);
    }


    unsigned char gbeta1[crypto_core_ristretto255_BYTES];
    unsigned char gbeta2[crypto_core_ristretto255_BYTES];
    io->recv_data(gbeta1, crypto_core_ristretto255_BYTES);
    io->recv_data(gbeta2, crypto_core_ristretto255_BYTES);

    io->send_data(galpha1, crypto_core_ristretto255_BYTES);
    io->send_data(galpha2, crypto_core_ristretto255_BYTES);


    unsigned char* prfsalpha1_x = (unsigned char*) malloc(n * crypto_core_ristretto255_BYTES);
    unsigned char* encsalpha2_x = (unsigned char*) malloc(2 * n * crypto_core_ristretto255_BYTES);

    #pragma omp parallel for
    for (size_t i = 0; i < n; i++) {
      ristPRF(&prfsalpha1_x[i * crypto_core_ristretto255_BYTES], alpha1, &X[i * crypto_core_ristretto255_BYTES]);
      ristElgamalEnc(&encsalpha2_x[2 * i * crypto_core_ristretto255_BYTES], galpha2, &PSI[i * crypto_core_ristretto255_BYTES]);
    }

    cout << PARTY(party) << ": sending PRFs and ciphertexts to R..." << endl;

    io->send_data(prfsalpha1_x, n * crypto_core_ristretto255_BYTES);
    io->send_data(encsalpha2_x, 2 * n * crypto_core_ristretto255_BYTES);

    unsigned char* prfsbeta1alpha1_x = (unsigned char*) malloc(n * crypto_core_ristretto255_BYTES);
    unsigned char* encsalpha2beta2_x = (unsigned char*) malloc(2 * n * crypto_core_ristretto255_BYTES);
    io->recv_data(prfsbeta1alpha1_x, n * crypto_core_ristretto255_BYTES);
    io->recv_data(encsalpha2beta2_x, n * 2 * crypto_core_ristretto255_BYTES);

    unsigned char* prfsbeta1_y = (unsigned char*) malloc(n * crypto_core_ristretto255_BYTES);
    unsigned char* encsbeta2_y = (unsigned char*) malloc(2 * n * crypto_core_ristretto255_BYTES);

    io->recv_data(prfsbeta1_y, n * crypto_core_ristretto255_BYTES);
    io->recv_data(encsbeta2_y, n * 2 * crypto_core_ristretto255_BYTES);

    cout <<PARTY(party)<<": computing Step 4..."<<endl;
    
    bytesHash hashTable;
    for (size_t i = 0; i < n; i++) {
      //0 means that the element is not inside, so we cannot insert 0
      hashTable.insert(&prfsbeta1_y[i * crypto_core_ristretto255_BYTES], crypto_core_ristretto255_BYTES, i+1);
    }      

    //Step 4
    //UnMask
    unsigned char* prfsbeta1_x = (unsigned char*) malloc(n * crypto_core_ristretto255_BYTES);
    unsigned char* encsbeta2_x = (unsigned char*) malloc(2*n * crypto_core_ristretto255_BYTES);

    unsigned char alpha1INVERSE[crypto_core_ristretto255_SCALARBYTES];

    if (crypto_core_ristretto255_scalar_invert(alpha1INVERSE, alpha1) != 0) {
      cout << "Inverse does not exists?!" << endl;
      exit(-1);
    }

#pragma omp parallel for      
    for (size_t i = 0; i < n; i++) {
      ristUnMask(&prfsbeta1_x[i * crypto_core_ristretto255_BYTES], alpha1INVERSE, &prfsbeta1alpha1_x[i * crypto_core_ristretto255_BYTES]);
      ristPartElgamalDec(&encsbeta2_x[2*i*crypto_core_ristretto255_BYTES], alpha2, &encsalpha2beta2_x[2*i*crypto_core_ristretto255_BYTES]);   
    }


    unsigned char *sigma = (unsigned char*) malloc(5*n*crypto_core_ristretto255_BYTES);

    #pragma omp parallel for
    for (size_t i = 0; i < n; i++) {
      memcpy(&sigma[5*i*crypto_core_ristretto255_BYTES], &prfsbeta1_y[i*crypto_core_ristretto255_BYTES], crypto_core_ristretto255_BYTES);
      ristPRFElgamal(&sigma[(5*i+1)*crypto_core_ristretto255_BYTES], alpha1, &encsbeta2_y[2*i*crypto_core_ristretto255_BYTES]);
      auto j = hashTable.lookup(&prfsbeta1_x[i * crypto_core_ristretto255_BYTES], crypto_core_ristretto255_BYTES);
      if (j!=0) {
	j--; //remember that we cannot insert 0
	ristPRFElgamal(&sigma[(5*i+3)*crypto_core_ristretto255_BYTES], alpha1, &encsbeta2_x[2*i*crypto_core_ristretto255_BYTES]);	
      } else {
	unsigned char buf[2*crypto_core_ristretto255_BYTES];
	ristReEnc(buf, gbeta2, &sigma[(5*i+1)*crypto_core_ristretto255_BYTES]);
	ristPRFElgamal(&sigma[(5*i+3)*crypto_core_ristretto255_BYTES], alpha1, buf);
      }
    }
    
    //Send Sigma to R
    cout <<PARTY(party)<<": sending Sigma..."<<endl; 
    io->send_data(sigma, 5*n*crypto_core_ristretto255_BYTES);
    
    cout << PARTY(party) << " total sent: " << ((double) io->counter) / (1024 * 1024) << " MByte, per element: " << ((double) io->counter) / (n) << " Byte" << endl;
    auto elapsed = emp::time_from(grandTotalStart);
    cout << PARTY(party) << " total time: " << elapsed / 1000 << " ms" << endl;

    io->send_data(&io->counter, sizeof(uint64_t));

    delete io;

  } else { //Receiver

    unsigned char beta1[crypto_core_ristretto255_HASHBYTES];
    unsigned char beta2[crypto_core_ristretto255_HASHBYTES];
    unsigned char gbeta1[crypto_core_ristretto255_BYTES];
    unsigned char gbeta2[crypto_core_ristretto255_BYTES];

    crypto_core_ristretto255_scalar_random(beta1);
    crypto_scalarmult_ristretto255_base(gbeta1, beta1);
    crypto_core_ristretto255_scalar_random(beta2);
    crypto_scalarmult_ristretto255_base(gbeta2, beta2);

    std::vector<osuCrypto::block> y(n);
    std::vector<uint64_t> v(n);
    prngy.get(y.data(), y.size());
    prngv.get(v.data(), v.size());

    cout << "Receiver connecting..." << endl;
    auto io = new emp::NetIO("127.0.0.1", port);
    auto grandTotalStart = emp::clock_start();

    unsigned char* Y = (unsigned char*) malloc(n * crypto_core_ristretto255_BYTES);
    unsigned char* PHI = (unsigned char*) malloc(n * crypto_core_ristretto255_BYTES);

    cout <<PARTY(party)<<": hashing to curve"<<endl;
    #pragma omp parallel for
    for (size_t i = 0; i < n; i++) {
      unsigned char buf[crypto_core_ristretto255_HASHBYTES];
      bzero(buf, crypto_core_ristretto255_HASHBYTES);
      extract128(buf, y[i]);
      crypto_core_ristretto255_from_hash(&Y[i * crypto_core_ristretto255_BYTES], buf);
      memcpy(&buf[16], &v[i], sizeof(uint64_t));
      crypto_core_ristretto255_from_hash(&PHI[i * crypto_core_ristretto255_BYTES], buf);
    }

    io->send_data(gbeta1, crypto_core_ristretto255_BYTES);
    io->send_data(gbeta2, crypto_core_ristretto255_BYTES);

    unsigned char galpha1[crypto_core_ristretto255_BYTES];
    unsigned char galpha2[crypto_core_ristretto255_BYTES];
    io->recv_data(galpha1, crypto_core_ristretto255_BYTES);
    io->recv_data(galpha2, crypto_core_ristretto255_BYTES);

    unsigned char* prfsbeta1_y = (unsigned char*) malloc(n * crypto_core_ristretto255_BYTES);
    unsigned char* encsbeta2_y = (unsigned char*) malloc(2 * n * crypto_core_ristretto255_BYTES);

    cout << PARTY(party) << ": computing PRFsbeta1 and encsbeta2..." << endl;

    bytesHash hashTable;

    #pragma omp parallel for
    for (size_t i = 0; i < n; i++) {
      ristPRF(&prfsbeta1_y[i * crypto_core_ristretto255_BYTES], beta1, &Y[i * crypto_core_ristretto255_BYTES]);
      ristElgamalEnc(&encsbeta2_y[2 * i * crypto_core_ristretto255_BYTES], gbeta2, &PHI[i * crypto_core_ristretto255_BYTES]);
    }

    for (size_t i = 0; i < n; i++) {
      hashTable.insert(&prfsbeta1_y[i * crypto_core_ristretto255_BYTES], crypto_core_ristretto255_BYTES, i+1);//Recall that we cannot enter values = 0 inter the hash table.
    }
    
    unsigned char* prfsalpha1_x = (unsigned char*) malloc(n * crypto_core_ristretto255_BYTES);
    unsigned char* encsalpha2_x = (unsigned char*) malloc(2 * n * crypto_core_ristretto255_BYTES);
    io->recv_data(prfsalpha1_x, n * crypto_core_ristretto255_BYTES);
    io->recv_data(encsalpha2_x, 2 * n * crypto_core_ristretto255_BYTES);

    unsigned char* prfsbeta1alpha1_x = (unsigned char*) malloc(n * crypto_core_ristretto255_BYTES);
    unsigned char* encsalpha2beta2_x = (unsigned char*) malloc(2 * n * crypto_core_ristretto255_BYTES);

    cout << PARTY(party) << ": computing PRFSbeta1alpha1 and encsalpha2beta2..." << endl;

#pragma omp parallel for
    for (size_t i = 0; i < n ; i++) {
      ristPRF(&prfsbeta1alpha1_x[i * crypto_core_ristretto255_BYTES], beta1, &prfsalpha1_x[i * crypto_core_ristretto255_BYTES]);
      ristAddEnc(&encsalpha2beta2_x[2 * i * crypto_core_ristretto255_BYTES], beta2, gbeta2, galpha2, &encsalpha2_x[2 * i * crypto_core_ristretto255_BYTES]);
    }

    
    cout << PARTY(party) << ": Sending R_1 and R_2 back..." << endl;

    
        //Send R_1
    io->send_data(prfsbeta1alpha1_x, n * crypto_core_ristretto255_BYTES);
    io->send_data(encsalpha2beta2_x, n * 2 * crypto_core_ristretto255_BYTES);

    //Send R_2
    io->send_data(prfsbeta1_y, n * crypto_core_ristretto255_BYTES);
    io->send_data(encsbeta2_y, n * 2 * crypto_core_ristretto255_BYTES);
    
 
 cout <<PARTY(party)<<": receiving sigma..."<<endl;
    //Receiving Sigma
    unsigned char *sigma = (unsigned char*) malloc(5*n*crypto_core_ristretto255_BYTES);
    io->recv_data(sigma, 5*n*crypto_core_ristretto255_BYTES);

    cout <<PARTY(party)<<": computing intersection..."<<endl;
    size_t sum = 0;
    #pragma omp parallel for reduction (+:sum)
   for (size_t i = 0; i < n ; i++) {
     unsigned char bprime[crypto_core_ristretto255_BYTES];
     ristElgamalDec(bprime, beta2, &sigma[(5*i+1)*crypto_core_ristretto255_BYTES]);

     unsigned char cprime[crypto_core_ristretto255_BYTES];
     ristElgamalDec(cprime, beta2, &sigma[(5*i+3)*crypto_core_ristretto255_BYTES]);

     auto index = hashTable.lookup(&sigma[5*i*crypto_core_ristretto255_BYTES], crypto_core_ristretto255_BYTES);
     if (index!=0) {
       index --; //Recall that we cannot enter values = 0 inter the hash table.
       if (memcmp(bprime, cprime, crypto_core_ristretto255_BYTES)!=0) {
	 sum++;
	 //cout <<PARTY(party)<<": match at "<<int(index)<<endl;
       }
     }

   }

   cout <<PARTY(party)<<": number of matches is "<<size_t(sum)<<endl;
   //Done
    cout << PARTY(party) << " total sent: " << ((double) io->counter) / (1024 * 1024) << " MByte, per element: " << ((double) io->counter) / (n) << " Byte" << endl;

    auto elapsed = emp::time_from(grandTotalStart);
    cout << PARTY(party) << " total time to compute mismatch including waiting: " << elapsed / (1000 * 1000) << " s." << endl;

    uint64_t otherCounter;
    io->recv_data(&otherCounter, sizeof(uint64_t));
    otherCounter += io->counter;
    cout << "TOTAL COMM: " << ((double) otherCounter) / (1024 * 1024) << " MByte, per element: " << ((double) otherCounter) / (n) << " Byte" << endl;
    cout<<"+++"<<((double) otherCounter) / (1024 * 1024)<<","<<elapsed / (1000 * 1000)<<endl;

  }

}


int main(int argc, char** argv) {
  int port = 9876;

  if (argc != 3) {
    printf("Must supply log of number of elements and party number\n");
    return -1;
  }

  size_t n = (1 << atoi(argv[1]));
  int party = atoi(argv[2]);
  myRun(party, port, n);
  return 0;
}
