#include "cryptoTools/Crypto/PRNG.h"

#include "hash.h"

AES aesHash(osuCrypto::block(4253465, 3434565));
AES aesHash1(osuCrypto::block(425346, 3433365));
AES aesHash2(osuCrypto::block(42534, 2234565));
AES aesHash3(osuCrypto::block(42535, 3422565));


bucket::bucket(size_t beta) {
  x.resize(beta);
  u.resize(beta);
  load = 0;
}

bucket::~bucket() {

}

void simpleHashTable::printTable() {
  for (size_t i = 0; i < m ; i++) {
    cout << size_t(i) << ": ";

    for (uint8_t j = 0; j < table[i].load; j++) {
      cout << table[i].x[j] << " ";
    }
    
    cout <<"load = "<<int(table[i].load)<< endl;
  }
}

simpleHashTable::simpleHashTable(size_t mySize, size_t myBeta) {
  for (size_t i = 0; i < mySize; i++) {
    bucket b(myBeta);
    table.push_back(b);
  }

  m = mySize;
  beta = myBeta;
}

simpleHashTable::~simpleHashTable() {

}

void simpleHashTable::computeSimpleHashTable(vector<osuCrypto::block> x, vector<uint64_t> u) {

  cout <<"Bug here: we need to check whether element is already in bucket"<<endl;
  exit(1);
  
  for  (size_t i = 0; i < x.size(); i++) {
    size_t index;
    hashBlock2u64(index, x[i]);
    index = index % m;

    table[index].x[table[index].load] = x[i];
    table[index].u[table[index].load] = u[i];

    table[index].load++;

  }


}

inline bool isInBucket(osuCrypto::block x, bucket b) {

  for (uint8_t i = 0; i < b.load ; i++) {
    if (b.x[i] == x) {
      return true;
    }
  }

  return false;

}

void simpleHashTable::computeSimpleTripleHashTable(vector<osuCrypto::block> x, vector<uint64_t> u) {

  for  (size_t i = 0; i < x.size(); i++) {
    size_t index;
    hashBlock2u64_1(index, x[i]);
    index = index % m;

    if (isInBucket(x[i], table[index]) == false) {
      table[index].x[table[index].load] = x[i];
      table[index].u[table[index].load] = u[i];
      table[index].load++;
    }

    //cout <<int(i)<<" goes in "<<int(index)<<" ";

    hashBlock2u64_2(index, x[i]);
    index = index % m;

    if (isInBucket(x[i], table[index]) == false) {
      table[index].x[table[index].load] = x[i];
      table[index].u[table[index].load] = u[i];
      table[index].load++;
    }

    //cout <<int(index)<<" ";

    hashBlock2u64_3(index, x[i]);
    index = index % m;

    if (isInBucket(x[i], table[index]) == false) {
      table[index].x[table[index].load] = x[i];
      table[index].u[table[index].load] = u[i];
      table[index].load++;
    }

    //cout <<int(index)<<endl;

  }
}

void simpleHashTable::computeSimpleTripleHashTable(vector<osuCrypto::block> x) {

  for  (size_t i = 0; i < x.size(); i++) {
    size_t index;
    hashBlock2u64_1(index, x[i]);
    index = index % m;

    if (isInBucket(x[i], table[index]) == false) {
      table[index].x[table[index].load] = x[i];
      table[index].load++;

      /*      if (index == 11) {
        cout << int(i) << " (" << x[i] << ") goes in " << int(index) << " using 1st hash" << endl;
	}*/

    }


    hashBlock2u64_2(index, x[i]);
    index = index % m;

    if (isInBucket(x[i], table[index]) == false) {
      table[index].x[table[index].load] = x[i];
      table[index].load++;

      /*      if (index == 11) {
        cout << int(i) << " (" << x[i] << ") goes in " << int(index) << " using 2nd hash" << endl;
	}*/

    }

    //cout <<int(index)<<" ";

    hashBlock2u64_3(index, x[i]);
    index = index % m;

    if (isInBucket(x[i], table[index]) == false) {
      table[index].x[table[index].load] = x[i];
      table[index].load++;

      /*if (index == 11) {
        cout << int(i) << " (" << x[i] << ") goes in " << int(index) << " using 3rd hash" << endl;
	}*/

    }

  }
}



cuckooHashTable::cuckooHashTable(size_t mySize) {
  m = mySize;
  table.resize(m);
}


cuckooHashTable::~cuckooHashTable() {

}

void cuckooHashTable::printTable() {
  for (size_t i = 0; i < m ; i++) {
    cout << size_t(i) << ": "<<table[i].x<<", load = "<<int(table[i].load)<<endl;
  }
}

void cuckooHashTable::printLoads() {
  for (size_t i = 0; i < m ; i++) {
    cout << size_t(i) << ": "<<int(table[i].load)<<endl;
  }
}



void cuckooHashTable::computeCuckooHashTable(vector<osuCrypto::block> x, vector<uint64_t> u) {

  for (size_t i = 0; i < x.size(); i++) {
    //cout << int(i) << endl;

    cuckooBucket b;
    b.x = x[i];
    b.u = u[i];
    b.load = 1;
    b.choice = 0;
    b.item = i;
    //size_t iterations = 0;

    while (b.load == 1) {
      block xyz = b.x;
      size_t index;
      threeChoiceHash(index, xyz, m, b.choice);
      b.choice = (b.choice + 1) % 3;

      swap(b, table[index]);

      //iterations ++;
    }
  }
}

void cuckooHashTable::computeCuckooHashTable(vector<osuCrypto::block> x) {
  //printLoads();

  for (size_t i = 0; i < x.size(); i++) {
    //cout << int(i) << endl;

    cuckooBucket b;
    b.x = x[i];
    b.load = 1;
    b.choice = 0;
    b.item = i;
    size_t iterations = 0;

    while (b.load == 1) {
      block xyz = b.x;
      size_t index;

      if (iterations >100) {
	cout <<"too many iterations"<<endl;
      }
      
      /*if (iterations > 100 ) {
	cout <<"too many iterations "<<endl;
	exit(1);
	threeChoiceHash(index, xyz, m, b.choice);
	cout <<"i: "<<size_t(i)<<", "<<xyz<<", "<<index<<", holding "<<size_t(b.item)<<endl;
	
	if (iterations>120) {
	  printLoads();
	  cout <<size_t(x.size())<<endl;
	exit(1);
	}
	}*/


      threeChoiceHash(index, xyz, m, b.choice);
      b.choice = (b.choice + 1) % 3;

      swap(b, table[index]);

      iterations ++;
    }
  }
}


cuckooBucket::cuckooBucket() {

}

cuckooBucket::~cuckooBucket() {

}
