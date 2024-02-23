#include <bits/stdc++.h>

using namespace std;

class bytesHash {
public:
  std::unordered_map<string, size_t> order;

  int lookup(unsigned char *b, size_t length);
  void insert(unsigned char *b, size_t length);
  void insert(unsigned char *b, size_t length, size_t value);
};


inline string hex2String(unsigned char* str, size_t length) {
std::stringstream ss;
 for(size_t i=0; i<length; ++i) {
    ss << std::hex << (int)str[i];
 }
 
return ss.str();
}
