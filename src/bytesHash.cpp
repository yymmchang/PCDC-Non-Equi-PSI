#include "bytesHash.h"

int bytesHash::lookup(unsigned char *b, size_t length) {
  return order[hex2String(b, length)];
}

void bytesHash::insert(unsigned char *b, size_t length) {
  order[hex2String(b, length)] = 1;
}

void bytesHash::insert(unsigned char *b, size_t length, size_t value) {
  order[hex2String(b, length)] = value;
}


/*int main()
{

  bytesHash b;
  b.insert((unsigned char*)"bra",3);
    b.insert((unsigned char*)"blubbra",3);
    cout <<int(b.lookup((unsigned char*)"bra",3))<<endl;
    }
*/
