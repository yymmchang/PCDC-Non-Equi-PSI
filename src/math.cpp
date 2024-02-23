#include "include.h"
double binom(double n,size_t k){
    double result = 1.0;
    for(size_t i=1; i <= k; i++){
        result *= (n+1-i)/i;
    }
    return result;
}


double logTwo(double x) {
  return log(x)/log(2.0);
}

double buckets(size_t n, size_t k, double c, size_t h) {
  //  return logTwo(c*n*binom(h*n,k)*((1/(c*n))**k))
  return logTwo(c*n*binom(h*n,k)*(pow(1/(c*n),k)));
}

size_t searchBeta(size_t n, double c, size_t h) {
  double p = 0; 
  size_t k = 0;
  while (p>-40) {
    k = k + 1;
    p = buckets(n, k, c, h);
  }
  return k;
}

