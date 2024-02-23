//define PREFIX64(input,i) (((uint64_t)input) & ((UINT64_MAX<<(64-i))))
//define FLIP64I(input,i) (((uint64_t)input) ^ (((uint64_t)1)<<(64-i)))

//define XORPREFIX64(input,i) (FLIP64I(PREFIX64(input,i),i))


inline uint64_t PREFIX64(uint64_t input, uint8_t i) {
  return (((uint64_t)input) & ((UINT64_MAX<<(64-i))));
}

inline uint64_t FLIP64I(uint64_t input, uint8_t i) {
  return (((uint64_t)input) ^ (((uint64_t)1)<<(64-i)));
}

inline uint64_t XORPREFIX64(uint64_t input, uint8_t i) {
  return (FLIP64I(PREFIX64(input,i),i));
}



inline uint32_t PREFIX32(uint32_t input, uint8_t i) {
  return (((uint32_t)input) & ((UINT32_MAX<<(32-i))));
}

inline uint32_t FLIP32I(uint32_t input, uint8_t i) {
  return (((uint32_t)input) ^ (((uint32_t)1)<<(32-i)));
}

inline uint32_t XORPREFIX32(uint32_t input, uint8_t i) {
  return (FLIP32I(PREFIX32(input,i),i));
}
