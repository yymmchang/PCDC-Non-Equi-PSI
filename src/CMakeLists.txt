cmake_minimum_required(VERSION 3.18)

project(
  kkrt
  LANGUAGES CXX)

set(CMAKE_CXX_FLAGS "-Wall -O6 -fopenmp -Wall -Wno-ignored-attributes -march=native -maes -mrdseed")

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
#set(CMAKE_CXX_COMPILER "g++-11")
include_directories(/usr/local/opt/openssl/include /usr/local/include)
link_directories(/usr/local/lib)
set(CMAKE_CXX_FLAGS "-Wall -O3 -Xpreprocessor -fopenmp")
#set(CMAKE_CXX_FLAGS "-Wall -O0 -pg -g -Xpreprocessor -fopenmp")
SET(CMAKE_EXE_LINKER_FLAGS "-lomp")
endif()

#SET(CMAKE_EXE_LINKER_FLAGS "-pg")


find_package(libOTe REQUIRED HINTS ../libOTe/)

include_directories(../emp-tool ../emp-ot ../emp-sh2pc ../relic/include)
link_directories(../relic/lib ../emp-tool)

add_executable(s3_linear-mismatch s3_linear-mismatch.cpp bytesHash.cpp)
target_link_libraries(s3_linear-mismatch PRIVATE sodium oc::libOTe)

add_executable(s6 s6.cpp hash.cpp kkrtoprf.cpp)
target_link_libraries(s6 PRIVATE oc::libOTe)

