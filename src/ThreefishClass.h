#ifndef THREEFISH_CLASS_H
#define THREEFISH_CLASS_H

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <random>
#include <ctime>
#include <exception>
#include <thread>
#include <vector>

#include "skeinApi.h"
#include "threefishApi.h"


enum KeySize{
  key256 = Threefish256,
  key512 = Threefish512,
  key1024 = Threefish1024
};

enum {
  IgnoreFileSize = 1
};


class ThreefishException : public std::exception
{
private:
  std::string str;
public:
  ThreefishException(const char* exc) : std::exception()//("Threefish exception")
  {
    str = exc;
  }
  using std::exception::what;
  virtual const char* what()
  {
    return str.c_str();
  }
};

class Threefish
{
public:
  /*Key must be the same length as the cipher*/
  /*key256 = 256 bit, key512 = 512 bit or key1024 = 1024 bit*/
  /*Use IgnoreFileSize if you have a trouble with big files on the x32 platform or MinGW32*/
  explicit Threefish(const std::string &file, uint8_t *key, KeySize keySize, int IgnoreFileSize = 0);
  Threefish(const Threefish &) = delete;
  void setInputFileName(const std::string &);
  void setOutputFileName(const std::string &);
  std::string getInputFileName();
  std::string getOutputFileName();
  void encrypt();
  void decrypt();
  ~Threefish();

  bool validPassword;
  
private:
  std::ifstream input;
  std::ofstream output;

  std::string inputFileName;
  std::string outputFileName;
  std::string tempStr;
  std::string add = ".data";
   
  SkeinCtx_t ctx;
  SkeinSize_t skeinSize;
  ThreefishKey_t keyCtx;
  ThreefishSize_t threefishSize;

  int skeinBlockBytes;
  int skeinMaxStateWords;
  size_t temp;
  uint64_t fileSize;
  int ignoreFileSize;

  uint64_t bufSize = 102400000;
  uint64_t bufCount = 0;
  std::vector<std::thread> threadVector;
  size_t threadCount;

  uint8_t *bufIn = nullptr;
  uint8_t *bufOut = nullptr;
  uint8_t *blockCrypt = nullptr;
  uint8_t *blockDecrypt = nullptr;
  uint8_t *keyHash = nullptr;
  uint64_t *key = nullptr;
  uint64_t *tweak = nullptr;
  uint64_t *random = nullptr;

  void clear();
};

#endif //THREEFISH_CLASS_H