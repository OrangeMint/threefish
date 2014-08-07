#ifndef SKEIN_CLASS_H
#define SKEIN_CLASS_H

#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <cstdio>

#include "skeinApi.h"

class SkeinClass;
static std::ostream &operator<<(std::ostream &out, SkeinClass &skein);


class SkeinClass
{
public:
  friend std::ostream &operator<<(std::ostream &, SkeinClass &);

  explicit SkeinClass(const char *, SkeinSize_t, size_t = 0);
  SkeinClass(const SkeinClass &) = delete;
  uint8_t* getHash();
  int getSkeinStateBytes();
  ~SkeinClass();
  void printHash();


private:
  int skeinStateBytes;
  SkeinCtx_t ctx;
  SkeinSize_t skeinSize;
  uint8_t *hash = nullptr;
}; 

static std::ostream &operator<<(std::ostream &out, SkeinClass &skein)
{
  int size = skein.getSkeinStateBytes();
  uint8_t *temp = skein.getHash();
  out << std::setw(2) << std::setfill('0') << std::setbase(16);
  for (int i = 0; i < size; i++) {
    //printf("%02x", temp[i]);
    out << static_cast<int>(temp[i]);
  }
  out << std::setw(0) << std::setfill(' ') << std::setbase(10);
  return out;
}

typedef SkeinClass Skein;
#endif //SKEIN_CLASS_H