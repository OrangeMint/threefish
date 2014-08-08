#include "SkeinClass.h"


SkeinClass::SkeinClass(const char *str, SkeinSize_t size, size_t generation)
{
  switch (size) {
  case Skein256:
    skeinStateBytes = SKEIN_256_STATE_BYTES;
    break;
  case Skein512:
    skeinStateBytes = SKEIN_512_STATE_BYTES;
    break;
  case Skein1024:
    skeinStateBytes = SKEIN1024_STATE_BYTES;
    break;
  }

  hash = new uint8_t[skeinStateBytes];
  skeinCtxPrepare(&ctx, size);
  skeinInit(&ctx, size);
  skeinUpdate(&ctx, (const uint8_t*)str, strlen(str));
  skeinFinal(&ctx, hash);
  
  if (generation > 0) {
    for (size_t i = 0; i < generation; i++) {
      skeinInit(&ctx, size);
      skeinUpdate(&ctx, hash, skeinStateBytes);
      skeinFinal(&ctx, hash);
    }
  }
}

int SkeinClass::getSkeinStateBytes()
{
  return skeinStateBytes;
}

uint8_t* SkeinClass::getHash()
{
  return hash;
}

SkeinClass::~SkeinClass()
{
  delete[] hash;
}
