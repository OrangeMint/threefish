#include "ThreefishClass.h"

/*
enum threefishType{
  threefish256,
  threefish512,
  threefish1024,
};
*/

void threadEncrypt(ThreefishKey_t &keyCtx, uint8_t *in, uint8_t *out, uint64_t size, size_t count, int skeinBlockBytes)
{
  uint8_t *threadCrypt = new uint8_t[skeinBlockBytes];
  uint8_t *threadDecrypt = new uint8_t[skeinBlockBytes];

  for (uint64_t i = 0; i < size; i += skeinBlockBytes) {
    memcpy(threadDecrypt, in + (count * size) + i, skeinBlockBytes);
    threefishEncryptBlockBytes(&keyCtx, threadDecrypt, threadCrypt);
    memcpy(out + (count * size) + i, threadCrypt, skeinBlockBytes);
  }
  delete[] threadCrypt;
  delete[] threadDecrypt;
}

void threadDecrypt(ThreefishKey_t &keyCtx, uint8_t *in, uint8_t *out, uint64_t size, size_t count, int skeinBlockBytes)
{
  uint8_t *threadCrypt = new uint8_t[skeinBlockBytes];
  uint8_t *threadDecrypt = new uint8_t[skeinBlockBytes];

  for (uint64_t i = 0; i < size; i += skeinBlockBytes) {
    memcpy(threadCrypt, in + (count * size) + i, skeinBlockBytes);
    threefishDecryptBlockBytes(&keyCtx, threadCrypt, threadDecrypt);
    memcpy(out + (count * size) + i, threadDecrypt, skeinBlockBytes);
  }
  delete[] threadCrypt;
  delete[] threadDecrypt;
}


Threefish::Threefish(const std::string &file, uint8_t *key, KeySize keySize, int IgnoreFileSize)
{
  inputFileName = file;
  ignoreFileSize = IgnoreFileSize;

  skeinMaxStateWords = SKEIN_MAX_STATE_WORDS;

  switch (keySize) {
  case Threefish256:
    skeinBlockBytes = SKEIN_256_BLOCK_BYTES;
    threefishSize = Threefish256;
    skeinSize = Skein256;
    break;
  case Threefish512:
    skeinBlockBytes = SKEIN_512_BLOCK_BYTES;
    threefishSize = Threefish512;
    skeinSize = Skein512;
    break;
  case Threefish1024:
    skeinBlockBytes = SKEIN1024_BLOCK_BYTES;
    threefishSize = Threefish1024;
    skeinSize = Skein1024;
    break;
  }

  bufIn = new uint8_t[bufSize];
  bufOut = new uint8_t[bufSize];
  blockCrypt = new uint8_t[skeinBlockBytes];
  blockDecrypt = new uint8_t[skeinBlockBytes];
  keyHash = new uint8_t[skeinBlockBytes];
  this->key = new uint64_t[skeinMaxStateWords];
  tweak = new uint64_t[skeinMaxStateWords];

  memset(this->key, 0, sizeof(*key) * skeinMaxStateWords);
  memset(keyHash, 0, sizeof(*keyHash) * skeinBlockBytes);
  memset(tweak, 0, sizeof(*tweak) * skeinMaxStateWords);
  memset(blockCrypt, 0, sizeof(*blockCrypt) * skeinBlockBytes);
  memset(blockDecrypt, 0, sizeof(*blockDecrypt) * skeinBlockBytes);
  memset(bufIn, 0, bufSize);
  memset(bufOut, 0, bufSize);

  memcpy(this->key, key, keySize / 8);
  memcpy(this->keyHash, key, skeinBlockBytes);
  skeinCtxPrepare(&ctx, skeinSize);
  threefishSetKey(&keyCtx, threefishSize, this->key, tweak);

  threadCount = std::thread::hardware_concurrency();
  if (threadCount == 0)
    threadCount = 2;
  threadVector.resize(threadCount);
}

void Threefish::setInputFileName(const std::string &fileName)
{
  inputFileName = fileName;
}

std::string Threefish::getInputFileName()
{
  return inputFileName;
}

void Threefish::setOutputFileName(const std::string &fileName)
{
  outputFileName = fileName;
}

std::string Threefish::getOutputFileName()
{
  return outputFileName;
}

void Threefish::encrypt()
{
  input.open(inputFileName, std::ios::binary);
  if (!input.is_open()) {
    throw ThreefishException("Error: can not open file");
  }
  //
  input.seekg(0, std::ios::end);
  fileSize = input.tellg();
  input.clear();
  input.seekg(0, std::ios::beg);
  /////////////////////////////////////////
  if (fileSize < 0 && ignoreFileSize == 0){
    throw ThreefishException("Error: fileSize overflowed, use IgnoreFileSize mode");
  }
  /////////////////////////////////////////

  srand(time(NULL));
  random = new uint64_t((rand() % 100000 + 1) * (rand() % 100000 + 1)); //must be changed!
  memcpy(blockDecrypt, (const void*)random, sizeof(*random));
  skeinInit(&ctx, skeinSize);
  skeinUpdate(&ctx, (const uint8_t*)inputFileName.c_str(), inputFileName.size());
  skeinUpdate(&ctx, blockDecrypt, skeinBlockBytes);
  skeinFinal(&ctx, blockCrypt);
  memset(random, 0, sizeof(*random));

  Skein_Get64_LSB_First(tweak, blockCrypt, threefishSize / 64);
  Skein_Put64_LSB_First(blockCrypt, tweak, threefishSize / 8);
  threefishEncryptBlockBytes(&keyCtx, blockCrypt, blockDecrypt);

  if (outputFileName.empty())
    outputFileName = inputFileName + add;
  output.open(outputFileName, std::ios::binary);
  if (!output.is_open()) {
    throw ThreefishException("Error: can not open output file");
  }
  //write first block 
  output.write(reinterpret_cast<char*>(blockDecrypt), skeinBlockBytes); //tweak

  threefishSetKey(&keyCtx, threefishSize, key, tweak);

  //write second block
  threefishEncryptBlockBytes(&keyCtx, keyHash, blockDecrypt);
  output.write(reinterpret_cast<char*>(blockDecrypt), skeinBlockBytes); //key

  memset(keyHash, 0, sizeof(*keyHash) * skeinBlockBytes);
  memset(blockCrypt, 0, sizeof(*blockCrypt) * skeinBlockBytes);
  memset(blockDecrypt, 0, sizeof(*blockDecrypt) * skeinBlockBytes);

  //write third block
  if (inputFileName.size() > skeinBlockBytes) {
    temp = inputFileName.find_last_of(".");
    tempStr = inputFileName.substr(temp, inputFileName.size() - temp);
    tempStr.insert(0, "...");
    inputFileName.replace(skeinBlockBytes - tempStr.size() - 1, tempStr.size(), tempStr);
    inputFileName.erase(skeinBlockBytes - 1);
  }

  Skein_Put64_LSB_First(blockDecrypt, inputFileName.c_str(), inputFileName.size() + 1);
  threefishEncryptBlockBytes(&keyCtx, blockDecrypt, blockCrypt);
  output.write(reinterpret_cast<char*>(blockCrypt), skeinBlockBytes); //file name

  memset(blockCrypt, 0, sizeof(*blockCrypt) * skeinBlockBytes);
  memset(blockDecrypt, 0, sizeof(*blockDecrypt) * skeinBlockBytes);
  
  //write fourth block
  Skein_Put64_LSB_First(blockDecrypt, (void*)&fileSize, sizeof(fileSize));
  threefishEncryptBlockBytes(&keyCtx, blockDecrypt, blockCrypt);
  output.write(reinterpret_cast<char*>(blockCrypt), skeinBlockBytes); //size

  memset(blockCrypt, 0, sizeof(*blockCrypt) * skeinBlockBytes);
  memset(blockDecrypt, 0, sizeof(*blockDecrypt) * skeinBlockBytes);
  
  while (!input.eof()) {
    input.read(reinterpret_cast<char*>(bufIn), bufSize);

    if (bufSize > (uint64_t)input.gcount()) {
      for (bufCount = 0; bufCount <= (uint64_t)input.gcount(); bufCount += skeinBlockBytes) {
        memcpy(blockDecrypt, bufIn + bufCount, skeinBlockBytes);
        threefishEncryptBlockBytes(&keyCtx, blockDecrypt, blockCrypt);
        memcpy(bufOut + bufCount, blockCrypt, skeinBlockBytes);

        memset(blockCrypt, 0, sizeof(*blockCrypt) * skeinBlockBytes);
        memset(blockDecrypt, 0, sizeof(*blockDecrypt) * skeinBlockBytes);
      }
      output.write(reinterpret_cast<char*>(bufOut), bufCount);
    }
    else {
      for (size_t i = 0; i < threadCount; i++) {
        std::thread t(threadEncrypt, std::ref(keyCtx), bufIn, bufOut, bufSize / threadCount, i, skeinBlockBytes);
        threadVector[i] = (move(t));
      }
      for (size_t i = 0; i < threadCount; i++)
        threadVector[i].join();
      output.write(reinterpret_cast<char*>(bufOut), bufSize);
    }
    memset(bufIn, 0, bufSize);
    memset(bufOut, 0, bufSize);
  }

  clear();
}

void Threefish::decrypt()
{
  input.open(inputFileName, std::ios::binary);
  if (!input.is_open()) {
    throw ThreefishException("Error: can not open file");
  }

  //read first block
  input.read(reinterpret_cast<char*>(blockCrypt), skeinBlockBytes);
  threefishDecryptBlockBytes(&keyCtx, blockCrypt, blockDecrypt);
  Skein_Get64_LSB_First(tweak, blockDecrypt, threefishSize / 64);

  threefishSetKey(&keyCtx, threefishSize, key, tweak);

  //read second block
  input.read(reinterpret_cast<char*>(blockCrypt), skeinBlockBytes);
  threefishDecryptBlockBytes(&keyCtx, blockCrypt, blockDecrypt);

  if (memcmp(keyHash, blockDecrypt, skeinBlockBytes) != 0) {
    validPassword = false;
    throw ThreefishException("Error: Invalid password");
  }
  validPassword = true;

  //read third block
  input.read(reinterpret_cast<char*>(blockCrypt), skeinBlockBytes);
  threefishDecryptBlockBytes(&keyCtx, blockCrypt, blockDecrypt);
  if (outputFileName.empty())
    outputFileName = (char*)blockDecrypt;

  memset(blockCrypt, 0, sizeof(*blockCrypt) * skeinBlockBytes);
  memset(blockDecrypt, 0, sizeof(*blockDecrypt) * skeinBlockBytes);

  //read fourth block
  input.read(reinterpret_cast<char*>(blockCrypt), skeinBlockBytes);
  threefishDecryptBlockBytes(&keyCtx, blockCrypt, blockDecrypt);
  memcpy((void*)&fileSize, blockDecrypt, sizeof(fileSize));

  memset(blockCrypt, 0, sizeof(*blockCrypt) * skeinBlockBytes);
  memset(blockDecrypt, 0, sizeof(*blockDecrypt) * skeinBlockBytes);

  output.open(outputFileName, std::ios::binary);
  if (!output.is_open()) {
    throw ThreefishException("Error: can not open output file");
  }

  while (!input.eof()) {
    input.read(reinterpret_cast<char*>(bufIn), bufSize);

    if (bufSize > (uint64_t)input.gcount()) {
      for (bufCount = 0; bufCount <= (uint64_t)input.gcount(); bufCount += skeinBlockBytes) {
        memcpy(blockCrypt, bufIn + bufCount, skeinBlockBytes);
        threefishDecryptBlockBytes(&keyCtx, blockCrypt, blockDecrypt);
        memcpy(bufOut + bufCount, blockDecrypt, skeinBlockBytes);

        memset(blockCrypt, 0, sizeof(*blockCrypt) * skeinBlockBytes);
        memset(blockDecrypt, 0, sizeof(*blockDecrypt) * skeinBlockBytes);
      } 
      if (ignoreFileSize == 0) {
        output.write(reinterpret_cast<char*>(bufOut), fileSize);
        break;
      } 
      output.write(reinterpret_cast<char*>(bufOut), input.gcount());
    }
    else {
      for (size_t i = 0; i < threadCount; i++) {
        std::thread t(threadDecrypt, std::ref(keyCtx), bufIn, bufOut, bufSize / threadCount, i, skeinBlockBytes);
        threadVector[i] = (move(t));
      }
      for (size_t i = 0; i < threadCount; i++)
        threadVector[i].join();
      output.write(reinterpret_cast<char*>(bufOut), bufSize);
      fileSize -= bufSize;
    }
    memset(bufIn, 0, bufSize);
    memset(bufOut, 0, bufSize);
  }

  clear();
}

void Threefish::clear()
{
  memset(bufIn, 0, bufSize);
  memset(bufOut, 0, bufSize);
  memset(key, 0, sizeof(*key) * skeinMaxStateWords);
  memset(keyHash, 0, sizeof(*keyHash) * skeinBlockBytes);
  memset(tweak, 0, sizeof(*tweak) * skeinMaxStateWords);
  memset(blockCrypt, 0, sizeof(*blockCrypt) * skeinBlockBytes);
  memset(blockDecrypt, 0, sizeof(*blockDecrypt) * skeinBlockBytes);

  input.close();
  output.close();
}

Threefish::~Threefish()
{

  delete random;
  delete[] key;
  delete[] keyHash;
  delete[] bufIn;
  delete[] bufOut;
  delete[] tweak;
  delete[] blockCrypt;
  delete[] blockDecrypt;
}
