#include "ThreefishClass.h"

/*
enum threefishType{
  threefish256,
  threefish512,
  threefish1024,
};
*/

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

  memcpy(this->key, key, keySize / 8);
  memcpy(this->keyHash, key, skeinBlockBytes);
  skeinCtxPrepare(&ctx, skeinSize);
  threefishSetKey(&keyCtx, threefishSize, this->key, tweak);
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
  if (fileSize < 0 && ignoreFileSize == 0){
    throw ThreefishException("Error: fileSize overflowed, use IgnoreFileSize mode");
  }

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
  output.write(reinterpret_cast<char*>(blockDecrypt), skeinBlockBytes);

  threefishSetKey(&keyCtx, threefishSize, key, tweak);

  //write second block
  threefishEncryptBlockBytes(&keyCtx, keyHash, blockDecrypt);
  output.write(reinterpret_cast<char*>(blockDecrypt), skeinBlockBytes);

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
  output.write(reinterpret_cast<char*>(blockCrypt), skeinBlockBytes);

  memset(blockCrypt, 0, sizeof(*blockCrypt) * skeinBlockBytes);
  memset(blockDecrypt, 0, sizeof(*blockDecrypt) * skeinBlockBytes);
  
  //write fourth block
  Skein_Put64_LSB_First(blockDecrypt, (void*)&fileSize, sizeof(fileSize));
  threefishEncryptBlockBytes(&keyCtx, blockDecrypt, blockCrypt);
  output.write(reinterpret_cast<char*>(blockCrypt), skeinBlockBytes);

  memset(blockCrypt, 0, sizeof(*blockCrypt) * skeinBlockBytes);
  memset(blockDecrypt, 0, sizeof(*blockDecrypt) * skeinBlockBytes);
  
  while (!input.eof()) {
    input.read(reinterpret_cast<char*>(blockCrypt), skeinBlockBytes);

    threefishEncryptBlockBytes(&keyCtx, blockCrypt, blockDecrypt);
    output.write(reinterpret_cast<char*>(blockDecrypt), skeinBlockBytes);

    memset(blockCrypt, 0, sizeof(*blockCrypt) * skeinBlockBytes);
    memset(blockDecrypt, 0, sizeof(*blockDecrypt) * skeinBlockBytes);
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

  if (memcmp(keyHash, blockDecrypt, skeinBlockBytes)) {
    throw ThreefishException("Error: Invalid password");
  }

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
    input.read(reinterpret_cast<char*>(blockCrypt), skeinBlockBytes);

    if (input.fail())
      break;
    threefishDecryptBlockBytes(&keyCtx, blockCrypt, blockDecrypt);

    if (ignoreFileSize == 0) {
      if (fileSize <= skeinBlockBytes) {
        output.write(reinterpret_cast<char*>(blockDecrypt), fileSize);
        break;
      }
    }
    output.write(reinterpret_cast<char*>(blockDecrypt), skeinBlockBytes);
    fileSize -= skeinBlockBytes;

    memset(blockCrypt, 0, sizeof(*blockCrypt) * skeinBlockBytes);
    memset(blockDecrypt, 0, sizeof(*blockDecrypt) * skeinBlockBytes);
  }

  clear();
}

void Threefish::clear()
{
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
  delete[] tweak;
  delete[] blockCrypt;
  delete[] blockDecrypt;
}
