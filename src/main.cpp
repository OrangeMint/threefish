//#pragma clang diagnostic ignored "-Wpadded"
#include <iostream>
#include <string>
#include <ctime>
#include <thread>
#include <ctime>

#include "ThreefishClass.h"
#include "SkeinClass.h"

using namespace std;

int main()
{
  cout << "Start" << endl;

  int f;
  cout << "Encrypt - 1, Decrypt - 2: ";
  cin >> f;

  Skein *key = new Skein("test", Skein1024, 0x2ffff);
  const clock_t start = clock();

  //Skein *key = new Skein("test", Skein1024, 0x2ffff);
  cout << *key << endl;

  Threefish *t = nullptr;
  //t = new Threefish("1.flv", key->getHash(), key1024);
  //t->encrypt();

  if (f == 1) {
    try {
      t = new Threefish("1.flv", key->getHash(), key1024);//"1.txt", key->getHash(), key1024);//Windows 7.vmdk", hash, key1024);
      t->encrypt();
    }
    catch (ThreefishException exc)
    {
      cout << exc.what() << endl;
      cin.get();
      cin.get();
      return 2;
    }
  }
  if (f == 2) {
    //do {
      //string str;
      //cout << "Enter password: ";
      //cin >> str;
      //Skein *keyDecrypt = new Skein(str.c_str(), Skein1024, 0x2ffff);
      //cout << *key << endl;

      try {
        t = new Threefish("1.flv.data", key->getHash(), key1024);//"1.txt.data", key->getHash(), key1024);//Windows 7.vmdk.data", hash, key1024);"Evangelion.avi.data"
        t->decrypt();
      }
      catch (ThreefishException exc)
      {
        cout << exc.what() << endl;
      }
      //delete keyDecrypt;
    //} while (t->validPassword != true);

  }
  delete t;
  delete key;
  //cout << *key << endl;
  const double time = static_cast<double>(clock() - start) / CLOCKS_PER_SEC;
  std::cout << endl << time << " seconds" << std::endl;

  cout << endl << "Fisnish";

  //cin.get();
  //cin.get();
  return 0;
}
