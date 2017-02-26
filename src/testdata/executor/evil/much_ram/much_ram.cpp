#include <iostream>


static const long chunk_size = 16 * 1024 * 1024 + 1234; // 16MB + 1234

int main() {
  std::cout << "much_ram" << std::endl;
  for(long i = 0; ; i++) {
    int * chunk = new int[chunk_size];
    chunk[i % chunk_size] = 123;
  }
  return 0;
}
