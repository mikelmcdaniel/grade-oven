#include <cassert>
#include <iostream>

using std::cout;
using std::endl;

static const long chunk_size = 4 * 1024; // 4k

int main() {
  cout << "much_ram" << endl;
  for(long i = 0; i <= 2 * 100 * 1024 * 1024 / chunk_size; i++) {
    int * chunk = new int[chunk_size];
    assert(chunk);
    chunk[0] = i;
    if (i * chunk_size % (1024 * 1024) == 0) {
      cout << "much_ram: Allocated " << i * chunk_size / (1024 * 1024)
           << "MB." << endl;
    }
  }
  return 0;
}
