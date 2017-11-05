#include <cassert>
#include <fstream>
#include <iostream>
#include <string>

using std::cout;
using std::endl;
using std::ofstream;
using std::to_string;

int main() {
  for (int j = 0; j < 1000; j++) {
    auto * f = new ofstream(to_string(j));
    assert(*f);
    if (j % 10 == 0) {
      cout << "many_open_files: " << j << " files open" << endl;
    }
  }
  return 0;
}
