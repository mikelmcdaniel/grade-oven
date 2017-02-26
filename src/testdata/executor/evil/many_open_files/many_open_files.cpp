#include <fstream>
#include <iostream>
#include <string>

int main() {
  std::cout << "many_open_files" << std::endl;
  for (long j = 0; ; j++) {
    new std::ofstream(std::to_string(j));
  }
  return 0;
}
