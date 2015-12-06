#include <fstream>
#include <string>

int main() {
  for (long j = 0; ; j++) {
    new std::ofstream(std::to_string(j));
  }
  return 0;
}
