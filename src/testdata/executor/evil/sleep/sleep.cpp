#include <unistd.h>

int main() {
  const int seconds_per_day = 24 * 60 * 60;
  sleep(seconds_per_day);
  return 0;
}
