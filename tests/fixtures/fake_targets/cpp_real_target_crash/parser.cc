#include <cstddef>
#include <cstdint>

int ParseThing(const uint8_t* data, size_t size) {
  if (size >= 4 && data[0] == 'B' && data[1] == 'U' && data[2] == 'G' && data[3] == '!') {
    volatile int* p = nullptr;
    *p = 1;
  }
  return 0;
}
