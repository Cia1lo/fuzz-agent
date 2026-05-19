#include <cstddef>
#include <cstdint>

int ParseThing(const uint8_t* data, size_t size) {
  if (size >= 5 && data[0] == 'M' && data[1] == 'A' && data[2] == 'G' && data[3] == 'I') {
    return data[4];
  }
  return 0;
}
