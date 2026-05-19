#include <cstddef>
#include <cstdint>

int ParseThing(const uint8_t* data, size_t size) {
  return size > 0 ? data[0] : 0;
}
