#include "parser.h"

#include <cstdlib>

int ParseThing(const uint8_t* data, size_t size) {
  if (size < 5) {
    return 0;
  }

  char* buf = static_cast<char*>(std::malloc(4));
  if (buf == nullptr) {
    return 0;
  }

  int checksum = 0;
  for (size_t i = 0; i < size; ++i) {
    // Target-owned heap out-of-bounds write for inputs longer than 4 bytes.
    buf[i] = static_cast<char>(data[i]);
    checksum += buf[i];
  }

  std::free(buf);
  return checksum;
}
