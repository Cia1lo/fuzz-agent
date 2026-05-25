#include "parser.h"

int ParseThing(const uint8_t* data, size_t size) {
  if (size > 0 && data[0] == 'S') {
    return 1;
  }
  return 0;
}

