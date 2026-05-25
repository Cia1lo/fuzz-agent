#include "parser.h"

int ParseThing(const uint8_t* data, size_t size) {
  if (size >= 2 && data[0] == 'H' && data[1] == 'I') {
    return 7;
  }
  return 0;
}

