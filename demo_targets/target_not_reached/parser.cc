#include "parser.h"

int ParseThing(const uint8_t* data, size_t size) {
  if (size >= 3 && data[0] == 'O' && data[1] == 'K') {
    return data[2];
  }
  return 0;
}

