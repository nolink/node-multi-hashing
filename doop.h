#ifndef DOOP_H
#define DOOP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void doop_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
