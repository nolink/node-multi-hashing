#ifndef DAMO_H
#define DAMO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void damo_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
