#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_hamsi.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_shabal.h"
#include "sha3/sph_whirlpool.h"
#include "sha3/sph_sha2.h"

//#include "common.h"

enum Algo {
	BLAKE = 0,
	BMW,
	GROESTL,
	JH,
	KECCAK,
	SKEIN,
	LUFFA,
	CUBEHASH,
	SHAVITE,
	SIMD,
	ECHO,
	HAMSI,
	FUGUE,
	SHABAL,
	WHIRLPOOL,
	SHA512,
	HASH_FUNC_COUNT
};

static void getDamoAlgoString(const uint8_t* prevblock, char *output)
{
	char *sptr = output;
	int j;

	for (j = 0; j < HASH_FUNC_COUNT; j++) {
		char b = (15 - j) >> 1; // 16 ascii hex chars, reversed
		uint8_t algoDigit = (j & 1) ? prevblock[b] & 0xF : prevblock[b] >> 4;
		if (algoDigit >= 10)
			sprintf(sptr, "%c", 'A' + (algoDigit - 10));
		else
			sprintf(sptr, "%u", (uint32_t) algoDigit);
		sptr++;
	}
	*sptr = '\0';
}

void damo_hash(const char* input, char* output, uint32_t len)
{
	uint32_t hash[64/4];
	char hashOrder[HASH_FUNC_COUNT + 1] = { 0 };

	sph_blake512_context     ctx_blake;
	sph_bmw512_context       ctx_bmw;
	sph_groestl512_context   ctx_groestl;
	sph_skein512_context     ctx_skein;
	sph_jh512_context        ctx_jh;
	sph_keccak512_context    ctx_keccak;
	sph_luffa512_context     ctx_luffa;
	sph_cubehash512_context  ctx_cubehash;
	sph_shavite512_context   ctx_shavite;
	sph_simd512_context      ctx_simd;
	sph_echo512_context      ctx_echo;
	sph_hamsi512_context     ctx_hamsi;
	sph_fugue512_context     ctx_fugue;
	sph_shabal512_context    ctx_shabal;
	sph_whirlpool_context    ctx_whirlpool;
	sph_sha512_context       ctx_sha512;

	void *in = (void*) input;
	int size = len;
    int i;

	getDamoAlgoString(&input[4], hashOrder);

	int count = 0;

	for (i = 9; i < 16; i++)
	{
		const char elem = hashOrder[i];
		const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';

		switch (algo) {
		case BLAKE:
			count += 3;
			sph_blake512_init(&ctx_blake);
			sph_blake512(&ctx_blake, in, size);
			sph_blake512_close(&ctx_blake, hash);
			break;
		case BMW:
			count += 2;
			sph_bmw512_init(&ctx_bmw);
			sph_bmw512(&ctx_bmw, in, size);
			sph_bmw512_close(&ctx_bmw, hash);
			break;
		case GROESTL:
			count += 15;
			sph_groestl512_init(&ctx_groestl);
			sph_groestl512(&ctx_groestl, in, size);
			sph_groestl512_close(&ctx_groestl, hash);
			break;
		case SKEIN:
			count += 1;
			sph_skein512_init(&ctx_skein);
			sph_skein512(&ctx_skein, in, size);
			sph_skein512_close(&ctx_skein, hash);
			break;
		case JH:
			count += 10;
			sph_jh512_init(&ctx_jh);
			sph_jh512(&ctx_jh, in, size);
			sph_jh512_close(&ctx_jh, hash);
			break;
		case KECCAK:
			count += 6;
			sph_keccak512_init(&ctx_keccak);
			sph_keccak512(&ctx_keccak, in, size);
			sph_keccak512_close(&ctx_keccak, hash);
			break;
		case LUFFA:
			count += 11;
			sph_luffa512_init(&ctx_luffa);
			sph_luffa512(&ctx_luffa, in, size);
			sph_luffa512_close(&ctx_luffa, hash);
			break;
		case CUBEHASH:
			count += 9;
			sph_cubehash512_init(&ctx_cubehash);
			sph_cubehash512(&ctx_cubehash, in, size);
			sph_cubehash512_close(&ctx_cubehash, hash);
			break;
		case SHAVITE:
			count += 7;
			sph_shavite512_init(&ctx_shavite);
			sph_shavite512(&ctx_shavite, in, size);
			sph_shavite512_close(&ctx_shavite, hash);
			break;
		case SIMD:
			count += 13;
			sph_simd512_init(&ctx_simd);
			sph_simd512(&ctx_simd, in, size);
			sph_simd512_close(&ctx_simd, hash);
			break;
		case ECHO:
			count += 12;
			sph_echo512_init(&ctx_echo);
			sph_echo512(&ctx_echo, in, size);
			sph_echo512_close(&ctx_echo, hash);
			break;
		case HAMSI:
			count += 16;
			sph_hamsi512_init(&ctx_hamsi);
			sph_hamsi512(&ctx_hamsi, in, size);
			sph_hamsi512_close(&ctx_hamsi, hash);
			break;
		case FUGUE:
			count += 14;
			sph_fugue512_init(&ctx_fugue);
			sph_fugue512(&ctx_fugue, in, size);
			sph_fugue512_close(&ctx_fugue, hash);
			break;
		case SHABAL:
			count += 5;
			sph_shabal512_init(&ctx_shabal);
			sph_shabal512(&ctx_shabal, in, size);
			sph_shabal512_close(&ctx_shabal, hash);
			break;
		case WHIRLPOOL:
			count += 8;
			sph_whirlpool_init(&ctx_whirlpool);
			sph_whirlpool(&ctx_whirlpool, in, size);
			sph_whirlpool_close(&ctx_whirlpool, hash);
			break;
		case SHA512:
			count += 4;
			sph_sha512_init(&ctx_sha512);
			sph_sha512(&ctx_sha512,(const void*) in, size);
			sph_sha512_close(&ctx_sha512,(void*) hash);
			break;
		}
		in = (void*) hash;
		size = 64;
	}

	if(count < 34) {
        sph_hamsi512_init(&ctx_hamsi);
        sph_hamsi512 (&ctx_hamsi, in, size);
        sph_hamsi512_close(&ctx_hamsi, hash);
    }else if(count < 46){
        sph_groestl512_init(&ctx_groestl);
        sph_groestl512 (&ctx_groestl, in, size);
        sph_groestl512_close(&ctx_groestl, hash);
    }else if(count < 54){
        sph_fugue512_init(&ctx_fugue);
        sph_fugue512 (&ctx_fugue, in, size);
        sph_fugue512_close(&ctx_fugue, hash);
    }else if(count < 61){
        sph_simd512_init(&ctx_simd);
        sph_simd512 (&ctx_simd, in, size);
        sph_simd512_close(&ctx_simd, hash);
    }else if(count < 68){
        sph_echo512_init(&ctx_echo);
        sph_echo512 (&ctx_echo, in, size);
        sph_echo512_close(&ctx_echo, hash);
    }else if(count < 73){
        sph_luffa512_init(&ctx_luffa);
        sph_luffa512 (&ctx_luffa, in, size);
        sph_luffa512_close(&ctx_luffa, hash);
    }else if(count < 78){
        sph_jh512_init(&ctx_jh);
        sph_jh512 (&ctx_jh, in, size);
        sph_jh512_close(&ctx_jh, hash);
    }else if(count < 83){
        sph_cubehash512_init(&ctx_cubehash);
        sph_cubehash512 (&ctx_cubehash, in, size);
        sph_cubehash512_close(&ctx_cubehash, hash);
    }else if(count < 88){
        sph_whirlpool_init(&ctx_whirlpool);
        sph_whirlpool(&ctx_whirlpool, in, size);
        sph_whirlpool_close(&ctx_whirlpool, hash);
    }else if(count < 93){
        sph_shavite512_init(&ctx_shavite);
        sph_shavite512(&ctx_shavite, in, size);
        sph_shavite512_close(&ctx_shavite, hash);
    }else if(count < 97){
        sph_keccak512_init(&ctx_keccak);
        sph_keccak512 (&ctx_keccak, in, size);
        sph_keccak512_close(&ctx_keccak, hash);
    }else if(count < 101){
        sph_shabal512_init(&ctx_shabal);
        sph_shabal512 (&ctx_shabal, in, size);
        sph_shabal512_close(&ctx_shabal, hash);
    }else if(count < 104){
        sph_sha512_init(&ctx_sha512);
        sph_sha512 (&ctx_sha512, (const void*)in, size);
        sph_sha512_close(&ctx_sha512, (void*)hash);
    }else if(count < 107){
        sph_blake512_init(&ctx_blake);
        sph_blake512 (&ctx_blake, in, size);
        sph_blake512_close(&ctx_blake, hash);
    }else if(count < 110){
        sph_bmw512_init(&ctx_bmw);
        sph_bmw512 (&ctx_bmw, in, size);
        sph_bmw512_close(&ctx_bmw, hash);
    }else{
        sph_skein512_init(&ctx_skein);
        sph_skein512 (&ctx_skein, in, size);
        sph_skein512_close(&ctx_skein, hash);
    }

	memcpy(output, hash, 32);
}