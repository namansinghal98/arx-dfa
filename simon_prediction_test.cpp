#include <stdio.h>
#include <string.h>
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <stdint.h>
#include <algorithm>
#include <fstream>
#include <cryptominisat5/cryptominisat.h>
#include <chrono>

// g++ simon.cpp -lcryptominisat5 -std=c++11


using CMSat::Lit;
using CMSat::lbool;
using CMSat::SATSolver;
using std::vector;
using std::pair;


// Just set N and M; 
#define N (64)
#define M (4)
#define DEBUG (0)

#if (N == 64)
	#define WORD_MASK (0xffffffffffffffffull)
#else
	#define WORD_MASK ((0x1ull << (N&63)) - 1)
#endif

#define CONST_C ((0xffffffffffffffffull ^ 0x3ull) & WORD_MASK)

#if (N == 4)
	#define ROUNDS (32)
	#define CONST_J (0)
#elif (N == 16)
	#define ROUNDS (32)
	#define CONST_J (0)
#elif (N == 24)
	#if (M == 3)
		#define ROUNDS (36)
		#define CONST_J (0)
	#elif (M == 4)
		#define ROUNDS (36)
		#define CONST_J (1)
	#endif
#elif (N == 32)
	#if (M == 3)
		#define ROUNDS (42)
		#define CONST_J (2)
	#elif (M == 4)
		#define ROUNDS (44)
		#define CONST_J (3)
	#endif
#elif (N == 48)
	#if (M == 2)
		#define ROUNDS (52)
		#define CONST_J (2)
	#elif (M == 3)
		#define ROUNDS (54)
		#define CONST_J (3)
	#endif
#elif (N == 64)
	#if (M == 2)
		#define ROUNDS (68)
		#define CONST_J (2)
	#elif (M == 3)
		#define ROUNDS (69)
		#define CONST_J (3)
	#elif (M == 4)
		#define ROUNDS (72)
		#define CONST_J (4)
	#endif
#endif


//////////////////////////////////////
///////////////// Start //////////////
//////////////////////////////////////


//////////////////////////////////////
//////////// The Cypher //////////////
//////////////////////////////////////

// The Header File contains all the functions of the Cypher
#include "cipher_functions.h"

// The Round Function
uint64_t F(uint64_t x) 
{
	return (shift(x,1) & shift(x,8)) ^ shift(x,2);
}

void test()
{

	uint64_t x, y, ex, ey;

	if (N == 16 && M == 4) {
		uint64_t keys[] = {0x0100, 0x0908, 0x1110, 0x1918};
		set_key(keys);
		x = 0x6565;	y = 0x6877;	ex = 0xc69b; ey = 0xe9bb;
	}
	if (N == 24 && M == 3) {
		uint64_t keys[] = {0x121110, 0x0a0908, 0x020100};
		set_key(keys);
		x = 0x612067; y = 0x6e696c; ex = 0xdae5ac; ey = 0x292cac;
	}
	if (N == 24 && M == 4) {
		uint64_t keys[] = {0x1a1918, 0x121110, 0x0a0908, 0x020100};
		set_key(keys);
		x = 0x726963; y = 0x20646e;	ex = 0x6e06a5; ey = 0xacf156;
	}
	if (N == 32 && M == 3) {
		uint64_t keys[] = {0x03020100, 0x0b0a0908, 0x13121110};
		set_key(keys);
		x = 0x6f722067; y = 0x6e696c63; ex = 0x5ca2e27f; ey = 0x111a8fc8;		
	}
	if (N == 32 && M == 4) {
		uint64_t keys[] = {0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918};
		set_key(keys);
		x = 0x656b696c;	y = 0x20646e75; ex = 0x44c8fc20; ey = 0xb9dfa07a;		
	}
	if (N == 48 && M == 2) {
		uint64_t keys[] = {0x050403020100, 0x0d0c0b0a0908};
		set_key(keys);
		x = 0x2072616c6c69; y = 0x702065687420; ex = 0x602807a462b4; ey = 0x69063d8ff082;
	}
	if (N == 48 && M == 3) {
		uint64_t keys[] = {0x050403020100, 0x0d0c0b0a0908, 0x151413121110};
		set_key(keys);
		x = 0x746168742074; y = 0x73756420666f; ex = 0xecad1c6c451e; ey = 0x3f59c5db1ae9;
	}	
	if (N == 64 && M == 2) {
		uint64_t keys[] = {0x0706050403020100, 0x0f0e0d0c0b0a0908};
		set_key(keys);
		x = 0x6373656420737265; y = 0x6c6c657661727420; ex = 0x49681b1e1e54fe3f; ey = 0x65aa832af84e0bbc;
	}
	if (N == 64 && M == 3) {	
		uint64_t keys[] = {0x0706050403020100, 0x0f0e0d0c0b0a0908, 0x1716151413121110};
		set_key(keys);
		x = 0x206572656874206e; y = 0x6568772065626972; ex = 0xc4ac61effcdc0d4f; ey = 0x6c9c8d6e2597b85b;
	}
	if (N == 64 && M == 4) {
		uint64_t keys[] = {0x0706050403020100, 0x0f0e0d0c0b0a0908, 0x1716151413121110, 0x1f1e1d1c1b1a1918};
		set_key(keys);
		x = 0x74206e69206d6f6f; y = 0x6d69732061207369; ex = 0x8d2b5579afc8a3a0; ey = 0x3bf72a87efe7b868;
	}
	
	encrypt(x, y);
	if (x != ex || y != ey)
		printf("Test-std::vector mismatch! %016lx %016lx <=> %016lx %016lx\n", x, y, ex, ey);
	else
		printf("**Test Successful! Ready for Attacks**\n");
}


////////////////////////////////////////
/////////////// DFA ////////////////////
////////////////////////////////////////

////////////////////////////////////////
// Fault Injection and Prediction //////
////////////////////////////////////////

// ROUNDS - x represents T - x - 1 round 
// (Last round is T -1 which is ROUNDS - 0)
#define FAULT_ROUND (ROUNDS-7) 
// Header that contains all the fault injection and location finding functions
#include "fault_lib_2.h"


int main() {

	rng.seed(time(NULL)); // seed marsenne twister rng

	std::cout<<"N: "<<N<<std::endl;
	std::cout<<"M: "<<M<<std::endl;
	std::cout<<"Fault Round: T - "<<ROUNDS - FAULT_ROUND + 1<<std::endl;

	fault_location_find_setup();
	fault_location_find_test();

	return 0;
}