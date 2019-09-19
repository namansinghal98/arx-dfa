/*
HEADER FILE: cipher_functions.h

This Header File Needs to following parameters if the cypher defined before being included:

N
M
ROUNDS
WORD_MASK
CONST_C

The Header file defines the following 

Constants::
z : Key Schedule Constant
rng, uniform_int_distribution : Randon Number Generation
k : key values

Functions:: (Look at the Comments with the Function defination for more information)
binary()
shift()
key_schedule()
encrypt()
decrypt()
set_key()
setup_random_key()
test_cypher()

**The Round Function ("F") will be defined after including this header file for different cyphers**

We are not using a completely different namespace to keep thing simple, please avoid using there names
in rest of the program or you will have redefination errors.
*/

#ifndef CYPHER_FUNCTIONS
#define CYPHER_FUNCTIONS

#include <random>

uint64_t z[5][62] = {
	{1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0,1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0},
	{1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0,1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0},
	{1,0,1,0,1,1,1,1,0,1,1,1,0,0,0,0,0,0,1,1,0,1,0,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,1,0,0,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,1,0,0,1,1},
	{1,1,0,1,1,0,1,1,1,0,1,0,1,1,0,0,0,1,1,0,0,1,0,1,1,1,1,0,0,0,0,0,0,1,0,0,1,0,0,0,1,0,1,0,0,1,1,1,0,0,1,1,0,1,0,0,0,0,1,1,1,1},
	{1,1,0,1,0,0,0,1,1,1,1,0,0,1,1,0,1,0,1,1,0,1,1,0,0,0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,0,0,1,1,0,0,1,0,1,0,0,1,0,0,1,1,1,0,1,1,1,1}
};


// Library Used to Generate Randon Numbers With a Uniform Distribuation
std::mt19937 rng;
std::uniform_int_distribution<uint64_t> uni_dist(0x0ull, WORD_MASK);

// The Key array that stores the whole key schedule
uint64_t k[ROUNDS] = { 0 };

// The Round Function, this will be different for multiple cyphers with this architecture
uint64_t F(uint64_t x);


int hammingWeight(uint64_t x) {
    x -= (x >> 1) & 0x5555555555555555;             //put count of each 2 bits into those 2 bits
    x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333); //put count of each 4 bits into those 4 bits 
    x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f;        //put count of each 8 bits into those 8 bits 
    return (x * 0x0101010101010101) >> 56;  //returns left 8 bits of x + (x<<8) + (x<<16) + (x<<24) + ... 
}  



// Just a beautiful display function for uint64 numbers
char* binary(uint64_t x) 
{
	char *r = new char[N+1];
	
	for (uint64_t i = 0; i < N; ++i)
		r[i] = ((x >> (N-1-i)) & 0x1) ? '1' : '0';
	r[N] = '\0';

	return r;
}

// General round shift function, left positive, right negative
uint64_t shift(uint64_t x, int p) 
{
	if (p >= N || p <= -N)
		perror("Bad rotation amount!\n");
			
	return (p > 0) ? 
		((x << p) | (x >> (N-p))) & WORD_MASK :
		((x >> (-p)) | (x << (N+p))) & WORD_MASK;
}

// Calculates the whole key schedule given first M keys are set. 
void key_schedule() 
{
	uint64_t tmp;
	for (uint64_t i = M; i < ROUNDS; ++i) 
	{
		tmp = shift(k[i-1], -3);
		
		if (M == 4)
			tmp ^= k[i-3];
		tmp ^= shift(tmp, -1);
		
		k[i] = k[i-M] ^ z[CONST_J][(i-M) % 62] ^ tmp ^ CONST_C;
	}
			//printf("k[%2d] : %s   wt : %d\n", i, binary(k[i]), weight(k[i]));
}


/*
The Encrypt Function
x is the Left Register (Plain Text) 
y is the Right Register (Plain Text)

Output: x,y as the Encrypted left and right registers.
*/
void encrypt(uint64_t &x, uint64_t &y, uint64_t num_rounds) 
{
	uint64_t tmp;
	for (uint64_t i = 0; i < num_rounds; ++i) 
	{
		tmp = x;
		x = y ^ F(x) ^ k[i];
		y = tmp;
	}
}

void encrypt(uint64_t &x, uint64_t &y) 
{
	encrypt(x, y, ROUNDS);
}

/*
The Decrypt Function
x is the Left Register (Encrypted Text) 
y is the Right Register (Encrypted Text)

Output: x,y as the Plain left and right registers.
*/
void decrypt(uint64_t &x, uint64_t &y, uint64_t num_rounds) 
{
	uint64_t tmp;
	for (uint64_t i = 0; i < num_rounds; ++i) 
	{
		tmp = y;
		y = x ^ F(y) ^ k[ROUNDS-i-1];
		x = tmp;
	}
}

void decrypt(uint64_t &x, uint64_t &y) 
{
	decrypt(x, y, ROUNDS);
}


// Sets given values for first M keys
void set_key(uint64_t key[M]) 
{
	for (uint64_t i = 0; i < M; ++i)
		k[i] = key[i] & WORD_MASK;
	
	key_schedule();
}

// Sets randon values for first M keys 
void setup_random_key() {
	for (uint64_t i = 0; i < M; ++i)
		k[i] = uni_dist(rng) & WORD_MASK;
	key_schedule();
}

// Tests the cypher by checking encryption and decryption work fine.
void test_cypher() 
{	

	uint64_t x,y,a,b;
	
	for (uint64_t j = 0; j < 1e6; ++j) 
	{
		// Draw random plaintext
		a = uni_dist(rng) & WORD_MASK;
		b = uni_dist(rng) & WORD_MASK;
		x = a;
		y = b;
		
		// Draw random master key
		for (uint64_t i = 0; i < M; ++i)
			k[i] = uni_dist(rng) & WORD_MASK;
		key_schedule();
		
		// Encrypt + decrypt
		encrypt(x,y);
		decrypt(x,y);
		
		if (x != a || y != b)
			printf("encrypt/decrypt failed!\n");
	}
}


#endif
