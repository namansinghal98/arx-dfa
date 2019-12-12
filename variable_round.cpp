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
#define N (16)
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

#define FAULT_ROUND (ROUNDS -2)
// Header that contains all the fault injection and location finding functions
#include "fault_lib.h"



/////////////////////////////////////////////////////////
////////////// Randon Functions Currently Testing /////////
/////////////////////////////////////////////////////////

// Function Written to find relation between hamming weight
// encrypted text and previous round registers
// Current Result: No Relations
void check_hamming_relation()
{
	uint64_t a,b,x,y,x1,y1;

	uint64_t s1,s2,s3;
	s1 = s2 = s3 = 0;

	int64_t s4 = 0;

	int c1,c2,c3,c4;

	c4 = 0;


	for(int i=0;i<1e7;i++)
	{

		a = uni_dist(rng) & WORD_MASK;
		b = uni_dist(rng) & WORD_MASK;
		setup_random_key();

		x1 = x = a;
		y1 = y = b;
		encrypt(x, y, ROUNDS);
		encrypt(x1, y1, ROUNDS-1);
		// std::cout<<hammingWeight(x)<<' ';
		// std::cout<<hammingWeight(y)<<' ';
		// std::cout<<hammingWeight(y1)<<'\n';
		

		c1 = hammingWeight(x);
		c2 = hammingWeight(y);
		c3 = hammingWeight(y1);
	

		if(c1 >= 14)
		{

			s1 += c1;
			s2 += c2;
			s3 += c3;
			c4++;

		}
	}

	if(c4 != 0)
	{
		std::cout<<s1/c4<<' ';
		std::cout<<s2/c4<<' ';
		std::cout<<s3/c4<<'\n';
	}
}


#define LOWER_ROUNDS (5)

double B[LOWER_ROUNDS][3*N];

double correlation2(double *a, double *b)
{

	double a_mean, b_mean, a_var, b_var, num, corr;
	a_mean = b_mean = a_var = b_var = num = 0;

	for (uint64_t i = 0; i < 3 * N; ++i)
	{
		if ((a[i] == 0.5 && b[i] == -0.5) || (b[i] == 0.5 && a[i] == -0.5))
		{
			return -1;
		}

		a_mean += a[i];
		b_mean += b[i];
	}

	a_mean /= 3*N;
	b_mean /= 3*N;

	for (uint64_t i = 0; i < 3 * N; ++i)
	{
		a_var += (a[i] - a_mean)*(a[i] - a_mean);
		b_var += (b[i] - b_mean)*(b[i] - b_mean);
		num += (a[i] - a_mean)*(b[i] - b_mean);
	}

	a_var = sqrt(a_var);
	b_var = sqrt(b_var);

	corr = num / (a_var * b_var);

	return corr;
}

// Calculates The Correlation Matrix (Setup before the Fault Prediction)
void fault_round_find_setup()
{
	uint64_t iterations = 1e3;

	uint64_t x,y,a,b,xf,yf;
	uint64_t xdiff, ydiff;
	uint64_t l0,l1,l2;


	uint64_t count[LOWER_ROUNDS][3 * N] = {0};

	for (uint64_t r = 0; r < LOWER_ROUNDS; ++r)
	{
		for (uint64_t j = 0; j < iterations; ++j) 
		{
			a = uni_dist(rng) & WORD_MASK;
			b = uni_dist(rng) & WORD_MASK;
			xf = x = a;
			yf = y = b;
			
			setup_random_key();
			
			encrypt(x,y);
			faulty_encrypt(xf, yf, ROUNDS, ROUNDS-r, 1);

			xdiff = x ^ xf;
			ydiff = y ^ yf;

			l0 = xdiff;
			l1 = ydiff;
			l2 = l0 ^ F(y) ^ F(y ^ l1);

			for (uint64_t i = 0; i < N; ++i)
			{
				if (l0 & (0x1ull << i))
				{
					count[r][i]++;
				}
			}

			for (uint64_t i = 0; i < N; ++i)
			{
				if (l1 & (0x1ull << i))
				{
					count[r][N+i]++;
				}
			}

			for (uint64_t i = 0; i < N; ++i)
			{
				if (l2 & (0x1ull << i))
				{
					count[r][2*N+i]++;
				}
			}
		}
	}

	for (uint64_t i=0;i<LOWER_ROUNDS;i++)
	{
		for (uint64_t j=0;j<3*N;j++)
		{
			printf("%ld ", count[i][j]);
		}
		printf("\n");
	}

	for (uint64_t i=0;i<LOWER_ROUNDS;i++)
	{
		for (uint64_t j=0;j<3*N;j++)
		{
			B[i][j] = 0.5 - (double)count[i][j] / (double)iterations;	
		}
	}

	// for (uint64_t j=0;j<3*N;j++)
	// {
	// 	B[LOWER_ROUNDS - 1][j] = 0.00001;	
	// }

	for (uint64_t i=0;i<LOWER_ROUNDS;i++)
	{
		for (uint64_t j=0;j<3*N;j++)
		{
			printf("%f ", B[i][j]);
		}
		printf("\n");
	}

}

// Tests the accuracy of the location_find is a indepth view
void fault_round_find_test_complete()
{

	uint64_t iterations = 1e5;

	uint64_t x,y,a,b,xf,yf;
	uint64_t xdiff, ydiff;
	
	uint64_t l0,l1,l2;


	uint64_t counter[LOWER_ROUNDS][LOWER_ROUNDS] = {0};
	
	double trail[3 * N] = {0};
	std::vector<std::pair<double, int>> corr(LOWER_ROUNDS);


	for (uint64_t l = 0; l < iterations; ++l)
	{
		a = uni_dist(rng) & WORD_MASK;
		b = uni_dist(rng) & WORD_MASK;
		setup_random_key();

		xf = x = a;
		yf = y = b;

		encrypt(x,y);

		for (uint64_t m = 0; m <= 4; ++m)
		{
			xf = a;
			yf = b;
			uint64_t p = uni_dist(rng) % (LOWER_ROUNDS);

			faulty_encrypt(xf, yf, ROUNDS, ROUNDS-p, 1);

			xdiff = x ^ xf;
			ydiff = y ^ yf;

			l0 = xdiff;
			l1 = ydiff;
			l2 = l0 ^ F(y) ^ F(y ^ l1);

			for (uint64_t i = 0; i < N; ++i)
			{
				if (l0 & (0x1ull << i))
				{
					trail[i] = -0.5;
				}else
				{
					trail[i] = 0.5;
				}
			}

			for (uint64_t i = 0; i < N; ++i)
			{
				if (l1 & (0x1ull << i))
				{
					trail[N + i] = -0.5;
				}else
				{
					trail[N + i] = 0.5;
				}
			}


			for (uint64_t i = 0; i < N; ++i)
			{
				if (l2 & (0x1ull << i))
				{
					trail[2*N + i] = -0.5;
				}else
				{
					trail[2*N + i] = 0.5;
				}
			}

			// for (uint64_t i = 0; i < 2 * N; ++i)
			// {
			// 	printf("%f ", trail[i]);
			// }
			// printf("\n");

			// for (uint64_t i = 0; i < 2 * N; ++i)
			// {
			// 	printf("%f ", S[p][i]);
			// }
			// printf("\n");

			
			for (uint64_t i = 0; i < LOWER_ROUNDS; ++i)
			{
				std::pair<double, int>pa = {correlation(trail, B[i]), i};
				corr[i] = pa;
			}

			std::sort(corr.begin(),corr.end());

			counter[p][corr[LOWER_ROUNDS - 1].second]++;

			// for (uint64_t i = 0; i < LOWER_ROUNDS; ++i)
			// {
			// 	if (corr[i].second == p)
			// 		counter[p][LOWER_ROUNDS - i -1]++;
			// }
		}
	}

	for (uint64_t i=0;i<LOWER_ROUNDS;i++)
	{
		printf("%ld : ", i+1);
		for (uint64_t j=0;j<LOWER_ROUNDS;j++)
		{
			printf("%ld ", counter[i][j]);
		}
		printf("\n");
	}
	
	printf("\n");
	
	// for (uint64_t i=0;i<2*N;i++)
	// {
	// 	printf("%ld : ", i+1);
	// 	for (uint64_t j=0;j<2*N;j++)
	// 	{
	// 		printf("%f ", (double)counter[i][j] / (double)iterations);
	// 	}
	// 	printf("\n");
	// }
}


int main() {

	if(DEBUG)
	{

		rng.seed(time(NULL)); // seed marsenne twister rng

		printf("%llx\n",WORD_MASK);

		// printf("%llx\n", 0x1ull);

		// uint64_t hi;

		// printf("\nllo\n");

		test();
		test_cypher();
		// uint64_t keys[M] = {0x0100, 0x0908, 0x1110, 0x1918};
		// set_key(keys);

		uint64_t x, y, ex, ey, xf, yf;
		x = 0x6565;	y = 0x6877;	ex = 0xc69b; ey = 0xe9bb;
		faulty_encrypt(x, y, 8);
		printf("%lx, %lx \n", x, y);

		printf("%s, %s \n", binary(x), binary(y));



		xf = 0x6565;	yf = 0x6877;
		
		// encrypt(xf, yf);
		// printf("%lx, %lx \n", xf, yf);
		// printf("%s, %s \n", binary(xf), binary(yf));
		// printf("%s, %s \n", binary(x^xf), binary(y^yf));

	}

	std::cout<<"N: "<<N<<std::endl;
	std::cout<<"M: "<<M<<std::endl;

	// fault_location_find_test();

	uint64_t avg_sum = 0;
	uint64_t iters = 1e2;

	fault_round_find_setup();

	fault_round_find_test_complete();
	
	// check_hamming_relation();

	return 0;
}