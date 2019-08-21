#include <stdio.h>
#include <string.h>
#include <random>
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <stdint.h>
#include <algorithm>
#include <fstream>
// Just set N and M; 
#define N (16)
#define M (4)
#define DEBUG (1)

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
uint64_t z[5][62] = {
	{1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0,1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0},
	{1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0,1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0},
	{1,0,1,0,1,1,1,1,0,1,1,1,0,0,0,0,0,0,1,1,0,1,0,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,1,0,0,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,1,0,0,1,1},
	{1,1,0,1,1,0,1,1,1,0,1,0,1,1,0,0,0,1,1,0,0,1,0,1,1,1,1,0,0,0,0,0,0,1,0,0,1,0,0,0,1,0,1,0,0,1,1,1,0,0,1,1,0,1,0,0,0,0,1,1,1,1},
	{1,1,0,1,0,0,0,1,1,1,1,0,0,1,1,0,1,0,1,1,0,1,1,0,0,0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,0,0,1,1,0,0,1,0,1,0,0,1,0,0,1,1,1,0,1,1,1,1}
};

uint64_t k[ROUNDS] = { 0 };


//TO DO:
std::mt19937 rng;
std::uniform_int_distribution<uint64_t> uni_dist(0x0ull, WORD_MASK);


// Just a beautiful display function for uint64 numbers
char* binary(uint64_t x) 
{
	char *r = new char[N+1];
	
	for (int i = 0; i < N; ++i)
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

uint64_t F(uint64_t x) 
{
	return (shift(x,1) & shift(x,8)) ^ shift(x,2);
}



void key_schedule() 
{
	uint64_t tmp;
	for (int i = M; i < ROUNDS; ++i) 
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
x is the Left Register 
y is the Right Register
*/
void encrypt(uint64_t &x, uint64_t &y, int num_rounds) 
{
	uint64_t tmp;
	for (int i = 0; i < num_rounds; ++i) 
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

void decrypt(uint64_t &x, uint64_t &y, int num_rounds) 
{
	uint64_t tmp;
	for (int i = 0; i < num_rounds; ++i) 
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

void set_key(uint64_t key[M]) 
{	
	for (int i = 0; i < M; ++i)
		k[i] = key[i] & WORD_MASK;
	
	key_schedule();
}

void setup_random_key() {
	for (int i = 0; i < M; ++i)
		k[i] = uni_dist(rng) & WORD_MASK;
	key_schedule();
}


void test()
{

	uint64_t x, y, ex, ey;

	if (N == 16 && M == 4) {
		uint64_t keys[M] = {0x0100, 0x0908, 0x1110, 0x1918};
		set_key(keys);
		x = 0x6565;	y = 0x6877;	ex = 0xc69b; ey = 0xe9bb;
	}
	if (N == 24 && M == 3) {
		uint64_t keys[M] = {0x121110, 0x0a0908, 0x020100};
		set_key(keys);
		x = 0x612067; y = 0x6e696c; ex = 0xdae5ac; ey = 0x292cac;
	}
	if (N == 24 && M == 4) {
		uint64_t keys[M] = {0x1a1918, 0x121110, 0x0a0908, 0x020100};
		set_key(keys);
		x = 0x726963; y = 0x20646e;	ex = 0x6e06a5; ey = 0xacf156;
	}
	// if (N == 32 && M == 3) {
	// 	k[2] = 0x13121110; k[1] = 0x0b0a0908; k[0] = 0x03020100; x = 0x6f722067; y = 0x6e696c63; ex = 0x5ca2e27f; ey = 0x111a8fc8;		
	// }
	// if (N == 32 && M == 4) {
	// 	k[3] = 0x1b1a1918; k[2] = 0x13121110; k[1] = 0x0b0a0908; k[0] = 0x03020100; x = 0x656b696c;	y = 0x20646e75; ex = 0x44c8fc20; ey = 0xb9dfa07a;		
	// }
	// if (N == 48 && M == 2) {
	// 	k[1] = 0x0d0c0b0a0908; k[0] = 0x050403020100; x = 0x2072616c6c69; y = 0x702065687420; ex = 0x602807a462b4; ey = 0x69063d8ff082;
	// }
	// if (N == 48 && M == 3) {
	// 	k[2] = 0x151413121110; k[1] = 0x0d0c0b0a0908; k[0] = 0x050403020100; x = 0x746168742074; y = 0x73756420666f; ex = 0xecad1c6c451e; ey = 0x3f59c5db1ae9;
	// }	
	// if (N == 64 && M == 2) {
	// 	k[1] = 0x0f0e0d0c0b0a0908; k[0] = 0x0706050403020100; x = 0x6373656420737265; y = 0x6c6c657661727420; ex = 0x49681b1e1e54fe3f; ey = 0x65aa832af84e0bbc;
	// }
	// if (N == 64 && M == 3) {	
	// 	k[2] = 0x1716151413121110; k[1] = 0x0f0e0d0c0b0a0908; k[0] = 0x0706050403020100; x = 0x206572656874206e; y = 0x6568772065626972; ex = 0xc4ac61effcdc0d4f; ey = 0x6c9c8d6e2597b85b;
	// }
	// if (N == 64 && M == 4) {
	// 	k[3] = 0x1f1e1d1c1b1a1918; k[2] = 0x1716151413121110; k[1] = 0x0f0e0d0c0b0a0908; k[0] = 0x0706050403020100; x = 0x74206e69206d6f6f; y = 0x6d69732061207369; ex = 0x8d2b5579afc8a3a0; ey = 0x3bf72a87efe7b868;
	// }
	

	encrypt(x, y);
	if (x != ex || y != ey)
		printf("Test-std::vector mismatch! %016lx %016lx <=> %016lx %016lx\n", x, y, ex, ey);
	else
		printf("**Test Successful! Ready for Attacks**\n");
}

void test_cypher() 
{	

	uint64_t x,y,a,b;
	
	for (int j = 0; j < 1e6; ++j) 
	{
		// Draw random plaintext
		a = uni_dist(rng) & WORD_MASK;
		b = uni_dist(rng) & WORD_MASK;
		x = a;
		y = b;
		
		// Draw random master key
		for (int i = 0; i < M; ++i)
			k[i] = uni_dist(rng) & WORD_MASK;
		key_schedule();
		
		// Encrypt + decrypt
		encrypt(x,y);
		decrypt(x,y);
		
		if (x != a || y != b)
			printf("encrypt/decrypt failed!\n");
	}
}

////////////////////////////////////////
/////////////// DFA ////////////////////
////////////////////////////////////////

#define FAULT_ROUND (ROUNDS -2)

double S[2 * N][2 * N] = { 0 };

double correlation(double *a, double *b)
{

	double a_mean, b_mean, a_var, b_var, num, corr;
	a_mean = b_mean = a_var = b_var = num = 0;

	for (int i = 0; i < 2 * N; ++i)
	{
		if ((a[i] == 0.5 && b[i] == -0.5) || (b[i] == 0.5 && a[i] == -0.5))
		{
			return -1;
		}

		a_mean += a[i];
		b_mean += b[i];
	}

	a_mean /= 2*N;
	b_mean /= 2*N;

	for (int i = 0; i < 2 * N; ++i)
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

void faulty_encrypt(uint64_t &x, uint64_t &y, int num_rounds, int fault_round, int fault_location) 
{
	uint64_t tmp;
	int i;
	for (i = 0; i < fault_round - 1; ++i) 
	{
		tmp = x;
		x = y ^ F(x) ^ k[i];
		y = tmp;
	}

	if (fault_location >= 1 && fault_location <= N)
		x ^= 1ul << (fault_location -1);
	else if (fault_location >= N+1 && fault_location <= 2*N)
		y ^= 1ul << (fault_location - N -1);

	for (; i < num_rounds; ++i) 
	{
		tmp = x;
		x = y ^ F(x) ^ k[i];
		y = tmp;
	}
}

void faulty_encrypt(uint64_t &x, uint64_t &y, int fault_location) 
{
	faulty_encrypt(x, y, ROUNDS, FAULT_ROUND, fault_location);
}

void dfa_offline()
{
	uint64_t iterations = 1e5;

	uint64_t x,y,a,b,xf,yf;
	uint64_t xdiff, ydiff;

	uint64_t count[2 * N][2 * N] = {0};

	for (int p = 0; p < 2 * N; ++p)
	{
		for (int j = 0; j < iterations; ++j) 
		{
			a = uni_dist(rng) & WORD_MASK;
			b = uni_dist(rng) & WORD_MASK;
			xf = x = a;
			yf = y = b;
			
			setup_random_key();
			
			encrypt(x,y);
			faulty_encrypt(xf, yf, p+1);

			xdiff = x ^ xf;
			ydiff = y ^ yf;

			for (int i = 0; i < N; ++i)
			{
				if (xdiff & (1ul << i))
				{
					count[p][i]++;
				}
			}

			for (int i = 0; i < N; ++i)
			{
				if (ydiff & (1ul << i))
				{
					count[p][N+i]++;
				}
			}
		}
	}

	// for (int i=0;i<2*N;i++)
	// {
	// 	for (int j=0;j<2*N;j++)
	// 	{
	// 		printf("%ld ", count[i][j]);
	// 	}
	// 	printf("\n");
	// }

	for (int i=0;i<2*N;i++)
	{
		for (int j=0;j<2*N;j++)
		{
			S[i][j] = 0.5 - (double)count[i][j] / (double)iterations;	
		}
	}

	// for (int i=0;i<2*N;i++)
	// {
	// 	for (int j=0;j<2*N;j++)
	// 	{
	// 		printf("%f ", S[i][j]);
	// 	}
	// 	printf("\n");
	// }
}

int predict_fault_location(uint64_t x, uint64_t y, 
							uint64_t xf, uint64_t yf)
{
	uint64_t xdiff, ydiff;

	double trail[2 * N] = {0};
	std::vector<std::pair<double, int>> corr(2 * N);

	xdiff = x ^ xf;
	ydiff = y ^ yf;

	for (int i = 0; i < N; ++i)
	{
		if (xdiff & (1ul << i))
		{
			trail[i] = -0.5;
		}else
		{
			trail[i] = 0.5;
		}
	}

	for (int i = 0; i < N; ++i)
	{
		if (ydiff & (1ul << i))
		{
			trail[N + i] = -0.5;
		}else
		{
			trail[N + i] = 0.5;
		}
	}

	// for (int i = 0; i < 2 * N; ++i)
	// {
	// 	printf("%f ", trail[i]);
	// }
	// printf("\n");

	// for (int i = 0; i < 2 * N; ++i)
	// {
	// 	printf("%f ", S[p][i]);
	// }
	// printf("\n");


	for (int i = 0; i < 2 * N; ++i)
	{

		std::pair<double, int>p = {correlation(trail, S[i]), i+1};
		corr[i] = p;
	}

	std::sort(corr.begin(),corr.end());

	// for (int i = 0; i < 2 * N; ++i)
	// {
	// 	printf("%f %d \n", corr[i].first, corr[i].second);
	// }

	return corr[2 * N -1].second;
}

void fault_prediction_test()
{

	printf("\n** Starting Test: Fault Prediction Accuracy!!\n");
	uint64_t iterations = 2e4;

	uint64_t x,y,a,b,xf,yf;
	uint64_t xdiff, ydiff;
	
	uint64_t counter[2 * N] = {0};
	
	int p = uni_dist(rng) % (N*2);

	for( int p = 0; p < 2 * N; p++)
	{
		for (int l = 0; l < iterations; ++l)
		{
			a = uni_dist(rng) & WORD_MASK;
			b = uni_dist(rng) & WORD_MASK;
			setup_random_key();

			xf = x = a;
			yf = y = b;

			encrypt(x,y);

			xf = a;
			yf = b;		

			faulty_encrypt(xf, yf, p+1);

			int k = predict_fault_location(x,y,xf,yf);
		
			if (k == p+1)
			{
				counter[p]++;
			}

		}
	}

	printf("Doing %lx iterations for each fault location\n", iterations);
	printf("Fault Location : Number of correct predictions, Accuracy\n");
	for (int i=0;i<2*N;i++)
	{
		printf("%d : ", i+1);
		printf("%ld, %f ", counter[i], (float)counter[i]/(float)iterations);
		printf("\n");
	}
	
	printf("**Closing Test: Fault Prediction Accuracy** \n");

	printf("\n");
}

void fault_prediction_test_complete()
{

	uint64_t iterations = 1e5;

	uint64_t x,y,a,b,xf,yf;
	uint64_t xdiff, ydiff;
	
	uint64_t counter[2 * N][2 * N] = {0};
	
	double trail[2 * N] = {0};
	std::vector<std::pair<double, int>> corr(2 * N);


	for (int l = 0; l < iterations; ++l)
	{
		a = uni_dist(rng) & WORD_MASK;
		b = uni_dist(rng) & WORD_MASK;
		setup_random_key();

		xf = x = a;
		yf = y = b;

		encrypt(x,y);

		for (int m = 0; m <= 4; ++m)
		{
			xf = a;
			yf = b;
			int p = uni_dist(rng) % (N*2);

			faulty_encrypt(xf, yf, p+1);

			xdiff = x ^ xf;
			ydiff = y ^ yf;

			for (int i = 0; i < N; ++i)
			{
				if (xdiff & (1ul << i))
				{
					trail[i] = -0.5;
				}else
				{
					trail[i] = 0.5;
				}
			}

			for (int i = 0; i < N; ++i)
			{
				if (ydiff & (1ul << i))
				{
					trail[N + i] = -0.5;
				}else
				{
					trail[N + i] = 0.5;
				}
			}

			// for (int i = 0; i < 2 * N; ++i)
			// {
			// 	printf("%f ", trail[i]);
			// }
			// printf("\n");

			// for (int i = 0; i < 2 * N; ++i)
			// {
			// 	printf("%f ", S[p][i]);
			// }
			// printf("\n");

			
			for (int i = 0; i < 2 * N; ++i)
			{
				std::pair<double, int>pa = {correlation(trail, S[i]), i+1};
				corr[i] = pa;
			}

			std::sort(corr.begin(),corr.end());

			for (int i = 0; i < 2 * N; ++i)
			{
				if (corr[i].second == p+1)
					counter[p][2 * N - i -1]++;
			}
		}
	}

	for (int i=0;i<2*N;i++)
	{
		printf("%d : ", i+1);
		for (int j=0;j<2*N;j++)
		{
			printf("%ld ", counter[i][j]);
		}
		printf("\n");
	}
	
	printf("\n");
	
	// for (int i=0;i<2*N;i++)
	// {
	// 	printf("%d : ", i+1);
	// 	for (int j=0;j<2*N;j++)
	// 	{
	// 		printf("%f ", (double)counter[i][j] / (double)iterations);
	// 	}
	// 	printf("\n");
	// }
}


void dfa_attack_2nd_last_round()
{

	uint64_t x,y,a,b,xf,yf,lr1x, x1,y1;

	a = uni_dist(rng) & WORD_MASK;
	b = uni_dist(rng) & WORD_MASK;
	setup_random_key();

	std::fstream cnf;
	cnf.open("dfa.cnf", std::ios::out);

	xf = x = x1 = a;
	yf = y = y1 = b;

	encrypt(x,y);
	encrypt(x1,y1,ROUNDS-1);

	printf("Plain Text : %lx %lx \n", a, b);
	printf("Encrypted : %lx %lx \n", x, y);

	int number_of_faults = 13; //Each fault involves 2 variables in the equations

	cnf << "p cnf "<<N<<' '<<number_of_faults * 2<<"\n";

	std::set<int>ff;


	for (int m = 1; m <= number_of_faults; ++m)
	{
		int p;

		p = uni_dist(rng) % (N);
		while(ff.find(p) != ff.end())
		{
			p = uni_dist(rng) % (N);
		}
		ff.insert(p);


		xf = a;
		yf = b;

		faulty_encrypt(xf, yf, ROUNDS, ROUNDS-1, p+1);

		// printf("Faulty Encrypted : %lx %lx , Fault : %d\n", xf, yf, p+1);

		int k = predict_fault_location(x,y,xf,yf);
		k--;

		if (k != p)
		{
			printf("Atteck Failed, poor fault prediction detection\n");
		}

		lr1x = y ^ yf;

		if(lr1x & (1<< ((k+1)%N) ))
		{
			cnf<<((k-7+N)%N)+1<<" 0\n";
		}else
		{
			cnf<<'-'<<((k-7+N)%N)+1<<" 0\n";	
		}

		if(lr1x & (1<< ((k+8)%N) ))
		{
			cnf<<((k+7+N)%N)+1<<" 0\n";
		}else
		{
			cnf<<'-'<<((k+7+N)%N)+1<<" 0\n";	
		}
	}
	printf("Answer : %s\n", binary(y1));

	// system("cryptominisat5 --verb 0 --maxsol 20 dfa.cnf >> sat_out.txt");
}


void dfa_attack_3rd_last_round()
{

	uint64_t x,y,a,b,xf,yf,lr1x, x1,y1;

	a = uni_dist(rng) & WORD_MASK;
	b = uni_dist(rng) & WORD_MASK;
	setup_random_key();

	std::fstream cnf;
	cnf.open("dfa.cnf", std::ios::out);

	xf = x = x1 = a;
	yf = y = y1 = b;

	encrypt(x,y);
	encrypt(x1,y1,ROUNDS-1);

	printf("Plain Text : %lx %lx \n", a, b);
	printf("%s, %s \n\n", binary(a), binary(b));

	printf("Encrypted : %lx %lx \n", x, y);
	printf("%s, %s \n\n", binary(x), binary(y));

	int number_of_faults = 9; //Each fault involves 2 variables in the equations

	cnf << "p cnf "<<N<<' '<<number_of_faults<<"\n";

	std::set<int>ff;
	std::map<int,int>vars;
	int var_counter = N+1;

	for (int m = 1; m <= number_of_faults; ++m)
	{
		int p;

		p = uni_dist(rng) % (N);
		while(ff.find(p) != ff.end())
		{
			p = uni_dist(rng) % (N);
		}

		ff.insert(p);

		xf = a;
		yf = b;

		faulty_encrypt(xf, yf, ROUNDS, ROUNDS-2, p+1);
		// faulty_encrypt(xf, yf, p+1);

		printf("Faulty Encrypted : %lx %lx , Fault : %d\n", xf, yf, p+1);

		int k = predict_fault_location(x,y,xf,yf);
		k--;

		if (k != p)
		{
			printf("Atteck Failed, poor fault prediction detection\n");
		}


		int c,d;
		int A = ((k-7+N)%N)+1;
		int B = ((k+7+N)%N)+1;

		if(vars.find(A) != vars.end())
		{
			c = vars[A];
		}else
		{
			c = var_counter;
			vars[A] = var_counter;
			var_counter++;
		}

		if(vars.find(B) != vars.end())
		{
			d = vars[B];
		}else
		{
			d = var_counter;
			vars[B] = var_counter;
			var_counter++;
		}

		lr1x = y ^ yf;
		printf("xor: %s \n\n", binary(lr1x));

		if(lr1x & (1<< ((k+2)%N) ))
		{
			cnf<<((k-6+N)%N)+1<<" 0\n";
			cnf<<c<<" 0\n";
		}else
		{
			cnf<<'-'<<((k-6+N)%N)+1<<" -"<<c<<" 0\n";	
		}

		if((k+16)%N != k)
		{		
			if(lr1x & (1<< ((k+16)%N) ))
			{
				cnf<<((k+15)%N)+1<<" 0\n";
				cnf<<d<<" 0\n";
			}else
			{
				cnf<<'-'<<((k+15)%N)+1<<" -"<<d<<" 0\n";	
			}	
		}else
		{
			if(lr1x & (1<< ((k+16)%N) ))
			{
				cnf<<'-'<<((k+15)%N)+1<<" -"<<d<<" 0\n";	
			}else
			{
				cnf<<((k+15)%N)+1<<" 0\n";
				cnf<<d<<" 0\n";
			}
		}


		if(lr1x & (1<< ((k+3)%N) ))
		{
			cnf<<'x'<<((k-5+N)%N)+1<<" "<<c<<" 0\n";
		}else
		{
			cnf<<'x'<<((k-5+N)%N)+1<<" -"<<c<<" 0\n";
		}

		if(lr1x & (1<< ((k+10)%N) ))
		{
			cnf<<'x'<<((k+9)%N)+1<<" "<<d<<" 0\n";
		}else
		{
			cnf<<'x'<<((k+9)%N)+1<<" -"<<d<<" 0\n";
		}

		int a = ((k+1)%N)+1;
		int b = ((k+8)%N)+1;

		if(lr1x & (1<< ((k+9)%N)))
		{
			cnf<<b<<" "<<d<<" 0\n";
			cnf<<a<<" "<<c<<" 0\n";
			cnf<<c<<" "<<d<<" 0\n";
			cnf<<"-"<<a<<" "<<b<<" -"<<c<<" 0\n";
			cnf<<a<<" -"<<b<<" -"<<d<<" 0\n";
		}else
		{
			cnf<<"-"<<a<<" "<<c<<" "<<d<<" 0\n";
			cnf<<"-"<<b<<" -"<<c<<" "<<d<<" 0\n";
			cnf<<"-"<<a<<" -"<<b<<" -"<<c<<" -"<<d<<" 0\n";
			cnf<<a<<" "<<b<<" -"<<c<<" -"<<d<<" 0\n";
		}
	}

	printf("Answer : %s\n", binary(y1));
	printf("Mappings:\n");
	for(auto a: vars)
	{
		printf("%d,%d\n",a.first,a.second);
	}
}

void dfa_online()
{

	uint64_t x,y,a,b,xf,yf;

	a = uni_dist(rng) & WORD_MASK;
	b = uni_dist(rng) & WORD_MASK;
	setup_random_key();

	xf = x = a;
	yf = y = b;

	encrypt(x,y);

	printf("Plain Text : %lx %lx \n", a, b);
	printf("Encrypted : %lx %lx \n", x, y);

	for (int m = 0; m <= 4; ++m)
	{
		xf = a;
		yf = b;
		int p = uni_dist(rng) % (N*2);

		faulty_encrypt(xf, yf, p+1);

		printf("Faulty Encrypted : %lx %lx , Fault : %d\n", xf, yf, p+1);

		int k = predict_fault_location(x,y,xf,yf);

		printf("%d\n", k);
		printf("\n");
	}
}


int main() {

	rng.seed(time(NULL)); // seed marsenne twister rng

	printf("%llx\n",WORD_MASK);

	// printf("%llx\n", 0x1ull);

	// uint64_t hi;

	// printf("\nllo\n");

	test();
	test_cypher();
	uint64_t keys[M] = {0x0100, 0x0908, 0x1110, 0x1918};
	set_key(keys);

	uint64_t x, y, ex, ey, xf, yf;
	x = 0x6565;	y = 0x6877;	ex = 0xc69b; ey = 0xe9bb;
	faulty_encrypt(x, y, 8);
	printf("%lx, %lx \n", x, y);
	printf("%s, %s \n", binary(x), binary(y));

	xf = 0x6565;	yf = 0x6877;
	
	encrypt(xf, yf);
	printf("%lx, %lx \n", xf, yf);
	printf("%s, %s \n", binary(xf), binary(yf));
	printf("%s, %s \n", binary(x^xf), binary(y^yf));


	dfa_offline();
	// dfa_online();
	// fault_prediction_test();
	// dfa_attack_2nd_last_round();
	dfa_attack_3rd_last_round();

	return 0;
}