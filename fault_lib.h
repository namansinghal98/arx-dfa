/*
HEADER FILE: fault_lib.h

Needs the Cypher Defined (Include cipher_functions.h)
Needs FAULT_ROUND defined

The Header file defines the following 

Constants::
s : Correlation Matrix

Functions:: (Look at the Comments with the Function defination for more information)
faulty_encrypt()
correlation()
fault_location_find_setup()
fault_location_find_test()
fault_location_find_test_complete()

We are not using a completely different namespace to keep thing simple, please avoid using there names
in rest of the program or you will have redefination errors.
*/

#ifndef FAULT_LIB
#define FAULT_LIB

////////////////////////////////////////
///////////// Fault Injection //////////
////////////////////////////////////////

/*
Faulty Encryption

Fault Location: 1 to N in x, N+1 to 2*N in y
Fault Round: 1 to ROUNDS, fault is injected in the input
*/
void faulty_encrypt(uint64_t &x, uint64_t &y, uint64_t num_rounds, uint64_t fault_round, uint64_t fault_location) 
{
	uint64_t tmp;
	uint64_t i;
	for (i = 0; i < fault_round - 1; ++i) 
	{
		tmp = x;
		x = y ^ F(x) ^ k[i];
		y = tmp;
	}

	if (fault_location >= 1 && fault_location <= N)
		x ^= 0x1ull << (fault_location -1);
	else if (fault_location >= N+1 && fault_location <= 2*N)
		y ^= 0x1ull << (fault_location - N -1);

	for (; i < num_rounds; ++i) 
	{
		tmp = x;
		x = y ^ F(x) ^ k[i];
		y = tmp;
	}
}

void faulty_encrypt(uint64_t &x, uint64_t &y, uint64_t fault_location) 
{
	faulty_encrypt(x, y, ROUNDS, FAULT_ROUND, fault_location);
}

////////////////////////////////////////
///////////// Fault Prediction /////////
////////////////////////////////////////

// The correlation Matrix
double S[2 * N][2 * N] = { 0 };

double correlation(double *a, double *b)
{

	double a_mean, b_mean, a_var, b_var, num, corr;
	a_mean = b_mean = a_var = b_var = num = 0;

	for (uint64_t i = 0; i < 2 * N; ++i)
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

	for (uint64_t i = 0; i < 2 * N; ++i)
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
void fault_location_find_setup()
{
	uint64_t iterations = 1e5;

	uint64_t x,y,a,b,xf,yf;
	uint64_t xdiff, ydiff;

	uint64_t count[2 * N][2 * N] = {0};

	for (uint64_t p = 0; p < 2 * N; ++p)
	{
		for (uint64_t j = 0; j < iterations; ++j) 
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

			for (uint64_t i = 0; i < N; ++i)
			{
				if (xdiff & (0x1ull << i))
				{
					count[p][i]++;
				}
			}

			for (uint64_t i = 0; i < N; ++i)
			{
				if (ydiff & (0x1ull << i))
				{
					count[p][N+i]++;
				}
			}
		}
	}

	// for (uint64_t i=0;i<2*N;i++)
	// {
	// 	for (uint64_t j=0;j<2*N;j++)
	// 	{
	// 		printf("%ld ", count[i][j]);
	// 	}
	// 	printf("\n");
	// }

	for (uint64_t i=0;i<2*N;i++)
	{
		for (uint64_t j=0;j<2*N;j++)
		{
			S[i][j] = 0.5 - (double)count[i][j] / (double)iterations;	
		}
	}

	// for (uint64_t i=0;i<2*N;i++)
	// {
	// 	for (uint64_t j=0;j<2*N;j++)
	// 	{
	// 		printf("%f ", S[i][j]);
	// 	}
	// 	printf("\n");
	// }
}

// Input the xor for both x and y registers and return the fault position (1 to 2*N)
uint64_t find_fault_location(uint64_t xdiff, uint64_t ydiff)
{

	double trail[2 * N] = {0};
	std::vector<std::pair<double, int>> corr(2 * N);

	for (uint64_t i = 0; i < N; ++i)
	{
		if (xdiff & (0x1ull << i))
		{
			trail[i] = -0.5;
		}else
		{
			trail[i] = 0.5;
		}
	}

	for (uint64_t i = 0; i < N; ++i)
	{
		if (ydiff & (0x1ull << i))
		{
			trail[N + i] = -0.5;
		}else
		{
			trail[N + i] = 0.5;
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


	// Calculate Correlation with all the positions and the return the position with highest correlation
	for (uint64_t i = 0; i < 2 * N; ++i)
	{
		std::pair<double, int>p = {correlation(trail, S[i]), i+1};
		corr[i] = p;
	}

	std::sort(corr.begin(),corr.end());

	// for (uint64_t i = 0; i < 2 * N; ++i)
	// {
	// 	printf("%f %ld \n", corr[i].first, corr[i].second);
	// }

	return corr[2 * N -1].second;
}

// Tests the accuracy of the location_find
void fault_location_find_test()
{

	printf("\n** Starting Test: Fault Prediction Accuracy!!\n");
	uint64_t iterations = 2e4;

	uint64_t x,y,a,b,xf,yf;
	uint64_t xdiff, ydiff;
	
	uint64_t counter[2 * N] = {0};
	
	uint64_t p = uni_dist(rng) % (N*2);

	for( uint64_t p = 0; p < 2 * N; p++)
	{
		for (uint64_t l = 0; l < iterations; ++l)
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

			xdiff = x^xf;
			ydiff = y^yf;


			uint64_t k = find_fault_location(xdiff,ydiff);
		
			if (k == p+1)
			{
				counter[p]++;
			}

		}
	}

	printf("Doing %lx iterations for each fault location\n", iterations);
	printf("Fault Location : Number of correct location_finds, Accuracy\n");
	for (uint64_t i=0;i<2*N;i++)
	{
		printf("%ld : ", i+1);
		printf("%ld, %f ", counter[i], (float)counter[i]/(float)iterations);
		printf("\n");
	}
	
	printf("**Closing Test: Fault Prediction Accuracy** \n");

	printf("\n");
}

// Tests the accuracy of the location_find is a indepth view
void fault_location_find_test_complete()
{

	uint64_t iterations = 1e5;

	uint64_t x,y,a,b,xf,yf;
	uint64_t xdiff, ydiff;
	
	uint64_t counter[2 * N][2 * N] = {0};
	
	double trail[2 * N] = {0};
	std::vector<std::pair<double, int>> corr(2 * N);


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
			uint64_t p = uni_dist(rng) % (N*2);

			faulty_encrypt(xf, yf, p+1);

			xdiff = x ^ xf;
			ydiff = y ^ yf;

			for (uint64_t i = 0; i < N; ++i)
			{
				if (xdiff & (0x1ull << i))
				{
					trail[i] = -0.5;
				}else
				{
					trail[i] = 0.5;
				}
			}

			for (uint64_t i = 0; i < N; ++i)
			{
				if (ydiff & (0x1ull << i))
				{
					trail[N + i] = -0.5;
				}else
				{
					trail[N + i] = 0.5;
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

			
			for (uint64_t i = 0; i < 2 * N; ++i)
			{
				std::pair<double, int>pa = {correlation(trail, S[i]), i+1};
				corr[i] = pa;
			}

			std::sort(corr.begin(),corr.end());

			for (uint64_t i = 0; i < 2 * N; ++i)
			{
				if (corr[i].second == p+1)
					counter[p][2 * N - i -1]++;
			}
		}
	}

	for (uint64_t i=0;i<2*N;i++)
	{
		printf("%ld : ", i+1);
		for (uint64_t j=0;j<2*N;j++)
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


#endif
