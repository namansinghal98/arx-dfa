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
#define M (2) 
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
	return (shift(x,0) & shift(x,5)) ^ shift(x,1);
}


////////////////////////////////////////
/////////////// DFA ////////////////////
////////////////////////////////////////

////////////////////////////////////////
// Fault Injection and Prediction //////
////////////////////////////////////////

// ROUNDS - x represents T - x - 1 round 
// (Last round is T -1 which is ROUNDS - 0)
#define FAULT_ROUND (ROUNDS-2) 
// Header that contains all the fault injection and location finding functions
#include "fault_lib_2.h"

///////////////////////////////////////
////////////// SAT SETUP //////////////
///////////////////////////////////////

#include "sat_functions.h"


// Add Equations given the Fault is in Round R given the xor of L register of round R+2 or R redister of R+3
void equations(SATSolver &solver,uint64_t l1, uint64_t l2, uint64_t k, uint64_t dist, uint64_t &var_counter)
{
	uint64_t a,b,c;
	uint64_t A;
	uint64_t B;
	uint64_t ta, tb, tc, td, te;

	// uint64_t skips[] = {2,3,9,10,16};
	// uint64_t flips[] = {0,4};

	bool skip_check = false;
	bool flip_check = false;


	for(uint64_t i=0;i<N;i++)
	{
		skip_check = false;
		flip_check = false;

		if(dist == 1)
		{
			if((k + 0)%N == i)
			{
				flip_check = true;
			}	

		}else if(dist == 2)
		{

			if((k + 0)%N == i ||(k + 5)%N == i)
			{
				skip_check = true;
			}
	
			if((k + 1)%N == i)
			{
				flip_check = true;
			}	

		}else if(dist == 3)
		{

			if(
				(k + 0)%N == i ||
				(k + 1)%N == i ||
				(k + 5)%N == i ||
				(k + 6)%N == i ||
				(k + 10)%N == i)
			{
				skip_check = true;
			}
	
			if((k + 2)%N == i)
			{
				flip_check = true;
			}	

		}else if(dist == 4)
		{

			if(
				(k + 0)%N == i ||
				(k + 1)%N == i ||
				(k + 2)%N == i ||
				(k + 5)%N == i ||
				(k + 6)%N == i ||
				(k + 7)%N == i ||
				(k + 10)%N == i ||
				(k + 11)%N == i ||
				(k + 15)%N == i)
			{
				skip_check = true;
			}
	
			if((k + 3)%N == i)
			{
				flip_check = true;
			}	
		}else if(dist == 5)
		{

			if(
				(k + 0)%N == i ||
				(k + 1)%N == i ||
				(k + 2)%N == i ||
				(k + 3)%N == i ||
				(k + 5)%N == i ||
				(k + 6)%N == i ||
				(k + 7)%N == i ||
				(k + 8)%N == i ||
				(k + 10)%N == i ||
				(k + 11)%N == i ||
				(k + 12)%N == i ||
				(k + 15)%N == i ||
				(k + 16)%N == i ||
				(k + 20)%N == i)
			{
				skip_check = true;
			}
	
			if((k + 4)%N == i)
			{
				flip_check = true;
			}	
		}else if(dist == 6)
		{
			if(
				(k + 0)%N == i ||
				(k + 1)%N == i ||
				(k + 2)%N == i ||
				(k + 3)%N == i ||
				(k + 4)%N == i ||
				(k + 5)%N == i ||
				(k + 6)%N == i ||
				(k + 7)%N == i ||
				(k + 8)%N == i ||
				(k + 9)%N == i ||
				(k + 10)%N == i ||
				(k + 11)%N == i ||
				(k + 12)%N == i ||
				(k + 13)%N == i ||
				(k + 15)%N == i ||
				(k + 16)%N == i ||
				(k + 17)%N == i ||
				(k + 20)%N == i ||
				(k + 21)%N == i ||
				(k + 25)%N == i)
			{
				skip_check = true;
			}	
		}else if(dist == 7)
		{
			if(
				(k + 0)%N == i ||
				(k + 1)%N == i ||
				(k + 2)%N == i ||
				(k + 3)%N == i ||
				(k + 4)%N == i ||
				(k + 5)%N == i ||
				(k + 6)%N == i ||
				(k + 7)%N == i ||
				(k + 8)%N == i ||
				(k + 9)%N == i ||
				(k + 10)%N == i ||
				(k + 11)%N == i ||
				(k + 12)%N == i ||
				(k + 13)%N == i ||
				(k + 14)%N == i ||
				(k + 15)%N == i ||
				(k + 16)%N == i ||
				(k + 17)%N == i ||
				(k + 18)%N == i ||
				(k + 20)%N == i ||
				(k + 21)%N == i ||
				(k + 22)%N == i ||
				(k + 25)%N == i ||
				(k + 26)%N == i ||
				(k + 30)%N == i)
			{
				skip_check = true;
			}	
		}

		if(skip_check) continue;

		A = ((i+N-0)%N);
		B = ((i+N-5)%N);

		set_sat(solver, var_counter, l2 & (0x1ull<< ((i+N-0)%N)) ? true : false);
		a = var_counter;
		var_counter++;

		set_sat(solver, var_counter, l2 & (0x1ull<< ((i+N-5)%N)) ? true : false);
		b = var_counter;
		var_counter++;

		set_sat(solver, var_counter, l2 & (0x1ull<< ((i+N-1)%N)) ? true : false);
		c = var_counter;
		var_counter++;

		xor_sat(solver, A, a, var_counter);
		ta = var_counter;
		var_counter++;

		xor_sat(solver, B, b, var_counter);
		tb = var_counter;
		var_counter++;

		and_sat(solver, A, B, var_counter);
		tc = var_counter;
		var_counter++;

		and_sat(solver, ta, tb, var_counter);
		td = var_counter;
		var_counter++;

		xor_sat(solver, tc, td, var_counter);
		te = var_counter;
		var_counter++;

		xor_sat(solver, te, c, var_counter);

		if(flip_check)
		{
			set_sat(solver, var_counter, l1 & (0x1ull<< i) ? false : true);
		}else
		{
			set_sat(solver, var_counter, l1 & (0x1ull<< i) ? true : false);
		}

		var_counter++;
	}
}

uint64_t fault_number[M];
uint64_t unique_fault_number[M];


vector<uint64_t>faulty_x;
vector<uint64_t>faulty_y;
vector<uint64_t>faulty_pos;
std::set<uint64_t>ff;

// Mounts the Attack on a Single Round
int dfa_attack(uint64_t a, uint64_t b, bool found[N+1][M+2], uint64_t L_reg[M+2])
{
	uint64_t x,y,xf,yf,lr1x,l0,l1,l2;
	
	x = a; y = b;
	encrypt(x,y);

	bool unique_solution = false;

	uint64_t T = 0;
	uint64_t Dist = 0;

	for(uint64_t i=0;i<M+2;i++)
	{
		if(found[N][i]) T++;
		else break;
	}

	// std::cout<<std::endl<<T<<std::endl;
	uint64_t number_of_faults_counter = 0;
	uint64_t number_unique_of_faults_counter = 0;


	uint64_t p;

	Dist = ROUNDS - FAULT_ROUND - T + 1;

	if(T < M+2)
    while(!unique_solution)
	{

		// Check if currect number of faults give a unique solution
		if(faulty_pos.size())
		{			
			// Setup SAT SOLVER

			uint64_t var_counter = N;

			SATSolver solver;
			if(DEBUG) solver.log_to_file("logger.txt");
		    solver.set_num_threads(6);

			for(uint64_t i=0;i<faulty_pos.size();i++)
			{
				l1 = x ^ faulty_x[i];
				l2 = y ^ faulty_y[i];

				for(uint64_t l=0;l<=T-2;l++)
				{
					l0 = l1;
					l1 = l2;
					l2 = l0 ^ F(L_reg[l+1]) ^ F(L_reg[l+1] ^ l1);
				}

				// l0 = x ^ faulty_x[i];
				// l1 = y ^ faulty_y[i];			
				// l2 = l0 ^ F(y) ^ F(y ^ l1);

				equations(solver,l1,l2,faulty_pos[i],Dist,var_counter);
			}

			solver.new_vars(var_counter);

			lbool ret = solver.solve();

			if (ret != l_True) {
			    std::cout<< "**Fatal Error!! No Solution Found for the sat solver**\n";
			    break;
			}

			vector<Lit> ban_solution;
			for (uint32_t var = 0; var < 2 * N; var++) {
			    if (solver.get_model()[var] != l_Undef) {
			        ban_solution.push_back(
			            Lit(var, (solver.get_model()[var] == l_True)? true : false));
			    }
			}

			solver.add_clause(ban_solution);
			ret = solver.solve();

			if (ret != l_True) {
				if(DEBUG)
			    std::cout<< "Unique Solution Found!!\n";
			    unique_solution = true;
			}
		}


		if(faulty_pos.size() > N*0.9)
		{
			break;
		}

		if(!unique_solution)
		{
			p = uni_dist(rng) % (N);
			number_of_faults_counter++;
			number_unique_of_faults_counter++;
			while(ff.find(p) != ff.end())
			{
				number_of_faults_counter++;
				p = uni_dist(rng) % (N);
			}
			ff.insert(p);

			xf = a;yf = b;
			faulty_encrypt(xf, yf, ROUNDS, FAULT_ROUND, p+1);

			if(DEBUG)
			{
				printf("Fault Number %lu  ", faulty_pos.size() +1);
				printf("Faulty Encrypted : %lx %lx , Fault : %ld\n", xf, yf, p+1);		
			}

			l0 = x ^ xf;
			l1 = y ^ yf;
			l2 = x ^ xf ^ F(yf) ^ F(y);

			// for(uint64_t l=0;l<=T-2;l++)
			// {
			// 	l0 = l1;
			// 	l1 = l2;
			// 	l2 = l0 ^ F(L_reg[l+1]) ^ F(L_reg[l+1] ^ l1);
			// }

			uint64_t k = find_fault_location(l0,l1,l2);
			k--;
			if (k != p)
			{
				if(DEBUG)
				printf("Attack Failed, poor fault location_find detection\n");
				return 0;
			}

			// printf("XOR :%s \n\n", binary(l1));
			faulty_x.push_back(xf);
			faulty_y.push_back(yf);
			faulty_pos.push_back(k);
		}


	}

	if(!unique_solution)
	{
		// printf("Error!! Something Wrong\n");
		return 0;
	}

	uint64_t var_counter = N;

	SATSolver solver;
	if(DEBUG) solver.log_to_file("logger.txt");
    solver.set_num_threads(6);

	for(uint64_t i=0;i<faulty_pos.size();i++)
	{

		l1 = x ^ faulty_x[i];
		l2 = y ^ faulty_y[i];

		for(uint64_t l=0;l<=T-2;l++)
		{
			l0 = l1;
			l1 = l2;
			l2 = l0 ^ F(L_reg[l+1]) ^ F(L_reg[l+1] ^ l1);
		}

		equations(solver,l1,l2,faulty_pos[i],Dist,var_counter);
	}

	solver.new_vars(var_counter);
	solver.solve();

	// printf("Total Fault Number %lu  \n", attack_pos.size() +1);

    // std::cout<< "Solution is: ";
    // for (uint32_t var = 0; var < N; var++) {
    //     std::cout<<solver.get_model()[var]<<','; 
    //     }
    //     std::cout<<std::endl;

    for (uint32_t var = 0; var < N; var++) 
    {
        if (solver.get_model()[var] != l_Undef) 
        {
        	found[var][T] = true;
            if(solver.get_model()[var] == l_True)
            {
            	L_reg[T] |= (0x1ull<<var);
            }
        }
    }

	fault_number[T-2] = number_of_faults_counter;
	unique_fault_number[T-2] = number_unique_of_faults_counter;

	return 1;
}

// Handles the complete attack
int complete_dfa()
{
	faulty_y.clear();
	faulty_x.clear();
	faulty_pos.clear();
	ff.clear();
	for(int i=0;i<M;i++)fault_number[i] = 0;

	if(DEBUG)
	printf("\n****Starting Attack****\n");

	uint64_t x,y,a,b;

	a = uni_dist(rng) & WORD_MASK;
	b = uni_dist(rng) & WORD_MASK;
	setup_random_key();

	uint64_t answer[M+2];

	for(uint64_t i=0;i<=M+1;i++)
	{
		x = a;
		y = b;
		encrypt(x,y,ROUNDS-i);
		answer[i] = x;
	}

	x = a;
	y = b;
	encrypt(x,y);

	if(DEBUG)
	{

		printf("Plain Text : %lx %lx \n", a, b);
		printf("%s, %s \n\n", binary(a), binary(b));
		printf("Encrypted Text : %lx %lx \n", x, y);
		printf("%s, %s \n\n", binary(x), binary(y));
		for(uint64_t i=0;i<=M+1;i++)
		{	
			printf("Answer (L registers from the last round - %ld):: %s \n",i, binary(answer[i]));
		}
		printf("\n\n");
	}
	
	bool found[N+1][M+2] = {0}; // Nth bit of Mth round register is found
	uint64_t L_reg[M+2] = {false};

	L_reg[0] = answer[0];
	L_reg[1] = answer[1];

	for(uint64_t i=0;i<N+1;i++)
	{
		for(uint64_t j=0;j<M+2;j++)
		{
			found[i][j] = false;
			if(j<2) found[i][j] = true;
		}
	}

	while(!found[N][M+1])
	{
		// This is the attack function
		// Checks the Last register which hasn't been found till now
		// And mounts a attack to find that complete register
		int check = dfa_attack(a, b, found, L_reg);

		if(check == 0)
		{
			return 0;
		}
		// Check whether whole registers have been found
		// Sets the Nth Valse of found matric to True
		for(uint64_t j=0;j<=M+1;j++)
		{
			if(!found[N][j])
			{		
				uint64_t temp = true;
				for(uint64_t i=0;i<N;i++)
				{
					temp &= found[i][j];
				}	
				if(temp) found[N][j] = true;
			}
			if(!found[N][j])
			{
				break;
			}
		}

		if(DEBUG)
		for(uint64_t i=0;i<M+2;i++)
		{
			if(found[N][i])
				printf("Found");
			else
				printf("Not Found\n");
			printf("  Data (L registers from the last round - %ld):: %s \n",i, binary(L_reg[i]));
		}

		// break;
	}

	return 1;
}



int main() {

	rng.seed(time(NULL)); // seed marsenne twister rng

	if(DEBUG)
	{

		printf("%llx\n",WORD_MASK);

		// printf("%llx\n", 0x1ull);

		// uint64_t hi;

		// printf("\nllo\n");

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
	std::cout<<"Fault Round: T - "<<ROUNDS - FAULT_ROUND + 1<<std::endl;


	fault_location_find_setup();

	// fault_location_find_test();

	double avg_sum = 0;
	double unique_avg_sum = 0;

	uint64_t iters = 4e2;
	// iters = 10;


	uint64_t failed_attacks = 0;
	uint64_t check = 0;

	for(uint64_t i=0;i<iters;i++)
	{
		check = 1;

		for(uint64_t j=0;j<M;j++)
		{
			fault_number[j] = 0;
		}

		auto start = std::chrono::steady_clock::now();

		check = complete_dfa();

		if(check == 0)
		{
			failed_attacks++;
			// std::cout<<"FAILED"<<std::endl;
			continue;
		}
		
		auto end = std::chrono::steady_clock::now();

		// std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()<<"ms ";

		double sum = 0, unique_sum = 0;

		for(uint64_t j=0;j<M;j++)
		{
			// std::cout<<fault_number[j]<<' ';
			sum += fault_number[j];
			unique_sum += unique_fault_number[j];

		}
		// std::cout<<sum<<std::endl;

		if(i%100==0)
		std::cout<<i<<std::endl;

		avg_sum += sum;
		unique_avg_sum += unique_sum;
		
		if(DEBUG) break;
		// break;
	}

	if(iters == failed_attacks)
	{
		std::cout<<"All Attacks Failed -> "<<(double)failed_attacks / (double)iters<<std::endl;

	}else
	{
		std::cout<<"Average Faults "<<avg_sum / (iters - failed_attacks) <<std::endl;
		std::cout<<"Average Unique Faults "<<unique_avg_sum / (iters - failed_attacks) <<std::endl;
		std::cout<<"Failed Attacks "<<(double)failed_attacks / (double)iters<<std::endl;
	}
	// check_hamming_relation();

	return 0;
}