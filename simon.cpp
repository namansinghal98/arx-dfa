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

using CMSat::Lit;
using CMSat::lbool;
using CMSat::SATSolver;
using std::vector;
using std::pair;


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

///////////////////////////////////////
////////////// SAT SETUP //////////////
///////////////////////////////////////

#include "sat_functions.h"

// Add Equations given the Fault is in Round R given the xor of L register of round R+1 or R redister of R+2
void equations_2nd_round(SATSolver &solver,uint64_t lxor,uint64_t k,uint64_t &var_counter, std::map<uint64_t,uint64_t>&vars)
{
	uint64_t c,d;
	uint64_t A = ((k-7+N)%N);
	uint64_t B = ((k+7+N)%N);

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

	set_sat(solver, c, lxor & (0x1ull<< ((k+1)%N))? true : false );
	set_sat(solver, d, lxor & (0x1ull<< ((k+8)%N))? true : false );

}

// Add Equations given the Fault is in Round R given the xor of L register of round R+2 or R redister of R+3
void equations_3rd_round(SATSolver &solver,uint64_t lxor, uint64_t k, uint64_t &var_counter, std::map<uint64_t,uint64_t>&vars)
{
	uint64_t c,d;
	uint64_t A = ((k-7+N)%N);
	uint64_t B = ((k+7+N)%N);

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

	and_sat(solver, ((k-6+N)%N), c, var_counter);
	set_sat(solver, var_counter, lxor & (0x1ull<< ((k+2)%N))? true : false );
	var_counter++;

	if((k+16)%N != k)
	{		
		and_sat(solver, ((k+15)%N), d, var_counter);
		set_sat(solver, var_counter, lxor & (0x1ull<< ((k+16)%N))? true : false );
	}else
	{
		and_sat(solver, ((k+15)%N), d, var_counter);
		set_sat(solver, var_counter, lxor & (0x1ull<< ((k+16)%N))? false : true );
	}
	var_counter++;

	xor_sat(solver, ((k-5+N)%N), c, var_counter);
	set_sat(solver, var_counter, lxor & (0x1ull<< ((k+3)%N))? true : false);
	var_counter++;

	xor_sat(solver, ((k+9+N)%N), d, var_counter);
	set_sat(solver, var_counter, lxor & (0x1ull<< ((k+10)%N))? true : false);
	var_counter++;

	xor_sat(solver, ((k+1)%N), c, var_counter);
	uint64_t ta = var_counter;
	var_counter++;

	xor_sat(solver, ((k+8)%N), d, var_counter);
	uint64_t tb = var_counter;
	var_counter++;

	and_sat(solver, ((k+1)%N), ((k+8)%N), var_counter);
	uint64_t tc = var_counter;
	var_counter++;

	and_sat(solver, ta, tb, var_counter);
	uint64_t td = var_counter;
	var_counter++;

	xor_sat(solver, tc, td, var_counter);
	set_sat(solver, var_counter, lxor & (0x1ull<< ((k+9)%N)) ? true : false);
	var_counter++;
}

uint64_t fault_number[M];

// Mounts the Attack on a Single Round
void dfa_attack(uint64_t a, uint64_t b, bool found[N+1][M+2], uint64_t L_reg[M+2])
{
	uint64_t x,y,xf,yf,lr1x,l0,l1,l2;
	
	x = a; y = b;
	encrypt(x,y);

	std::set<uint64_t>ff;
	bool unique_solution = false;

	vector<uint64_t>attack_L1;
	vector<uint64_t>attack_L2;
	vector<uint64_t>attack_pos;

	uint64_t T = 0;

	for(uint64_t i=0;i<M+2;i++)
	{
		if(found[N][i]) T++;
		else break;
	}

	// std::cout<<std::endl<<T<<std::endl;
	
	uint64_t p;

	if(T < M+2)
    while(!unique_solution)
	{
		p = uni_dist(rng) % (N);
		while(ff.find(p) != ff.end())
		{
			p = uni_dist(rng) % (N);
		}
		ff.insert(p);

		xf = a;yf = b;
		faulty_encrypt(xf, yf, ROUNDS, ROUNDS-T, p+1);

		printf("Fault Number %lu  ", attack_pos.size() +1);
		printf("Faulty Encrypted : %lx %lx , Fault : %ld\n", xf, yf, p+1);
		
		l1 = x ^ xf;
		l2 = y ^ yf;

		for(uint64_t l=0;l<=T-2;l++)
		{
			l0 = l1;
			l1 = l2;
			l2 = l0 ^ F(L_reg[l+1]) ^ F(L_reg[l+1] ^ l1);
		}

		uint64_t k = find_fault_location(l0,l1);
		k--;
		if (k != p)
		{
			printf("Attack Failed, poor fault location_find detection\n");
		}

		// printf("XOR :%s \n\n", binary(l1));
		attack_L1.push_back(l1);
		attack_L2.push_back(l2);
		attack_pos.push_back(k);


		// Setup SAT SOLVER

		uint64_t var_counter = N+1;
		std::map<uint64_t,uint64_t>vars_map;

		SATSolver solver;
		solver.log_to_file("logger.txt");
	    solver.set_num_threads(6);

		for(uint64_t l=0;l<N;l++)
			if(found[l][T])
				set_sat(solver, l, L_reg[T] & (0x1ull<<l) ? true : false );

		for(uint64_t i=0;i<attack_pos.size();i++)
		{
			equations_2nd_round(solver, attack_L2[i], attack_pos[i], var_counter, vars_map);
			equations_3rd_round(solver, attack_L1[i], attack_pos[i], var_counter, vars_map);
		}

		solver.new_vars(var_counter);

		lbool ret = solver.solve();

		if (ret != l_True) {
		    std::cout<< "**Fatal Error!! No Solution Found for the sat solver**\n";
		    break;
		}

		vector<Lit> ban_solution;
		for (uint32_t var = 0; var < N; var++) {
		    if (solver.get_model()[var] != l_Undef) {
		        ban_solution.push_back(
		            Lit(var, (solver.get_model()[var] == l_True)? true : false));
		    }
		}

		solver.add_clause(ban_solution);
		ret = solver.solve();

		if (ret != l_True) {
		    std::cout<< "Unique Solution Found!!\n";
		    unique_solution = true;
		}
	}

	if(!unique_solution)
	{
		printf("Error!! Something Wrong\n");
		exit(0);
	}

	uint64_t var_counter = N+1;
	std::map<uint64_t,uint64_t>vars_map;

	SATSolver solver;
	solver.log_to_file("logger.txt");
    solver.set_num_threads(6);

	for(uint64_t l=0;l<N;l++)
		if(found[l][T])
			set_sat(solver, l, L_reg[T] & (0x1ull<<l) ? true : false );

	for(uint64_t i=0;i<attack_pos.size();i++)
	{
		equations_2nd_round(solver, attack_L2[i], attack_pos[i], var_counter, vars_map);
		equations_3rd_round(solver, attack_L1[i], attack_pos[i], var_counter, vars_map);
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

	// printf("Mappings:\n");
	// for(auto a: vars_map)
	// {
	// 	printf("%ld,%ld\n",a.first,a.second);
	// }

    if(T+1<M+2)
	for(auto a: vars_map)
	{
		uint64_t var = a.first;
		uint64_t m = a.second;

        if (solver.get_model()[m] != l_Undef) 
        {
        	found[var][T+1] = true;
            if(solver.get_model()[m] == l_True)
            {
            	L_reg[T+1] |= (0x1ull<<var);
            }
        }
	}

	fault_number[T-2] = attack_pos.size();

	return;
}

// Handles the complete attack
void complete_dfa()
{

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

	printf("Plain Text : %lx %lx \n", a, b);
	printf("%s, %s \n\n", binary(a), binary(b));
	printf("Encrypted Text : %lx %lx \n", x, y);
	printf("%s, %s \n\n", binary(x), binary(y));
	for(uint64_t i=0;i<=M+1;i++)
	{	
		printf("Answer (L registers from the last round - %ld):: %s \n",i, binary(answer[i]));
	}
	printf("\n\n");

	bool found[N+1][M+2] = {0}; // Nth bit of Mth round register is found
	uint64_t L_reg[M+2] = {0};

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
		dfa_attack(a, b, found, L_reg);

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
}


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

		

int main() {

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

	fault_location_find_setup();
	// fault_location_find_test();

	for(uint64_t i=0;i<1e1;i++)
	{
		for(uint64_t j=0;j<M;j++)
		{
			fault_number[j] = 0;
		}
		complete_dfa();

		uint64_t sum = 0;

		for(uint64_t j=0;j<M;j++)
		{
			std::cout<<fault_number[j]<<' ';
			sum += fault_number[j];
		}std::cout<<sum<<std::endl;

		break;
	}

	// check_hamming_relation();

	return 0;
}