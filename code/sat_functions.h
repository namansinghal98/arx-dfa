/*
HEADER FILE: sat_functions.h

Functions:: (Look at the Comments with the Function defination for more information)
set_sat()
and_sat()
xor_sat()

We are not using a completely different namespace to keep thing simple, please avoid using there names
in rest of the program or you will have redefination errors.
*/

#ifndef SAT_FUNCTIONS
#define SAT_FUNCTIONS

#include <cryptominisat5/cryptominisat.h>

using CMSat::Lit;
using CMSat::lbool;
using CMSat::SATSolver;
using std::vector;
using std::pair;

/*
Set a variable in SAT SOLVER
A = a_val
*/
void set_sat(SATSolver &solver, uint64_t A, bool a_val)
{
	vector<Lit> clause;
	clause.push_back(Lit(A,!a_val));
	solver.add_clause(clause);
}

/*
AND STATEMENT in SAT SOLVER
A & B = C
abar, bbar, cbar are to negate A, B, C respectively.
*/
void and_sat(SATSolver &solver, uint64_t A, bool abar, uint64_t B, bool bbar, uint64_t C, bool cbar)
{
	vector<Lit> clause;

	clause.push_back(Lit(A,abar));
	clause.push_back(Lit(C,!cbar));
	solver.add_clause(clause);
	clause.clear();

	clause.push_back(Lit(B,bbar));
	clause.push_back(Lit(C,!cbar));
	solver.add_clause(clause);
	clause.clear();

	clause.push_back(Lit(A,!abar));
	clause.push_back(Lit(B,!bbar));
	clause.push_back(Lit(C,cbar));
	solver.add_clause(clause);
}

void and_sat(SATSolver &solver, uint64_t A, uint64_t B, uint64_t C)
{
	and_sat(solver, A, false, B, false, C, false);
}

/*
XOR STATEMENT in SAT SOLVER
A xor B = C
abar, bbar, cbar are to negate A, B, C respectively.
*/
void xor_sat(SATSolver &solver, uint64_t A, bool abar, uint64_t B, bool bbar, uint64_t C, bool cbar)
{

	vector<unsigned> xclause;
	xclause.push_back(A);
	xclause.push_back(B);
	xclause.push_back(C);

	bool rhs = false;

	if(abar) rhs = !rhs;
	if(bbar) rhs = !rhs;
	if(cbar) rhs = !rhs;

	solver.add_xor_clause(xclause, rhs);
}

void xor_sat(SATSolver &solver, uint64_t A, uint64_t B, uint64_t C)
{
	xor_sat(solver, A, false, B, false, C, false);
}

#endif
