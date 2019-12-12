#include <cryptominisat5/cryptominisat.h>
#include <assert.h>
#include <vector>
using std::vector;
using namespace CMSat;
// g++ sat-test.cpp -lcryptominisat5 -std=c++11

void and_sat(SATSolver &solver, int A, bool a, int B, bool b, int C, bool c)
{
    vector<Lit> clause;

    clause.push_back(Lit(A,a));
    clause.push_back(Lit(C,!c));
    solver.add_clause(clause);
    clause.clear();

    clause.push_back(Lit(B,b));
    clause.push_back(Lit(C,!c));
    solver.add_clause(clause);
    clause.clear();

    clause.push_back(Lit(A,!a));
    clause.push_back(Lit(B,!b));
    clause.push_back(Lit(C,c));
    solver.add_clause(clause);
}

void xor_sat(SATSolver &solver, int A, bool a, int B, bool b, int C, bool c)
{

    vector<unsigned> xclause;
    xclause.push_back(A);
    xclause.push_back(B);
    xclause.push_back(C);

    bool rhs = false;

    if(a) rhs = !rhs;
    if(b) rhs = !rhs;
    if(c) rhs = !rhs;

    solver.add_xor_clause(xclause, rhs);
}

int main()
{
    SATSolver solver;
    vector<Lit> clause;

    //Let's use 4 threads
    solver.set_num_threads(4);

    //We need 3 variables

    //add "1 0"
    clause.push_back(Lit(0, false));
    solver.add_clause(clause);

    //add "-2 0"
    clause.clear();
    clause.push_back(Lit(1, false));
    // solver.add_clause(clause);



    xor_sat(solver, 0, false, 1, false, 2, false);
    xor_sat(solver, 1, false, 2, false, 3, false);
    xor_sat(solver, 2, false, 3, false, 4, true);

    solver.new_vars(5);

    std::cout<<solver.solve(&clause);
    
    //add "-1 2 3 0"
    clause.clear();
    clause.push_back(Lit(0, true));
    clause.push_back(Lit(1, false));
    clause.push_back(Lit(2, false));
    solver.add_clause(clause);

    // lbool ret = solver.solve();
    // assert(ret == l_True);
    // std::cout
    // << "Solution is: "
    // << solver.get_model()[0]
    // << ", " << solver.get_model()[1]
    // << ", " << solver.get_model()[2]
    // << std::endl;

    // //assumes 3 = FALSE, no solutions left
    // vector<Lit> assumptions;
    // assumptions.push_back(Lit(2, true));
    // ret = solver.solve(&assumptions);
    // assert(ret == l_False);

    // //without assumptions we still have a solution
    // ret = solver.solve();
    // assert(ret == l_True);

    // //add "-3 0"
    // //No solutions left, UNSATISFIABLE returned
    // clause.clear();
    // clause.push_back(Lit(2, true));
    // solver.add_clause(clause);
    // ret = solver.solve();
    // assert(ret == l_False);


    while(true) {
        lbool ret = solver.solve();
        if (ret != l_True) {
            assert(ret == l_False);
            //All solutions found.
            exit(0);
        }

        //Use solution here. print it, for example.
        std::cout<< "Solution is: ";
        for (uint32_t var = 0; var < solver.nVars(); var++) {
            std::cout<<solver.get_model()[var]<<','; 
            }
            std::cout<<std::endl;
        


        //Banning found solution
        vector<Lit> ban_solution;
        for (uint32_t var = 0; var < solver.nVars(); var++) {
            if (solver.get_model()[var] != l_Undef) {
                ban_solution.push_back(
                    Lit(var, (solver.get_model()[var] == l_True)? true : false));
            }
        }    // //add "-2 0"
    // clause.clear();
    // clause.push_back(Lit(1, true));
    // solver.add_clause(clause);
        solver.add_clause(ban_solution);
    }

    return 0;
}
