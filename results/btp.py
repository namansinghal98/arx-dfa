import csv

N = 16
ROUNDS = 9
FILE_EXP_VAL = "results_exp_val_" + str(N) + ".txt"
FILE_ER = "results_er_" + str(N) + ".txt"

def exp1(a1, a2):
    b = (a1 + a2 - a1*a2)/2
    return b


def exp2(a1, a2):
    b = (a1 + a2 - 2*a1*a2)
    return b


if __name__ == "__main__":

    exp_val = list()
    z = list()

    for r in range(ROUNDS):
        exp_val.append([])
        z.append([])
        for n in range(N):
            exp_val[r].append(0)
            z[r].append(0)

    exp_val[1][0] = 1

    for r in range(2, ROUNDS):
        for n in range(N):
            a = exp_val[r-1][(n - 1) % N]
            b = exp_val[r-1][(n - 2) % N]
            c = exp_val[r-1][(n - 8) % N]
            d = exp_val[r-2][n % N]
            e = exp1(a, c)
            f = exp2(b, d)
            g = exp2(e, f)
            exp_val[r][n] = g

    for r in range(1, ROUNDS):
        for n in range(N):
            a = exp_val[r][n % N]
            b = exp_val[r-1][(n - 2) % N]
            d = exp_val[r-2][n % N]
            e = 0
            if d == 0:
                e = exp2(a, b)
            if d == 1:
                e = exp2(a, b)
                e = 1 - e
            z[r][n] = 2 * e

    for r in range(0, ROUNDS):
        print(exp_val[r])

    with open(FILE_EXP_VAL, 'w') as file:
        writer = csv.writer(file)
        writer.writerows(exp_val)

    # for r in range(0, ROUNDS):
    #     print(z[r])

    for r in range(0, ROUNDS):
        print(r, sum(z[r]))

    with open(FILE_ER, 'w') as file:
        for r in range(0, ROUNDS):
            file.write(str(sum(z[r])) + '\n')