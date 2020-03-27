#include <bits/stdc++.h>
using namespace std;


#define fre freopen("in.txt","r",stdin); freopen("out.txt","w",stdout);
#define traca(a) cout<<a<<"#"<<endl;
#define tracb(a,b) cout<<a<<"$"<<b<<"$"<<endl;
#define tracc(a,b,c) cout<<a<<"*"<<b<<"*"<<c<<"*"<<endl;
#define tracd(a,b,c,d) cout<<a<<"&"<<b<<"&"<<c<<"&"<<d<<"&"<<endl;
#define oline cout<<endl;

#define sync ios_base::sync_with_stdio(0); cin.tie(0); cout.tie(0)

typedef long int int32;
typedef unsigned long int uint32;
typedef long long int int64;
typedef unsigned long long int  uint64;
typedef long double ldb;

const int MOD = 1e9+7;
const int INF = 1011111111;
const int64 LLINF = 1000111000111000111LL;
const ldb EPS = 1e-10;
const ldb PI = 3.14159265358979323;


int main()
{
	sync;
	fre;


	double n,m,r;
	double t1,t2,t3;
	

	int64 arr[5] = {16,24,32,48,64};
	for(int i=0;i<5;i++)
	{
		n = arr[i];
		cout<<n<<endl;
		for(int j=0;j<n*3;j++)
		{
			m = (n-1) / n ;
			r = pow(m,j+1);
			r = 1 - r;
			r = n * r;
			cout<<j+1<<' '<<r<<endl;
		}
	}

	return 0;
}