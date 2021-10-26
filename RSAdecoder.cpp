//RSAdecoder
#include <bits/stdc++.h>
#include <boost/multiprecision/cpp_int.hpp>
#define _GLIBCXX_DEBUG
#define iint mp::cpp_int
using namespace std;
namespace mp = boost::multiprecision;
int main(){
  iint n,d,k;
  string t;
  cin>>n>>d;
  k=msb(n);
  cout<<"please follow the format:n d ciphertext"<<endl;
  cin>>t;
  iint pb,pp,dig,bitset,tmp;
  iint input=0;
  pb=mp::pow((iint)2,(unsigned)(iint)6);
  iint er=0;
  for(int i=0;i<t.size();i++){
    if((int)(t[i]-'0')>=0){
      input=input*pb+(iint)(int)(t[i]-'0');
    }else{
      er++;
    }
  }
  dig=6*(t.size()-er);
  input=input>>(unsigned)(dig%(k+1));
  dig=(dig/(k+1))*(k+1);
  bitset=0;
  pb=mp::pow((iint)2,(unsigned)k);
  for(int i=0;i<dig/(k+1);i++){
    pp=mp::pow((iint)2,(unsigned)(dig-(i+1)*(k+1)));
    tmp=input/pp;
    tmp=mp::powm(tmp,d,n);
    bitset=bitset*pb+tmp;
    input%=pp;
  }
  dig=dig/(k+1)*k;
  bitset=bitset>>(unsigned)(dig%8);
  dig=(dig/8)*8;
  for(int i=0;i<dig/8;i++){
    pp=mp::pow((iint)2,(unsigned)(dig-(i+1)*8));
    tmp=bitset/pp;
    cout<<(char)(short)tmp;
    bitset%=pp;
  }
  cout<<endl;
}



