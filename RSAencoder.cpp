//RSAencoder
#include <bits/stdc++.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
#define _GLIBCXX_DEBUG
#define iint mp::cpp_int
using namespace std;
namespace mp = boost::multiprecision;
bool isprime(iint p){
  return miller_rabin_test(p, 1000);
}
iint gcd(iint a,iint b){
  if(b==0){
    return a;
  }else{
    return gcd(b,a%b);
  }
}
bool checkfe(iint f,iint e){
  return (gcd(f,e)==1);
}
pair<iint,iint> solvedio(iint a,iint b){
  a>b;
  if(b==0){
    if(a==1){
      return make_pair((iint)1,(iint)0);
    }else{
      return make_pair(0,0);
    }
  }else{
    iint n=a/b;
    iint d=a%b;
    pair<iint,iint> tmp=solvedio(b,d);
    iint p=tmp.first;
    iint q=tmp.second;
    if(p==0&&q==0){
      return tmp;
    }else{
      return make_pair(q,p-n*q);
    }
  }
}
iint getinv(iint a,iint m){
  pair<iint,iint> ans=solvedio(a,m);
  if(ans.first==0&&ans.second==0){
    return -1;
  }else{
    iint ttmp=ans.first;
    while(ttmp<0){
      ttmp+=m;
    }
    ttmp%=m;
    return ttmp;
  }
}
bool checkedf(iint e,iint d,iint f){
  return (e*d%f==1);
}
int main(){
  iint p,q,e,n,f,k,d;
  string mode;
  cout<<"please follow the format:mode <depend on mode>"<<endl;
  cout<<"mode should be one of:pqene,pqend,nedne,nednd"<<endl;
  cin>>mode;
  if(mode=="pqene"||mode=="pqend"){
    cout<<"please follow the format:"<<mode<<" p q e cleartext"<<endl;
    cin>>p>>q>>e;
    if(msb(p)!=msb(q)){
      cout<<"p and q are not same bits numbers"<<endl;
      return 1;
    }
    if(!isprime(p)||!isprime(q)){
      cout<<"p or q is not prime"<<endl;
      return 1;
    }
    n=p*q;
    f=(p-1)*(q-1);
    if(!checkfe(f,e)){
      cout<<"f(n) and e are not coprimes"<<endl;
      return 1;
    }
    d=getinv(e,f);
    if(d==-1){
      cout<<"e and f(n) are coprimes but e has no inverse"<<endl;
      return 1;
    }
    if(!checkedf(e,d,f)){
      cout<<"ed != f mod f"<<endl;
      return 1;
    }
  }else if(mode=="nedne"||mode=="nednd"){
    cout<<"please follow the format:"<<mode<<" n e d cleartext"<<endl;
    cin>>n>>e>>d;
  }else if(mode=="nene"){
    cout<<"please follow the format:"<<mode<<" n e cleartext"<<endl;
    cin>>n>>e;
  }else{
    cout<<"invalid mode"<<endl;
      return 1;
  }
  k=msb(n);
  string s,t="",u="";
  cin>>s;
  iint tmp;
  iint bitset=0;
  for(int i=0;i<s.size();i++){
    if((long)s[i]<0){
      tmp=(iint)((long)s[i]+256);
    }else{
      tmp=(iint)(long)s[i];
    }
    bitset=bitset*256+tmp;
  }
  iint dig=8*s.size();
  if(dig%k!=0){
    bitset= bitset << (unsigned)(k-dig%k);
    dig+=k-dig%k;
  }
  iint output=0;
  iint pp;
  iint pb=mp::pow((iint)2,(unsigned)k+1);
  for(int i=0;i<dig/k;i++){
    pp=mp::pow((iint)2,(unsigned)(dig-(i+1)*k));
    tmp=bitset/pp;
    tmp=mp::powm(tmp,e,n);
    output=output*pb+tmp;
    bitset%=pp;
  }
  dig=dig/k*(k+1);
  if(dig/6!=0){
    output= output << (unsigned)(6-dig%6);
    dig+=6-dig%6;
  }
  for(int i=0;i<dig/6;i++){
    pp=mp::pow((iint)2,(unsigned)(dig-(i+1)*6));
    tmp=output/pp;
    t.push_back((char)((int)tmp+'0'));
    output%=pp;
  }
  if(mode=="pqene"||mode=="pqend"||mode=="nedne"||mode=="nednd"){
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
      u.push_back((char)(short)tmp);
      bitset%=pp;
    }
    if(s!=u){
      cout<<"plaintext is not equal to cleartext"<<endl;
      return 1;
    }
  }
  if(mode=="pqene"||mode=="nedne"||mode=="nene"){
    cout<<n<<" "<<e<<" "<<t<<endl;
  }else if(mode=="pqend"||mode=="nednd"){
    cout<<n<<" "<<d<<" "<<t<<endl;
  }else{
    cout<<"invalid mode"<<endl;
    return 1;
  }
}
