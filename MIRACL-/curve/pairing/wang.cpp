/*
	Wang interactive ID based key exchange
	uses type 1 pairing
	See http://eprint.iacr.org/2005/108

	Compile with modules as specified below
	
	For MR_PAIRING_SS2 curves
	cl /O2 /GX wang.cpp ss2_pair.cpp ec2.cpp gf2m4x.cpp gf2m.cpp big.cpp miracl.lib
  
	For MR_PAIRING_SSP curves
	cl /O2 /GX wang.cpp ssp_pair.cpp ecn.cpp zzn2.cpp zzn.cpp big.cpp miracl.lib

	Very Simple Test program 
*/

#include <iostream>
#include <ctime>
#include <time.h>
//#include<windows.h>
 

//********* choose just one of these **********
///#define MR_PAIRING_SS2    // AES-80 or AES-128 security GF(2^m) curve
//#define AES_SECURITY 80   // OR
//#define AES_SECURITY 128

#define MR_PAIRING_SSP    // AES-80 or AES-128 security GF(p) curve
#define AES_SECURITY 80   // OR
//#define AES_SECURITY 128
//*********************************************

#include "pairing_1.h"


// Here we ignore the mysterious h co-factor which appears in the paper..

int main()
{   
	PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve
	Big order=pfc.order();
	miracl* mip=get_mip();

	Big s1,s2,xA,r,A,B,M,h,c,k;
	G1 P,Ppub1,Ppub2,QA,DA,PKA,QB,SB,V,K,Q1,Q2,W;
	GT T,R1,R2,H1,H2,H3;
	time_t seed;
	clock_t  start,finish;
	int len1;//len2;
	double time1;
	time(&seed);
    irand((long)seed);
	
// setup
	//cout<<"setuo phase"<<endl;
    start = clock();
	//start=GetTickCount();
	pfc.random(P);
	pfc.precomp_for_mult(P);
	pfc.random(s1);
	pfc.random(s2);
	Ppub1=pfc.mult(P,s1);
	Ppub2=pfc.mult(P,s2);
	finish = clock();
    time1 = (finish - start) / (double)CLOCKS_PER_SEC;
	//finish=GetTickCount();
	//finish= finish-start;
    cout<<"the time of setup phase ="<< time1<<"s"<<endl;
	//mip->IOBASE=10;
	cout<<"P="<<P.g<<endl;
	cout<<"s1="<<s1<<endl;
	cout<<"s2="<<s2<<endl;
	cout<<"Ppub1="<<Ppub1.g<<endl;
	cout<<"Ppub2="<<Ppub2.g<<endl;



// 生成无证书环境秘钥
	//cout<<"生成无证书环境秘钥"<<endl;
	start = clock();
	pfc.hash_and_map(QA,(char *)"Alice");
	DA=pfc.mult(QA,s1);
	pfc.precomp_for_mult(DA);
	pfc.random(xA);
	PKA=pfc.mult(P,xA);
	finish = clock();
    time1 = (finish - start) / (double)CLOCKS_PER_SEC;
    cout<<"生成无证书环境秘钥所用时间 ="<< time1<<"s"<<endl;
	cout<<"DA="<<DA.g<<endl;
	cout<<"xA="<<xA<<endl;
	cout<<"PKA="<<PKA.g<<endl;


// 生成基于身份环境的密钥
	//cout<<"生成基于身份环境秘钥"<<endl;
    start = clock();
    pfc.hash_and_map(QB,(char *)"Bob");
	SB=pfc.mult(QB,s2);
	pfc.precomp_for_mult(SB);
	finish = clock();
    time1 = (finish - start) / (double)CLOCKS_PER_SEC;
    cout<<"生成基于身份环境秘钥所用时间 ="<< time1<<"s"<<endl;
	cout<<"SB="<<SB.g<<endl;


//签密
	//cout<<"签密"<<endl;
    start = clock();
	mip->IOBASE=256;
	M=(char *)"test message"; // to be signcrypted from Alice to Bob
	//mip->IOBASE=16;
	cout << "Signed Message=   " << M << endl;
	//A=(char *)"Alice";
	B=(char *)"Bob";
	A=(char *)"Alice";
	mip->IOBASE=16;
	pfc.random(r);
	V=pfc.mult(P,r);
	T=pfc.pairing(Ppub2,QB);
	T=pfc.power(T,r);
	pfc.start_hash();
	pfc.add_to_hash(V);
	pfc.add_to_hash(T);
	pfc.add_to_hash(B);
	h=pfc.finish_hash_to_group();
	c=lxor(M,h);
	//mip->IOBASE=10;
	cout<<"the cipher is="<<c<<endl;
	pfc.start_hash();
	pfc.add_to_hash(V);
	pfc.add_to_hash(c);
	pfc.add_to_hash(A);
	pfc.add_to_hash(PKA);
	k=pfc.finish_hash_to_group();
	pfc.big_and_map(K,k);
	//pfc.hash_and_map1(K,k);
	//pfc.random(K);
	Q1=pfc.mult(K,r);
	Q2=pfc.mult(K,xA);
	W=DA+Q1+Q2;
	finish = clock();
    time1 = (finish - start) / (double)CLOCKS_PER_SEC;
    cout<<"the time of signcryption ="<< time1<<"s"<<endl;
	cout<<"V="<<V.g<<endl;
	cout<<"c="<<c<<endl;
	cout<<"W="<<W.g<<endl;

	//len1=length(W);
	//cout<<"len1="<<len1<<endl;
	//mip->IOBASE=2;
	// len1=length(c);
	len1=c.len();
//	len1=V.length;
	//pfc.precomp_for_mult(V);
	//len2=V.spill(bytes);
	cout<<"bytes of the cipher="<<4*len1+128+128<<endl;
	//cout<<"len2="<<len2<<endl;
// 解签密
    start = clock();
	R1=pfc.pairing(W,P);
	H1=pfc.pairing(Ppub1,QA);
	pfc.start_hash();
	pfc.add_to_hash(V);
	pfc.add_to_hash(c);
	pfc.add_to_hash(A);
	pfc.add_to_hash(PKA);
	k=pfc.finish_hash_to_group();
	//big_to_bytes(20,k,ptr,justify);
	pfc.big_and_map(K,k);
	//pfc.random(K);
	Q1=pfc.mult(K,r);
	Q2=pfc.mult(K,xA);
	H2=pfc.pairing(K,V);//V没有问题
	H3=pfc.pairing(K,PKA);
	R2=H1*H2*H3;
    if(R1==R2)
	{
		cout << "Message is OK" << endl;
	    T=pfc.pairing(V,SB);//由V求的T与签密时求的T不一样
	    pfc.start_hash();
	    pfc.add_to_hash(V);
	    pfc.add_to_hash(T);
	    pfc.add_to_hash(B);
	    h=pfc.finish_hash_to_group();
	    M=lxor(c,h);
	    mip->IOBASE=256;
        cout << "Verified Message= " << M << endl;
	}
	else
		cout << "Message is bad    " << c << endl;
     finish = clock();
     time1 = (finish - start) / (double)CLOCKS_PER_SEC;
	 cout<<"the time of signcryption ="<< time1<<"s"<<endl;
    return 0;
}
