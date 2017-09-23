/*
Author 			:  	shreyx ( Shreyanshu Agarwal )
Github Profile	: 	https://github.com/shreyx
Disclaimer		:	This code is presented "as is" without any guarantees.
Description		:	This code is an implementation of S-DES encryption using C for Integer input 


@shreyx
*/
#include<stdio.h>

int swap(int data);
int permute(int d,const short * permutator, int n ,int bitsize);
int fk(int data, int key);
int lcs(int val, int no_of_bits ,int bitsize);
int * keygen(int key);
int sdes_encrypt(int data,int key);

int main()
{
    int key;            // 10 bit key ---->  Non-negative Value less than 1024
    int data;           // 8 Bit data ---->  Non-negative Value less than 256
    int cipher;
    printf("Enter 10 bit Key i.e. non-negative integer value less than 1024\n");
    scanf("%d",&key);
    printf("Enter 8 bit Data or Plain Text i.e. non-negative integer value less than 256\n");
    scanf("%d",&data);
    cipher=sdes_encrypt(data,key);								//	S DES Encryption
    printf("SDES Encrypted Data is = %d",cipher);
    return 0;
}

int swap(int data)                                              //  Performing SWAP or SWITCH
{
    int lpart=data>>4;
    int rpart=data & 15;
    return ((rpart << 4) | lpart);
}

int permute(int data,const short * permutator, int n ,int bitsize)             //  Permutation
{
    int i,out=0,bitmask;
    for(i=0;i<n;i++)
    {
        bitmask=(1 << (bitsize - permutator[i]));
        if(bitmask & data)
            out|=(1 << (n-i-1));
    }
    return out;
}

int fk(int data, int key)                                    //  fk1 or fk2  depending upon key
{
    static const short ep[8]={4,1,2,3,2,3,4,1};              //  E/P
    static const short p4[4]={2,4,3,1};                      //  P4

    static const short rowbits[2]={1,4};
    static const short colbits[2]={2,3};

    const short s0[4][4]= { {1,0,3,2},
                            {3,2,1,0},
                            {0,2,1,3},
                            {3,1,3,2}
                        };                                   //  S0 Box
    const short s1[4][4]= { {0,1,2,3},
                            {2,0,1,3},
                            {3,0,1,0},
                            {2,1,0,3}
                        };                                   //  S1 Box
    int lpart,rpart,temp,l,r,row,col;

    lpart= data >> 4;                                       //  Extract Left part
    rpart= data & 15;                                       //  Extract Right part
    temp=rpart;

    temp=permute(temp, ep , 8 , 4);                         //  Performing Expansion / Permutation  (E/P)

    temp=temp^key;                                          //  Performing XOR with Key

    l=temp >> 4;                                            //  Extracting Left Sub Part Of The Right Part
    r=temp & 15;                                            //  Extracting Right Sub Part Of The Right Part

    row=permute(l, rowbits, 2 , 4);                         //  Fetch The  row bits from Left subpart
    col=permute(l, colbits, 2 , 4);                         //  Fetch The  column bits from Left subpart
    l=s0[row][col];                                         //  Get Mapped Value from S0 Box

    row=permute(r, rowbits, 2 , 4);                         //  Fetch The  row bits from Right subpart
    col=permute(r, colbits, 2 , 4);                         //  Fetch The  column bits from Right subpart
    r=s1[row][col];                                         //  Get Mapped Value from S1 Box

    temp=((l << 2) | r);                                    //  Merge Left and Right Subparts

    temp=permute(temp, p4 , 4 , 4);                         //  Permute P4

    lpart=lpart^temp;                                       //  XOR Left Part of Data with temp

    return ((lpart<<4) | rpart);                            //  Merge Left and Right Part of Data
}

int lcs(int val, int no_of_bits ,int bitsize)               //  'Left Circular Shift' on 'val' by 'no_of_bits' on a number of bit size of 'bitsize'
{
    return ((val << no_of_bits) | (val >> (bitsize - no_of_bits)));
}

int * keygen(int key)                                       //   Generate k1 and k2
{
    static int k[2]={};
    static const short p10[10]={3,5,2,7,4,10,1,9,8,6};      //  P10
    static const short p8[8]={6,3,7,4,8,5,10,9};            //  P8
    int lpart , rpart, kcopy;

    kcopy=permute(key, p10 , 10 , 10);                      //  Performing P10 permutation

    lpart=kcopy>>5;
    rpart=(kcopy & 31);                                     //  Since (00000 11111) base 2 == (31) base 10

    lpart=lcs(lpart, 1 , 5);                                //  Performing LS-1 on Left part
    rpart=lcs(rpart, 1 , 5);                                //  Performing LS-1 on Right part

    k[0]=(lpart<<5 | rpart);                                //  Merging Left And Right Part
    k[0]=permute(k[0] , p8 , 8 , 10);                       //  Performing P8 permutation to get k1

    lpart=lcs(lpart, 2 , 5);                                //  Performing LS-2 on Left part
    rpart=lcs(rpart, 2 , 5);                                //  Performing LS-2 on Right part

    k[1]=(lpart<<5 | rpart);                                //  Merging Left And Right Part
    k[1]=permute(k[1] , p8 , 8 , 10);                       //  Performing P8 permutation to get k1

    return k;
}

int sdes_encrypt(int data,int key)
{
    static const short ip[8]={2,6,3,1,4,8,5,7};             // IP
    static const short ipinv[8]={4,1,3,5,7,2,8,6};          // IP-1
    int *k=keygen(key);                                     // generate_keys k1  and k2

    int ptcopy=permute(data, ip , 8 , 8);

    ptcopy=fk( ptcopy , k[0]);                              //  Perform fk1

    ptcopy=swap(ptcopy);                                    //  Swap left and Right Parts

    ptcopy=fk( ptcopy , k[1]);                              //  Perform fk2

    ptcopy=permute(ptcopy, ipinv , 8 , 8);                  //  Perform IP inverse

    return ptcopy;
}
