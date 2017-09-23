/*
Author          :   shreyx ( Shreyanshu Agarwal )
Github Profile  :   https://github.com/shreyx
Disclaimer      :   This code is presented "as is" without any guarantees.
Description     :   This code is an implementation of S-DES encryption using C for binary stream input

@shreyx
*/
#include<stdio.h>
#include<string.h>

char key[11],k1[9],k2[9],ptcopy[9],pt[9],ct[9];

void sdes_encrypt();
void keygen();
void fkey(char keyarr[]);
void swap();

int main()
{
    printf("Enter 10 bit key in binary (e.g. 1001001001)\n");
    scanf("%s",key);
    printf("Enter 8 bit data or plain text in binary (e.g. 10101001)\n");
    scanf("%s",pt);
    sdes_encrypt();
    printf("Plain Text: %s\n", pt);
    printf("Cipher Text: %s\n", ct);
    return 0;
}
void swap()                                                 //SW SWITCH OR SWAP To switch left and right part of ptcopy
{
    char tmp;
    int i;
    for(i=0;i<4;i++)
    {
        tmp=ptcopy[4+i];
        ptcopy[4+i]=ptcopy[i];
        ptcopy[i]=tmp;
    }
}
void sdes_encrypt()
{
    keygen();
    const short ip[8]={2,6,3,1,4,8,5,7};        // IP
    const short ipinv[8]={4,1,3,5,7,2,8,6};     // IP-1
    int i;
    for(i=0;i<8;i++)                    // Performing IP on pt
    {
        ptcopy[i]=pt[ip[i]-1];
    }
    ptcopy[i]='\0';

    fkey(k1);
    swap();
    fkey(k2);

    for(i=0;i<8;i++)                    // Performing IP-1 on ptcopy for Cipher Text
    {
        ct[i]=ptcopy[ipinv[i]-1];
    }
    ct[i]='\0';
}
void keygen()
{
    const int p10[10]={3,5,2,7,4,10,1,9,8,6};
    const int p8[8]={6,3,7,4,8,5,10,9};

    char lpart[6],rpart[6];
    char kcopy[11];
    int i;

    for(i=0;i<10;i++)                               // Performing P10
        kcopy[i]=key[p10[i]-1];
    kcopy[i]='\0';

    for(i=0;i<5;i++)                                //Performing  LS-1
    {
        lpart[i]=kcopy[(i+1)%5];
        rpart[i]=kcopy[5+(i+1)%5];
    }
    lpart[5]='\0';
    rpart[5]='\0';
    strcpy(kcopy,lpart);
    strcat(kcopy,rpart);

    for(i=0;i<8;i++)                                // Performing P8 for k1
    {
        k1[i]=kcopy[p8[i]-1];
    }
    k1[i]='\0';

    for(i=0;i<5;i++)                                //  Performing  LS-2
    {
        lpart[i]=kcopy[(i+2)%5];
        rpart[i]=kcopy[5+(i+2)%5];
    }
    lpart[5]='\0';
    rpart[5]='\0';
    strcpy(kcopy,lpart);
    strcat(kcopy,rpart);

    for(i=0;i<8;i++)                                // Performing P8 for k2
    {
        k2[i]=kcopy[p8[i]-1];
    }
    k2[i]='\0';
}
void fkey(char keyarr[])
{
    const short ep[8]={4,1,2,3,2,3,4,1};              //  E/P
    const short p4[4]={2,4,3,1};                      //  P4
    const short s0[4][4]= { {1,0,3,2},
                            {3,2,1,0},
                            {0,2,1,3},
                            {3,1,3,2}
                        };                                                     //  S0 Box
    const short s1[4][4]= { {0,1,2,3},
                            {2,0,1,3},
                            {3,0,1,0},
                            {2,1,0,3}
                        };                                                     //  S1 Box

    char bin[4][3]={"00","01","10","11"};
    const int dec[2][2]={   {0,1},
                            {2,3}
                        };
    char temp[9];
    char l[3],r[3];
    char toxor[5];                                     // Left and Right parts after e/p
    int i,row,col;

    for(i=0;i<8;i++)
    {
        temp[i]=ptcopy[ 4 + ep[i]-1 ];                  //  Performing E/P on ptcopy right part
    }

    temp[i]='\0';
    for(i=0;i<8;i++)
    {
        temp[i]=(char)(48 + ((temp[i]- '0')^(keyarr[i] - '0')));   //  Performing XOR On temp with keyarr
    }

    row=dec[ temp[0]-'0' ][ temp[3]-'0' ];
    col=dec[ temp[1]-'0' ][ temp[2]-'0' ];
    strcpy( l , bin[ s0[row][col] ] );

    row=dec[ temp[4+0]-'0' ][ temp[4+3]-'0' ];
    col=dec[ temp[4+1]-'0' ][ temp[4+2]-'0' ];
    strcpy( r, bin[ s1[row][col] ] );

    strcpy(temp,l);
    strcat(temp,r);

    for(i=0;i<4;i++)
    {
        toxor[i]=temp[p4[i]-1];
    }
    toxor[i]='\0';

    for(i=0;i<4;i++)
        ptcopy[i]=(char)(48 + ((ptcopy[i]-'0')^(toxor[i]-'0')));
}
