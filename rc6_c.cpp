//#include "rc6_c.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define RC6_R   20
#define RC6_C   4

static const unsigned int r=20;
static const unsigned int w=32;
static const unsigned int b=16;
static const unsigned int c=4;
static const unsigned int p=0x8E549B60;
static const unsigned int q=0x4C3A82D7;



static unsigned int moveleft(unsigned int x,unsigned int y)
{
    unsigned int i,temp;
    if(y/32!=0)
        y=y%32;
    for (i=0; i<y; i++)
    {
        temp=x&0x80000000;
        x=x<<1;
        x=x+((temp>>31)&0x00000001);
    }
    return x;
}

static unsigned int moveright(unsigned int x,unsigned int y)
{
    unsigned int i,temp;
    if(y/32!=0)
        y=y%32;
    for (i=0; i<y; i++)
    {
        temp=x&0x00000001;
        x=x>>1;
        x=(x&0x7fffffff)+(temp<<31);
    }
    return x;
}

void keyextend(unsigned int *s,unsigned int *l)
{
    unsigned int i,j,k,k_a,k_b;
    s[0]=p;
    for (i=1; i<=43; i++)
        s[i]=s[i-1]+q;
    k_a=0x3A4158C9;
    k_b=0x6D7219E5;
    i=0;
    j=0;
    for (k=1; k<=132; k++)
    {
        s[i]=s[i]+k_a+k_b;
        s[i]=moveleft(s[i],3);
        k_a=s[i];
        l[j]=l[j]+k_a+k_b;
        l[j]=moveleft(l[j],((k_a+k_b)%32));
        k_b=l[j];
        i=(i+1)%44;
        j=(j+1)%4;
    }
}

static void encryp(unsigned int *A,unsigned int *B,unsigned int *C,unsigned int *D,unsigned int *S)
{
    int i,j,t,u,temp;
    *B=*B+S[0];
    *D=*D+S[1];
    j=(unsigned int)(log(w)/log(2));
    for (i=1; i<=r; i++)
    {
        t=moveleft(((*B)*(2*(*B)+1)),j);
        u=moveleft(((*D)*(2*(*D)+1)),j);
        temp=moveleft(((*A)^t),u%32);
        *A=temp+S[2*i];
        temp=moveleft(((*C)^u), t%32);
        *C=temp+S[2*i+1];
        temp=*A;
        *A=*B;
        *B=*C;
        *C=*D;
        *D=temp;
    }
    *A=*A+S[2*r+2];
    *C=*C+S[2*r+3];
}

static void decryp(unsigned int *A,unsigned int *B,unsigned int *C,unsigned int *D,unsigned int *S)
{
    unsigned int i,j,u,t,temp;
    j=(unsigned int)(log(w)/log(2));
    *C=*C-S[2*r+3];
    *A=*A-S[2*r+2];
    for (i=r; i>=1; i--)
    {
        temp=*D;
        *D=*C;
        *C=*B;
        *B=*A;
        *A=temp;
        u=moveleft(((*D)*(2*(*D)+1)),j);
        t=moveleft(((*B)*(2*(*B)+1)),j);
        temp=moveright(((*C)-S[2*i+1]),t%32);
        *C=temp^u;
        temp=moveright(((*A)-S[2*i]), u%32);
        *A=temp^t;
    }
    *D=*D-S[1];
    *B=*B-S[0];
}

void encryp_buffer( unsigned char *data_buffer, long long buffer_size )
{
    unsigned int key_print[ 8 ] = { 0x9F375AE6, 0x8C90A562, 0xB304D857, 0x219B547D, 0xD7054A28, 0xFC7419B3, 0x10A2359D, 0x64C2F7EA };
    unsigned int ex_key[ 2 * RC6_R + 4 ];
    int i;
    keyextend( ex_key, key_print );

    if( NULL != data_buffer )
    {
        unsigned int *enc_a = NULL;
        unsigned int *enc_b = NULL;
        unsigned int *enc_c = NULL;
        unsigned int *enc_d = NULL;

        int once_enc_size = sizeof( unsigned int ) * 4;
        int loop = buffer_size / ( sizeof( unsigned int ) * 4 );
        for( i = 0; i < loop; ++i )
        {
            enc_a = ( unsigned int *)( data_buffer + once_enc_size * i );
            enc_b = ( unsigned int *)( data_buffer + once_enc_size * i + 4 );
            enc_c = ( unsigned int *)( data_buffer + once_enc_size * i + 8 );
            enc_d = ( unsigned int *)( data_buffer + once_enc_size * i + 12 );

            encryp( enc_a, enc_b, enc_c, enc_d, ex_key );
        }
    }
}

void decryp_buffer( unsigned char *data_buffer, long long buffer_size )
{
    unsigned int key_print[ 8 ] = { 0x9F375AE6, 0x8C90A562, 0xB304D857, 0x219B547D, 0xD7054A28, 0xFC7419B3, 0x10A2359D, 0x64C2F7EA };
    unsigned int ex_key[ 2 * RC6_R + 4 ];
    int i;
    keyextend( ex_key, key_print );

    if( NULL != data_buffer )
    {
        unsigned int *dec_a = NULL;
        unsigned int *dec_b = NULL;
        unsigned int *dec_c = NULL;
        unsigned int *dec_d = NULL;

        int once_dec_size = sizeof( unsigned int ) * 4;
        int loop = buffer_size / ( sizeof( unsigned int ) * 4 );
        for( i = 0; i < loop; ++i )
        {
            dec_a = ( unsigned int * )( data_buffer + once_dec_size * i );
            dec_b = ( unsigned int * )( data_buffer + once_dec_size * i + 4 );
            dec_c = ( unsigned int * )( data_buffer + once_dec_size * i + 8 );
            dec_d = ( unsigned int * )( data_buffer + once_dec_size * i + 12 );

            decryp( dec_a, dec_b, dec_c, dec_d, ex_key );
        }
    }
}
