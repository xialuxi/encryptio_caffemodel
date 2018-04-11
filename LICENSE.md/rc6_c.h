#ifndef RC6_C_H
#define RC6_C_H



//unsigned int moveleft(unsigned int x,unsigned int y);
//unsigned int moveright(unsigned int x,unsigned int y);
//void keyextend(unsigned int *s,unsigned int *l);
//void encryp(unsigned int *A,unsigned int *B,unsigned int *C,unsigned int *D,unsigned int *S);
//void decryp(unsigned int *A,unsigned int *B,unsigned int *C,unsigned int *D,unsigned int *S);

void encryp_buffer( unsigned char *data_buffer, long long buffer_size );
void decryp_buffer( unsigned char *data_buffer, long long buffer_size );

#endif // RC6_C_H

