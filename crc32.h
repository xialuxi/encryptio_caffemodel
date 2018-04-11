#ifndef _CRC32_H_
#define _CRC32_H_

/*
// Dynamic create crc table switch
*/
//#define DYNAMIC_CRC_TABLE

/* function declarations */
#ifndef uint32_t
typedef  unsigned int  uint32_t;
#endif

extern uint32_t crc32( uint32_t crc, const char *buf, long long len );
extern uint32_t crc32Combine( uint32_t crc1, uint32_t crc2, int len2 );

#endif

/* End of file */

