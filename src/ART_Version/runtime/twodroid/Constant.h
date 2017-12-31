#ifndef ART_RUNTIME_TWODROID_CONSTANT_H_
#define ART_RUNTIME_TWODROID_CONSTANT_H_

#include <stdint.h>

static unsigned int inline BKDRHash( const char * const str )
{
	const static unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
	unsigned int hash = 0;
 	unsigned int i = 0;
	while ( str[i] != 0 )
		hash = hash * seed + str[i++];
 
	return hash;
}


namespace gossip{

	typedef unsigned int 	u4;
	typedef unsigned short	u2;
	typedef unsigned char	u1;
	typedef long long		s8;


	const static u4	MaxLineLen			= 256;
	const static u4 ProcFileNameMaxLen	= 64;

	union myunion{
	double d;
	u4 u[2];
	s8 s;
    };


}//end of namespace




#endif