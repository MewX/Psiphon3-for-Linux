#include "ystring.h"

int SUBST_bcopy = 1; /* bcopy(void*,void*,unsigned int*); */

#if defined(__hpux__)
#define TSZ unsigned long
#else
#define TSZ unsigned int
#endif

void bcopy(const void *b1,void *b2,TSZ length)
{	int i;
	const char *t1;
	char *t2;

	if( b2 == b1 )
		return;
	if( b2 < b1 )
	for( i = 0; i < length; i++ )
		((char*)b2)[i] = ((char*)b1)[i];
	else{
		t1 = (char*)b1 + length - 1;
		t2 = (char*)b2 + length - 1;
		for( i = 0; i < length; i++ )
			*t2-- = *t1--;
	}
}

int bcmp(const void *b1,const void *b2,TSZ length)
{	int i;

	for( i = 0; i < length; i++) 
		if( ((char*)b1)[i] != ((char*)b2)[i] )
			return 1;
	return 0;
}
