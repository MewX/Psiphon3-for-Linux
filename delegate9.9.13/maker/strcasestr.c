int SUBST_strcasestr = 1;

#include <string.h>
#include <ctype.h>

int strncasecmp(const char *s1, const char *s2, size_t n);

char *Strcasestr(const char *s1,const char *s2)
{	const char *p1;
	int len;

	if( *s2 == 0 )
		return (char*)s1;

	len = strlen((char*)s2);
	for( p1 = s1; *p1; p1 ++ )
		if( toupper(*p1) == toupper(*s2) )
		if( strncasecmp((char*)p1,(char*)s2,len)==0 ) 
			return (char*)p1;
	return 0;
}
