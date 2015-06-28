int SUBST_strcasecmp = 1;

#include <ctype.h>

int strncasecmp(const char *a, const char *b, unsigned int n)
{	register char ac,bc;
	register int i;

	for( i = 1; i < n; i++ ){
		ac = *a++;
		bc = *b++;

		if(ac == 0){
			if(bc == 0)
				return 0;
			else	return -1;
		}else
		if(bc == 0)
			return 1;
		else
		if(ac != bc){
			if(islower(ac)) ac = toupper(ac);
			if(islower(bc)) bc = toupper(bc);
			if( ac != bc )
				return ac - bc;
		}
	}
	if(islower(*a)) ac = toupper(*a); else ac = *a;
	if(islower(*b)) bc = toupper(*b); else bc = *b;
	return ac - bc;
}

int strcasecmp(const char *a,const char *b)
{
	return strncasecmp(a,b,0xFFFFFFF);
}
