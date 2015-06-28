int SUBST_strstr = 1;

unsigned int strlen(const char*);
int strncmp(const char*,const char*,unsigned int);

const char *strstr(const char *s1,const char *s2)
{	const char *p1;
	int len;

	if( *s2 == 0 )
		return (char*)s1;

	len = strlen(s2);
	for( p1 = s1; *p1; p1 ++ )
		if( *p1 == *s2 && strncmp(p1,s2,len)==0 ) 
			return p1;
	return 0;
}
