int SUBST_strncpy = 1;

char *strncpy(char s1[], const char *s2, unsigned int n)
{	char *sp;

	sp = s1;
	while( 0 < n-- ){
		if( (*sp++ = *s2++) == 0 ){
			while( 0 < n-- )
				*sp++ = 0;
			break;
		}
	}
	return s1;
}
