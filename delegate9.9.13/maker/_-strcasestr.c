#if !defined(__osf__) && !defined(_MSC_VER) && !defined(__sun__)  \
 && !defined(__CYGWIN__) \
 && !defined(_AIX) \
 && !defined(__hpux__) \
 && !defined(__hpux)
int SUBST_strcasestr = 0;
#include <string.h>
char *Strcasestr(const char *s1,const char *s2){
	return strcasestr(s1,s2);
}
#endif
