#include "vsocket.h"
#if defined(hpux) || defined(__hpux__) \
 || defined(__CYGWIN__) \
 || defined(__hpux) \
 || defined(sun) \
 || defined(__osf__)

#undef gethostbyname /* 9.9.2: to avoid loop gethostbyname/_GETHOSTBYNAME */

struct hostent *gethostbyname2X(const char *name,int af){
	return gethostbyname(name);
}
#endif
