#include "vsocket.h"

#if defined(__cplusplus)
extern "C" {
#endif
struct hostent *gethostbyname2(const char *name,int af);
#if defined(__cplusplus)
}
#endif

struct hostent *gethostbyname2X(const char *name,int af){
	return gethostbyname2(name,af);
}
