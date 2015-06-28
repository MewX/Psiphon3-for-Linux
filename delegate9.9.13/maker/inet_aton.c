int SUBST_inet_aton = 1;

#include "vsocket.h"
int Inet_aton(const char *addr,struct in_addr *inap);
int inet_aton(const char *addr,struct in_addr *inap)
{
	return Inet_aton(addr,inap);
}
