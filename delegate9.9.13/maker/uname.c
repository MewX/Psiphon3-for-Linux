#ifdef news
#define UNAME "NEWS-OS"
#else
#ifdef _MSC_VER
#define UNAME "Windows"
#else
#define UNAME "?"
#endif
#endif

#include "ystring.h"
int Uname(PVStr(name))
{
	strcpy(name,UNAME);
	return -1;
}
