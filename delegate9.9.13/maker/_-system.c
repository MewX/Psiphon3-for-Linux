#include "ystring.h"

#ifndef _MSC_VER
int unix_system(PCStr(com));
extern "C" {
int system(PCStr(com)){
	return unix_system(com);
}
}
#endif
