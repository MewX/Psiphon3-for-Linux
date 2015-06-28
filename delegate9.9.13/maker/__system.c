#include "ystring.h"

#ifndef _MSC_VER
int unix_system(PCStr(com));
int std::system(PCStr(com)){
	return unix_system(com);
}
#endif
