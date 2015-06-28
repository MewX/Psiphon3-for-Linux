#include "ystring.h"
#include "proc.h"

#undef Finish
void Finish(int code)
{
	exit(code);
}
void FinishX(PCStr(F),int L,int code){
	exit(code);
}
