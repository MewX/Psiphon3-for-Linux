#include <sys/utsname.h>
#include <stdio.h>
#include "ystring.h"

typedef struct {
 struct utsname	ue_un;
	int	ue_un_got;
} UnEnv;
static UnEnv *unEnv;
#define un	unEnv->ue_un
#define un_got	unEnv->ue_un_got
void minit_uname(){
	if( unEnv == 0 )
		unEnv = NewStruct(UnEnv);
}

int Uname(PVStr(name))
{
	minit_uname();

	if( un_got == 0 ){
		if( 0 <= uname(&un) ){
			un.sysname[sizeof(un.sysname)-1] = 0;
			un.release[sizeof(un.release)-1] = 0;
			un_got = 1;
		}else	un_got = -1;
	}
	if( 0 < un_got ){
		sprintf(name,"%s/%s",un.sysname,un.release);
		return 0;
	}else{
		strcpy(name,"?");
		return -1;
	}
}
