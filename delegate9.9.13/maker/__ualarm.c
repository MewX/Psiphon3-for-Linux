#include <unistd.h>
int Ualarm(int usecs){
	return ualarm(usecs,0);
}
