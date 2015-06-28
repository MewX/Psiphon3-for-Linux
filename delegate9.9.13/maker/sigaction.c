#include <signal.h>
typedef void (*VFunc)(int);

VFunc signalRESTART(int sig,VFunc handler)
{
	return signal(sig,handler);
}
