#include <signal.h>
#ifdef _MSC_VER
void bzero(void *b,unsigned int length);
#else
#include <strings.h>
#endif

#ifdef sun
/* an executalbe compiled on SunOS may be executed on Solaris,
 * therefore SA_RESTART must be selected at run-time.
 */
#undef SA_RESTART
#define SA_RESTART	(IsSolaris() ? 4 : 0)
#endif

#if defined(SA_RESTART)
typedef void (*VFunc)(int);
VFunc signalRESTART(int sig,VFunc handler)
{	struct sigaction act,oact;

	bzero((char*)&act,sizeof(act));
	bzero((char*)&act.sa_mask,sizeof(act.sa_mask));
	act.sa_handler = handler;
	act.sa_flags = SA_RESTART; /* without SA_NOCLDSTOP */

	if( sigaction(sig,&act,&oact) == -1 )
		return (VFunc)-1;
	return oact.sa_handler;
}
#else
#include "sigaction.c"
#endif
