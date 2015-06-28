#include <process.h>

#ifdef _P_NOWAIT
#ifndef P_NOWAIT
#define P_NOWAIT _P_NOWAIT
#endif
#endif

#ifdef _P_WAIT
#ifndef P_WAIT
#define P_WAIT _P_WAIT
#endif
#endif

int INHERENT_spawn(){ return 1; }
int SPAWN_P_NOWAIT = P_NOWAIT;
int SPAWN_P_WAIT = P_WAIT;
