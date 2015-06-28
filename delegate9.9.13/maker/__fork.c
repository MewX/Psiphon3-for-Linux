#include <sys/wait.h>

int _INHERENT_fork(){ return 1; }
int INHERENT_fork(){ return 1; }
int WAIT_WNOHANG = WNOHANG;
