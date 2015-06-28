int INHERENT_ptrace(){ return 0; }
int ptraceTraceMe(){ return -1; }
int ptraceContinue(int a,int b){ return -1; }
int ptraceKill(int a){ return -1; }
int getWaitStopSig(int*a){ return -1; }
int getWaitExitSig(int*a){ return -1; }
int getWaitExitCode(int*a){ return -1; }
int getWaitExitCore(int*a){ return -1; }
