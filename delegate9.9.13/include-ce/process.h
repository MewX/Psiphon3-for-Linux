#define _set_invalid_parameter_handler(f)
void *GetProcAddress(HMODULE,const char*);
extern "C" {
int getpid();
}
int system(const char*);
int execvp(const char*,char *const*);
int execl(const char*,...);
int _execvp(const char*,const char *[1024]);

#define _P_WAIT 0
#define _P_NOWAIT 1
int _spawnvpe(int,const char*,const char *const[],const char *const[]);

/*
typedef void (*sigFunc)(int);
sigFunc signal(int,sigFunc);
*/
