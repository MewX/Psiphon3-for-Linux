HANDLE CreateFileX(const char *fn,int da,int sm,LPSECURITY_ATTRIBUTES sa,int cd,int fa,HANDLE tf);
#undef CreateFile
#define CreateFile(fn,da,sm,sa,cd,fa,tf) CreateFileX(fn,da,sm,sa,cd,fa,tf)

HMODULE GetModuleHandleX(char *mn);
#undef GetModuleHandle
#define GetModuleHandle(mn) GetModuleHandleX(mn)

HMODULE LoadLibraryX(const char *mn);
#undef LoadLibrary
#define LoadLibrary(mn) LoadLibraryX(mn)

#undef WSASocket
#define WSASocket(af,ty,pr,pi,gr,fl) WSASocketW(af,ty,pr,pi,gr,fl)

HRESULT CoInitialize(LPVOID rs);
int CreateProcessX(const char *an,char *cl,LPSECURITY_ATTRIBUTES pa,LPSECURITY_ATTRIBUTES ta,int ih,int cf,void *ev,void *cd,LPSTARTUPINFO si,LPPROCESS_INFORMATION pi);
#undef CreateProcess
#define CreateProcess(an,cl,pa,ta,ih,cf,ev,cd,si,pi) CreateProcessX(an,cl,pa,ta,ih,cf,ev,cd,si,pi)

#define WSAPROTOCOL_INFO WSAPROTOCOL_INFOW
int WSADuplicateSocketW(SOCKET s,int pid,LPWSAPROTOCOL_INFOW pi);
#undef WSADuplicateSocket
#define WSADuplicateSocket(s,pid,pi) WSADuplicateSocketW(s,pid,pi)

BOOL WINAPI GetProcessTimes(HANDLE hProcess,LPFILETIME lpCreationTime,LPFILETIME lpExitTime,LPFILETIME lpKernelTime,LPFILETIME lpUserTime);

HANDLE CreateFileForMappingA(const char *fn,DWORD da,DWORD sm, PSECURITY_ATTRIBUTES sa,DWORD cd,DWORD fa,HANDLE tf);
