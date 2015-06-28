int *_errno();
#define errno *_errno()
#define ENOENT  2
#define ESRCH   3
#define EINTR   4
#define EBADF   9
#define ECHILD 10
#define EAGAIN 11
#define ENOMEM 12
#define EACCES 13
#define ENOSPC 28
#define EPIPE  32
