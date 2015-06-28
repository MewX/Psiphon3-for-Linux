#include "ccenv.h"

#if defined(__APPLE__) \
 || defined(__linux__) \
 || defined(__FreeBSD__) && defined(DG_LIB_pthread) \
 || defined(__OpenBSD__) && defined(DG_LIB_pthread) \
 || defined(__NetBSD__)  && defined(DG_LIB_pthread) \
 || defined(sun)         && defined(DG_LIB_pthread) \
/* with the pthread library */
#define DG_WITH_PTHREAD
#endif
