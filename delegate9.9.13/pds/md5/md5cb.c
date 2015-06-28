#include "global.h"
#include <string.h>

/* Note: Replace "for loop" with standard memset if possible.
 */
void MD5_memset (POINTER output, int value, unsigned int len)
{
/*
  unsigned int i;
  for (i = 0; i < len; i++)
 ((char *)output)[i] = (char)value;
*/
  memset(output,value,len);
}
