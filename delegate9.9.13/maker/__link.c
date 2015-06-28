#include <unistd.h>
static void dummy(){ link("/","/"); }

int INHERENT_link(){ return 1; }
