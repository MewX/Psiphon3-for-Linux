int SUBST_usleep = 1;

void usleep_bypoll(int usec);
void usleep(int usec){ usleep_bypoll(usec); }
void Usleep(int usec){ usleep(usec); }
