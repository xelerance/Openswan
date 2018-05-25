#ifndef __seam_rnd_c__
#define __seam_rnd_c__

unsigned int rnd_offset=0;

/* this is very much non-random, for unit testing */
void get_rnd_bytes(u_char *buffer, int length) {
  int i; for(i=0;i<length;i++) buffer[i]=i+rnd_offset;

  /* force upper bit to be on */
  buffer[0] |= 0x80;
}


u_char    secret_of_the_day[SHA1_DIGEST_SIZE] = "abcdabcdabcd";
u_char    ikev2_secret_of_the_day[SHA1_DIGEST_SIZE] = "abcdabcdabcd";

void init_secret(void)
{

}
#endif
