#ifndef __seam_natt_vid_c__
#define __seam_natt_vid_c__
#include "pluto/nat_traversal.h"
#include "pluto/vendor.h"

/* send a single NAT VID */
bool nat_traversal_insert_vid(u_int8_t np, pb_stream *outs, struct state *st)
{
  unsigned char *data = "RFC 3947";
  static unsigned char *vid = NULL;
  static unsigned int   vid_len = 0;
  if(vid == NULL) {
    MD5_CTX ctx;
    unsigned char *vidm =  alloc_bytes(MD5_DIGEST_SIZE,"VendorID MD5");
    vid = (char *)vidm;
    if (vidm) {
      unsigned const char *d = data;
      osMD5Init(&ctx);
      osMD5Update(&ctx, d, strlen(data));
      osMD5Final(vidm, &ctx);
      vid_len = MD5_DIGEST_SIZE;
    }

  }
  return out_generic_raw(np, &isakmp_vendor_id_desc, outs,
                         vid, vid_len, "V_ID");
}

#endif
