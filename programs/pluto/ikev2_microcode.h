#ifndef _IKEV2_MICROCODE_H
#define _IKEV2_MICROCODE_H

#include "pluto_constants.h"
#include "ietf_constants.h"
#include "constants.h"
#include "demux.h"

struct state_v2_microcode {
    const char *svm_name;       /* human readable name for this state */
    enum state_kind state, next_state;
    enum isakmp_xchg_types recv_type;
    lset_t flags;
    lset_t req_clear_payloads;  /* required unencrypted payloads (allows just one) for received packet */
    lset_t opt_clear_payloads;  /* optional unencrypted payloads (none or one) for received packet */
    lset_t req_enc_payloads;  /* required encrypted payloads (allows just one) for received packet */
    lset_t opt_enc_payloads;  /* optional encrypted payloads (none or one) for received packet */
    enum event_type timeout_event;
    state_transition_fn *processor; /* handle expected message matching payloads as described above */
    state_transition_fn *ntf_processor; /* handle an encrypted notification */
};

extern const struct state_v2_microcode ikev2_parent_firststate_microcode;
extern const struct state_v2_microcode ikev2_childrekey_microcode;
extern struct state_v2_microcode v2_state_microcode_table[];

#endif // _IKEV2_MICROCODE_H
