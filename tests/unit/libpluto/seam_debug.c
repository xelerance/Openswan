#ifndef __seam_debug_c__
#define __seam_debug_c__

#ifndef WANT_THIS_DBG
#define WANT_THIS_DBG DBG_EMITTING|DBG_PARSING|DBG_CONTROL|DBG_CONTROLMORE|DBG_CRYPT|DBG_PRIVATE
#endif

void enable_debugging(void)
{
    base_debugging = WANT_THIS_DBG;
    reset_debugging();
}

void enable_debugging_on_sa(int num)
{
    struct state *st;
    lset_t to_enable = WANT_THIS_DBG;
    st = state_with_serialno(num);
    if(st != NULL) {
        passert(st->st_connection != NULL);
        st->st_connection->extra_debugging = to_enable;
    }
}

#endif
