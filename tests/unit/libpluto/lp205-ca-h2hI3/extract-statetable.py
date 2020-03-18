#!/usr/bin/python
#
# This script executes h2hI3 test case, and dumps states stored in
# statetable[] array into statetable.c file.
# 
# NOTE: most points are forced to NULL, only states adn connections
#       are dumped.
#
# To run manually:
#
#     gdb -q -nh -x extract-statetable.py

import gdb
import subprocess
import string
import re
import sys

testname = 'h2hI3'

gdb.execute('file %s' % testname)
gdb.execute('set args OUTPUT/ikev2client.record.x86_64 alttunnel OUTPUT/h2hI3.pcap h2hR1.pcap h2hR2.pcap')
gdb.execute('set print pretty')
gdb.execute('set confirm off')
gdb.execute('set target-charset ASCII')
gdb.execute('set print elements 1000')
gdb.execute('b show_states_status')
gdb.execute('run')

outfile = 'OUTPUT/%s-statetable.c' % testname
out = open(outfile, "w")

# adjust all serial numbers in the canned states by this amount
serial_adjust = 1000

states = {}
conns = {}
addresses = {}

symbol_mappings = {
        'ikev2_parent_inR1outI2_continue' : 'NULL',
        'crypto_encrypter_3des' : 'NULL',
        'crypto_hasher_md5' : 'NULL',
        'crypto_integ_md5' : 'NULL',
        'algo_aes' : 'NULL',
        'ei_buf' : 'NULL',
        }

def get_member(addr,atype,member):
    o = gdb.execute('p/x ((%s *)%s)->%s' % (atype,addr,member), to_string=True)
    return o.strip().split(' ', 2)[2]

def get_state_member(addr,member):
    return get_member(addr,'struct state',member)

def get_symbol(addr):
    if addr in addresses:
        return addresses[addr]

    txt = gdb.execute('info symbol %s' % addr, to_string=True)

    # WARNING: I dond't know why my gdb is doing this...
    # 
    # gdb$ p statetable[28]->st_hashchain_next->st_suspended_md_func
    # $12 = 0x469980 <__FUNCTION__.12047> "ikev2_parent_inR1outI2_continue"
    # gdb$ info symbol 0x469980
    # __FUNCTION__.12047 in section .rodata of /home/bart/src/Openswan/tests/unit/libpluto/lp205-ca-h2hI3/h2hI3
    #
    # it would be preferable to get the actual function name...
    if re.match(r'__FUNCTION__.\d+', txt):
        return

    match = re.match(r'^(\S+) in section .*$', txt)
    if match:
        return match.group(1)

    match = re.match(r'^(\S+ \+ \d+) in section .*$', txt)
    if match:
        return "(void*)( (char*)" + match.group(1) + " )"

def collect_states_and_conns():
    global states
    global conns
    for i in range(0,31):
        o = gdb.execute('p/x statetable[%d]' % i, to_string=True)
        state = o.strip().split(' ')[2]
        while int(state, 16):
            num = int(get_state_member(state,'st_serialno'),16)

            # adjust serial number
            num += serial_adjust

            # remember this state
            states[num] = state
            addresses[state] = 'h2h_sa_%d' % num

            # figure out the connection for this state
            conn = get_state_member(state, 'st_connection')
            if not conn in addresses:
                ci = len(conns.keys())
                conns[ci] = conn
                addresses[conn] = 'h2h_conn_%d' % ci

            # move to the next state
            state = get_state_member(state,'st_hashchain_next')

def apply_addresses(txt):
    # convert addresses we know to labels
    for addr,label in addresses.items():
        srch = r'\b' + re.escape(addr) + r'\b'
        repl = "&%s" % label
        txt = re.sub(srch, repl, txt)
    return txt

def apply_symbol_match(match):
    #print('---> %s' % match.group(0))
    #print(match.groups())

    name = match.group(1)
    addr = match.group(2)
    symb = match.group(3)
    valu = match.group(4)
    fini = match.group(5)

    #if name:
    #    print("name='%s'" % name)
    #if addr:
    #    print("addr='%s'" % addr)
    #if symb:
    #    print("symb='%s'" % symb)
    #if valu:
    #    print("valu='%s'" % valu)

    if valu:
        symbol = valu
    elif symb:
        symbol = symb
    else:
        symbol = get_symbol(addr)
        if not symbol:
            return '%s = %s%s' % (name, addr, fini)

    if symbol in symbol_mappings:
        return '%s = %s%s' % (name, symbol_mappings[symbol], fini)

    if symbol == 'NULL':
        return '%s = NULL%s' % (name, fini)

    if re.match(r'^[a-z0-9_]+$', symbol):
        return '%s = &%s%s' % (name, symbol, fini)

    return '%s = %s%s' % (name, symbol, fini)

def apply_symbols(txt):
    # convert addresses we know to labels
    srch = r'\b([a-zA-Z_]\S*) = (0x[0-9a-f]{4,})(?: <([^>]+)>)?(?: "([^"]+)")?(,|\n)'
    txt = re.sub(srch, apply_symbol_match, txt)

    return txt

def apply_unknown_addresses(txt):
    # kill all other addresses
    txt = re.sub( r"0x7fff[0-9a-f]{8,}", 'NULL', txt)
    return txt

def apply_repeats(txt):
    # replace 0x0 <repeats X times> from end of arrays
    txt = re.sub(r'(0x0+) <repeats \d+ times>}', r'\1}', txt)

    txt = re.sub(r"('\\\d+') <repeats \d+ times>", r'{\1,}', txt)

    m = re.search(r'.{,10} repeats \d+ times .{,10}', txt)
    if m:
        print(m)
        raise Exception('unexpected repeats x times')

    return txt

def apply_members(txt):
    # convert gdb pretty dump to C99 structure initialization
    txt = re.sub(r'(\s+)\b([_A-Za-z]\S* =[^\n]*)', r'\1.\2', txt)
    return txt

def apply_serial_adjust_match(match):
    name = match.group(1)
    num = int(match.group(2),0)

    if num:
        num += serial_adjust

    return '%s = %u' % (name, num)

def apply_serial_adjust(txt):
    srch = r'\b(st_serialno|st_clonedfrom) = ((?:0x)?[0-9a-f]+)\b'
    txt = re.sub(srch, apply_serial_adjust_match, txt)
    return txt

def out_struct(addr, atype, label):
    #o = gdb.execute('p/x *((%s *)%s)' % (atype, addr), to_string=True)
    o = gdb.execute('p *((%s *)%s)' % (atype, addr), to_string=True)
    o = o.strip()

    # strings
    o = re.sub( r'\b([a-z_]\S*) = 0x[0-9a-f]+ ("(?:\\.|[^"\\])*"),', r'\1 = \2,', o )

    # constants
    o = re.sub( r"\b([a-z_]\S*) = ([0-9]+) '[^']+',", r'\1 = \2,', o )

    o = apply_members(o)
    o = apply_repeats(o)
    o = apply_addresses(o)
    o = apply_symbols(o)
    o = apply_serial_adjust(o)
    o = apply_unknown_addresses(o)

    o = re.sub( r'^\S+', '%s %s' % (atype, label), o)

    out.write(o + ';\n')
    
def out_state(num, state):
    txt = 'SA #%d @ %s' % (num, state)
    print(txt)
    out.write('/* %s */\n' % txt)

    name = addresses[state]
    out_struct(state, 'struct state', name)

def out_conn(conn):

    txt = 'CONN @ %s' % conn
    print(txt)
    out.write('/* %s */\n' % txt)

    name = addresses[conn]
    out_struct(conn, 'struct connection', name)


collect_states_and_conns()

out.write('void h2h_insert_states(void);\n')
for i in sorted(states.keys()):
    state = states[i]
    name = addresses[state]
    out.write('struct state %s;\n' % name)

for i in sorted(conns.keys()):
    conn = conns[i]
    name = addresses[conn]
    out.write('struct connection %s;\n' % name)

for i in sorted(states.keys()):
    out_state(i, states[i])

for i in sorted(conns.keys()):
    out_conn(conns[i])

out.write('void h2h_insert_states(void) {\n')
out.write('    struct state *st;\n')
for i in sorted(states.keys()):
    state = states[i]
    name = addresses[state]
    out.write('    /* force %s into the statetable */\n' % name)
    out.write('    %s.st_hashchain_prev = NULL;\n' % name)
    out.write('    %s.st_hashchain_next = NULL;\n' % name)
    out.write('    insert_state( &%s );\n' % name)
out.write('}')


out.close()
gdb.execute('quit')

