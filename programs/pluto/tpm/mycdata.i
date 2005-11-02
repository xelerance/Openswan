/* -----------------------------------------------------------------------------
 * cdata.i
 *
 * Author(s):  David Beazley (beazley@cs.uchicago.edu)
 *
 * This library file contains macros for manipulating raw C data as strings.
 *
 * $Header: /xelerance/MASTER/cvs-master/openswan-2/programs/pluto/tpm/mycdata.i,v 1.1 2005/10/06 19:36:59 mcr Exp $
 * ----------------------------------------------------------------------------- */

%{
typedef struct SWIGCDATA {
    char *data;
    int   len;
} SWIGCDATA;
%}

/* -----------------------------------------------------------------------------
 * Typemaps for returning binary data
 * ----------------------------------------------------------------------------- */

#if SWIGPYTHON
%typemap(out) SWIGCDATA {
   $result = PyString_FromStringAndSize($1.data,$1.len);
}
%typemap(in) (const void *indata, int inlen) = (char *STRING, int LENGTH);
#elif SWIGPERL
%typemap(out) SWIGCDATA {
   ST(argvi) = sv_newmortal();
   sv_setpvn((SV*)ST(argvi++),$1.data,$1.len);
}
%typemap(in) (const void *indata, int inlen) = (char *STRING, int LENGTH);
#elif SWIGTCL
%typemap(out) SWIGCDATA {
   Tcl_SetObjResult(interp,Tcl_NewByteArrayObj($1.data,$1.len));
}
%typemap(in) (const void *indata, int inlen) {
    int temp;
    $1 = ($1_ltype) Tcl_GetByteArrayFromObj($input,&temp);
    $2 = ($2_ltype) temp;
}
#elif SWIGRUBY
%typemap(out) SWIGCDATA {
   $result = rb_str_new($1.data,$1.len);
}
%typemap(in) (const void *indata, int inlen) = (char *STRING, int LENGTH);
#elif SWIGGUILE
%typemap(out) SWIGCDATA {
   $result = gh_str2scm($1.data,$1.len);
}
%typemap(in) (const void *indata, int inlen) = (char *STRING, int LENGTH);
#else
%echo "cdata.i module not supported."
#endif


/* -----------------------------------------------------------------------------
 * %cdata(TYPE [, NAME]) 
 *
 * Convert raw C data to a binary string.
 * ----------------------------------------------------------------------------- */

%define %cdata(TYPE,NAME...)

%insert("header") {
#if #NAME == ""
static SWIGCDATA cdata_##TYPE(TYPE *ptr, int nelements) {
#else
static SWIGCDATA cdata_##NAME(TYPE *ptr, int nelements) {
#endif
   SWIGCDATA d;
   d.data = (char *) ptr;
#if #TYPE != "void"
   d.len  = nelements*sizeof(TYPE);
#else
   d.len  = nelements;
#endif
   return d;
}
}

%typemap(default) int nelements "$1 = 1;"

#if #NAME == ""
SWIGCDATA cdata_##TYPE(TYPE *ptr, int nelements);
#else
SWIGCDATA cdata_##NAME(TYPE *ptr, int nelements);
#endif
%enddef

%typemap(default) int nelements;

%rename(cdata) ::cdata_void(void *ptr, int nelements);

%cdata(void);

/* Memory move function */
void memmove(void *data, const void *indata, int inlen);




