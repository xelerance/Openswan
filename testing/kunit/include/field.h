#ifndef __NFSIM_FIELD_H
#define __NFSIM_FIELD_H
/* Dynamically attach a "field" to a structure.  This is better than
 * actually adding a field which might accidentally clash with a real
 * field (or someone developing under nfsim might think it's a real field!).
 */
#include <stdbool.h>

/* strct is talloc'ed: field destroyed when strct is.  val is talloc_stealed */
void field_attach(const void *strct, const char *name, void *val);
/* strct is not talloc'ed: field destroyed manually.  */
void field_attach_static(const void *strct, const char *name, void *val);
bool field_exists(const void *strct, const char *name);
void *field_value(const void *strct, const char *name);
void field_detach(const void *strct, const char *name);
void field_detach_all(const void *strct);
#endif /* __NFSIM_FIELD_H */

