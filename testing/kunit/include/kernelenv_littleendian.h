#ifndef _LINUX_BYTEORDER_LITTLE_ENDIAN_H
#define _LINUX_BYTEORDER_LITTLE_ENDIAN_H

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1234
#endif
#ifndef __LITTLE_ENDIAN_BITFIELD
#define __LITTLE_ENDIAN_BITFIELD
#endif

#define __constant_htonl(x) (swab32(x))
#define __constant_ntohl(x) swab32(x)
#define __constant_htons(x) (swab16(x))
#define __constant_ntohs(x) swab16(x)
#define __constant_cpu_to_le64(x) (x)
#define __constant_le64_to_cpu(x) (x)
#define __constant_cpu_to_le32(x) (x)
#define __constant_le32_to_cpu(x) (x)
#define __constant_cpu_to_le16(x) (x)
#define __constant_le16_to_cpu(x) (x)
#define __constant_cpu_to_be64(x) (swab64(x))
#define __constant_be64_to_cpu(x) swab64((u64)(x))
#define __constant_cpu_to_be32(x) (swab32(x))
#define __constant_be32_to_cpu(x) swab32((u32)(x))
#define __constant_cpu_to_be16(x) (swab16(x))
#define __constant_be16_to_cpu(x) swab16((u16)(x))
#define __cpu_to_le64(x) (x)
#define __le64_to_cpu(x) (x)
#define __cpu_to_le32(x) (x)
#define __le32_to_cpu(x) (x)
#define __cpu_to_le16(x) (x)
#define __le16_to_cpu(x) (x)
#define __cpu_to_be64(x) (swab64(x))
#define __be64_to_cpu(x) swab64((u64)(x))
#define __cpu_to_be32(x) (swab32(x))
#define __be32_to_cpu(x) swab32((u32)(x))
#define __cpu_to_be16(x) (swab16(x))
#define __be16_to_cpu(x) swab16((u16)(x))

static inline u64 __cpu_to_le64p(const u64 *p)
{
	return *p;
}
static inline u64 __le64_to_cpup(const u64 *p)
{
	return *p;
}
static inline u32 __cpu_to_le32p(const u32 *p)
{
	return *p;
}
static inline u32 __le32_to_cpup(const u32 *p)
{
	return *p;
}
static inline u16 __cpu_to_le16p(const u16 *p)
{
	return *p;
}
static inline u16 __le16_to_cpup(const u16 *p)
{
	return *p;
}
static inline u64 __cpu_to_be64p(u64 *p)
{
	return swab64p(p);
}
static inline u64 __be64_to_cpup(u64 *p)
{
	return swab64p((u64 *)p);
}
static inline u32 __cpu_to_be32p(const u32 *p)
{
	return swab32p(p);
}
static inline u32 __be32_to_cpup(u32 *p)
{
	return swab32p((u32 *)p);
}
static inline u16 __cpu_to_be16p(const u16 *p)
{
	return swab16p(p);
}
static inline u16 __be16_to_cpup(u16 *p)
{
	return swab16p((u16 *)p);
}
#define __cpu_to_le64s(x) do {} while (0)
#define __le64_to_cpus(x) do {} while (0)
#define __cpu_to_le32s(x) do {} while (0)
#define __le32_to_cpus(x) do {} while (0)
#define __cpu_to_le16s(x) do {} while (0)
#define __le16_to_cpus(x) do {} while (0)
#define __cpu_to_be64s(x) swab64s(x)
#define __be64_to_cpus(x) swab64s(x)
#define __cpu_to_be32s(x) swab32s(x)
#define __be32_to_cpus(x) swab32s(x)
#define __cpu_to_be16s(x) swab16s(x)
#define __be16_to_cpus(x) swab16s(x)

#endif /* _LINUX_BYTEORDER_LITTLE_ENDIAN_H */
