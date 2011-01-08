static inline u8 get_u8(void *vp)
{
	u8 *p = (u8*)vp;
	return *p;
}

static inline u16 get_u16(void *vp)
{
	u8 *p = (u8*)vp;
	u16 a;

	a  = p[0] << 8;
	a |= p[1];

	return a;
}

static inline u32 get_u32(void *vp)
{
	u8 *p = (u8*)vp;
	u32 a;

	a  = p[0] << 24;
	a |= p[1] << 16;
	a |= p[2] <<  8;
	a |= p[3] <<  0;

	return a;
}

static inline u64 get_u64(void *vp)
{
	u8 *p = (u8*)vp;
	u32 a, b;

	a = get_u32(p);
	b = get_u32(p + 4);

	return ((u64)a<<32) | b;
}

static inline void set_u16(void *vp, u16 v)
{
	u8 *p = (u8*)vp;
	p[0] = v >>  8;
	p[1] = v;
}

static inline void set_u32(void *vp, u32 v)
{
	u8 *p = (u8*)vp;
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >>  8;
	p[3] = v;
}

static inline void set_u64(void *vp, u64 v)
{
	u8 *p = (u8*)vp;
	set_u32(p + 4, v);
	v >>= 32;
	set_u32(p, v);
}

