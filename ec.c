// Copyright 2007,2008,2010  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <string.h>
#include <stdio.h>

#include "tools.h"

static u8 ec_p[20];
static u8 ec_a[20];	// mon
static u8 ec_b[20];	// mon
static u8 ec_N[21];
static u8 ec_G[40];	// mon
static u8 ec_Q[40];	// mon
static u8 ec_k[21];

static void elt_copy(u8 *d, u8 *a)
{
	memcpy(d, a, 20);
}

static void elt_zero(u8 *d)
{
	memset(d, 0, 20);
}

static int elt_is_zero(u8 *d)
{
	u32 i;

	for (i = 0; i < 20; i++)
		if (d[i] != 0)
			return 0;

	return 1;
}

static void elt_add(u8 *d, u8 *a, u8 *b)
{
	bn_add(d, a, b, ec_p, 20);
}

static void elt_sub(u8 *d, u8 *a, u8 *b)
{
	bn_sub(d, a, b, ec_p, 20);
}

static void elt_mul(u8 *d, u8 *a, u8 *b)
{
	bn_mon_mul(d, a, b, ec_p, 20);
}

static void elt_square(u8 *d, u8 *a)
{
	elt_mul(d, a, a);
}

static void elt_inv(u8 *d, u8 *a)
{
	u8 s[20];
	elt_copy(s, a);
	bn_mon_inv(d, s, ec_p, 20);
}

static void point_to_mon(u8 *p)
{
	bn_to_mon(p, ec_p, 20);
	bn_to_mon(p+20, ec_p, 20);
}

static void point_from_mon(u8 *p)
{
	bn_from_mon(p, ec_p, 20);
	bn_from_mon(p+20, ec_p, 20);
}

#if 0
static int point_is_on_curve(u8 *p)
{
	u8 s[20], t[20];
	u8 *x, *y;

	x = p;
	y = p + 20;

	elt_square(t, x);
	elt_mul(s, t, x);

	elt_mul(t, x, ec_a);
	elt_add(s, s, t);

	elt_add(s, s, ec_b);

	elt_square(t, y);
	elt_sub(s, s, t);

	return elt_is_zero(s);
}
#endif

static int point_zero(u8 *p)
{
	elt_zero(p);
	elt_zero(p+20);
}

static int point_is_zero(u8 *p)
{
	return elt_is_zero(p) && elt_is_zero(p+20);
}

static void point_double(u8 *r, u8 *p)
{
	u8 s[20], t[20];
	u8 pp[40];
	u8 *px, *py, *rx, *ry;

	memcpy(pp, p, 40);

	px = pp;
	py = pp + 20;
	rx = r;
	ry = r + 20;

	if (elt_is_zero(py)) {
		point_zero(r);
		return;
	}

	elt_square(t, px);	// t = px*px
	elt_add(s, t, t);	// s = 2*px*px
	elt_add(s, s, t);	// s = 3*px*px
	elt_add(s, s, ec_a);	// s = 3*px*px + a
	elt_add(t, py, py);	// t = 2*py
	elt_inv(t, t);		// t = 1/(2*py)
	elt_mul(s, s, t);	// s = (3*px*px+a)/(2*py)

	elt_square(rx, s);	// rx = s*s
	elt_add(t, px, px);	// t = 2*px
	elt_sub(rx, rx, t);	// rx = s*s - 2*px

	elt_sub(t, px, rx);	// t = -(rx-px)
	elt_mul(ry, s, t);	// ry = -s*(rx-px)
	elt_sub(ry, ry, py);	// ry = -s*(rx-px) - py
}

static void point_add(u8 *r, u8 *p, u8 *q)
{
	u8 s[20], t[20], u[20];
	u8 *px, *py, *qx, *qy, *rx, *ry;
	u8 pp[40], qq[40];

	memcpy(pp, p, 40);
	memcpy(qq, q, 40);

	px = pp;
	py = pp + 20;
	qx = qq;
	qy = qq + 20;
	rx = r;
	ry = r + 20;

	if (point_is_zero(pp)) {
		elt_copy(rx, qx);
		elt_copy(ry, qy);
		return;
	}

	if (point_is_zero(qq)) {
		elt_copy(rx, px);
		elt_copy(ry, py);
		return;
	}

	elt_sub(u, qx, px);

	if (elt_is_zero(u)) {
		elt_sub(u, qy, py);
		if (elt_is_zero(u))
			point_double(r, pp);
		else
			point_zero(r);

		return;
	}

	elt_inv(t, u);		// t = 1/(qx-px)
	elt_sub(u, qy, py);	// u = qy-py
	elt_mul(s, t, u);	// s = (qy-py)/(qx-px)

	elt_square(rx, s);	// rx = s*s
	elt_add(t, px, qx);	// t = px+qx
	elt_sub(rx, rx, t);	// rx = s*s - (px+qx)

	elt_sub(t, px, rx);	// t = -(rx-px)
	elt_mul(ry, s, t);	// ry = -s*(rx-px)
	elt_sub(ry, ry, py);	// ry = -s*(rx-px) - py
}

static void point_mul(u8 *d, u8 *a, u8 *b)	// a is bignum
{
	u32 i;
	u8 mask;

	point_zero(d);

	for (i = 0; i < 21; i++)
		for (mask = 0x80; mask != 0; mask >>= 1) {
			point_double(d, d);
			if ((a[i] & mask) != 0)
				point_add(d, d, b);
		}
}

static void generate_ecdsa(u8 *R, u8 *S, u8 *k, u8 *hash)
{
	u8 e[21];
	u8 kk[21];
	u8 m[21];
	u8 minv[21];
	u8 mG[40];
	FILE *fp;

	e[0] = 0;
	memcpy(e + 1, hash, 20);

try_again:
	fp = fopen("/dev/random", "rb");
	if (fread(m, sizeof m, 1, fp) != 1)
		fail("reading random");
	fclose(fp);
	m[0] = 0;
	if (bn_compare(m, ec_N, 21) >= 0)
		goto try_again;

	//	R = (mG).x

	point_mul(mG, m, ec_G);
	point_from_mon(mG);
	R[0] = 0;
	elt_copy(R+1, mG);

	//	S = m**-1*(e + Rk) (mod N)

	bn_copy(kk, k, 21);
	bn_reduce(kk, ec_N, 21);
	bn_to_mon(m, ec_N, 21);
	bn_to_mon(e, ec_N, 21);
	bn_to_mon(R, ec_N, 21);
	bn_to_mon(kk, ec_N, 21);

	bn_mon_mul(S, R, kk, ec_N, 21);
	bn_add(kk, S, e, ec_N, 21);
	bn_mon_inv(minv, m, ec_N, 21);
	bn_mon_mul(S, minv, kk, ec_N, 21);

	bn_from_mon(R, ec_N, 21);
	bn_from_mon(S, ec_N, 21);
}

static int check_ecdsa(u8 *Q, u8 *R, u8 *S, u8 *hash)
{
	u8 Sinv[21];
	u8 e[21];
	u8 w1[20], w2[20];
	u8 r1[40], r2[40];
	u8 rr[21];

	e[0] = 0;
	memcpy(e + 1, hash, 20);

	bn_to_mon(R, ec_N, 21);
	bn_to_mon(S, ec_N, 21);
	bn_to_mon(e, ec_N, 21);

	bn_mon_inv(Sinv, S, ec_N, 21);

	bn_mon_mul(w1, e, Sinv, ec_N, 21);
	bn_mon_mul(w2, R, Sinv, ec_N, 21);

	bn_from_mon(w1, ec_N, 21);
	bn_from_mon(w2, ec_N, 21);

	point_mul(r1, w1, ec_G);
	point_mul(r2, w2, Q);

	point_add(r1, r1, r2);

	point_from_mon(r1);

	rr[0] = 0;
	memcpy(rr + 1, r1, 20);
	bn_reduce(rr, ec_N, 21);

	bn_from_mon(R, ec_N, 21);
	bn_from_mon(S, ec_N, 21);

	return (bn_compare(rr, R, 21) == 0);
}

#if 0
static void ec_priv_to_pub(u8 *k, u8 *Q)
{
	point_mul(Q, k, ec_G);
}
#endif

int ecdsa_set_curve(u32 type)
{
	u8 Gx[20], Gy[20];

	if (ecdsa_get_params(type, ec_p, ec_a, ec_b, ec_N, Gx, Gy) < 0)
		return -1;

	bn_to_mon(ec_a, ec_p, 20);
	bn_to_mon(ec_b, ec_p, 20);

	memcpy(ec_G, Gx, 20);
	memcpy(ec_G+20, Gy, 20);

	point_to_mon(ec_G);

	return 0;
}

void ecdsa_set_pub(u8 *Q)
{
	memcpy(ec_Q, Q, 40);
	point_to_mon(ec_Q);
}

void ecdsa_set_priv(u8 *k)
{
	memcpy(ec_k, k, sizeof ec_k);
}

int ecdsa_verify(u8 *hash, u8 *R, u8 *S)
{
	int bork = check_ecdsa(ec_Q, R, S, hash);
	return bork;
}

void ecdsa_sign(u8 *hash, u8 *R, u8 *S)
{
	generate_ecdsa(R, S, ec_k, hash);
}
