// Copyright 2007,2008,2010  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <string.h>
#include <stdio.h>

#include "tools.h"

void bn_print(char *name, u8 *a, u32 n)
{
	u32 i;

	printf("%s = ", name);

	for (i = 0; i < n; i++)
		printf("%02x", a[i]);

	printf("\n");
}

static void bn_zero(u8 *d, u32 n)
{
	memset(d, 0, n);
}

void bn_copy(u8 *d, u8 *a, u32 n)
{
	memcpy(d, a, n);
}

int bn_compare(u8 *a, u8 *b, u32 n)
{
	u32 i;

	for (i = 0; i < n; i++) {
		if (a[i] < b[i])
			return -1;
		if (a[i] > b[i])
			return 1;
	}

	return 0;
}

static u8 bn_add_1(u8 *d, u8 *a, u8 *b, u32 n)
{
	u32 i;
	u32 dig;
	u8 c;

	c = 0;
	for (i = n - 1; i < n; i--) {
		dig = a[i] + b[i] + c;
		c = dig >> 8;
		d[i] = dig;
	}

	return c;
}

static u8 bn_sub_1(u8 *d, u8 *a, u8 *b, u32 n)
{
	u32 i;
	u32 dig;
	u8 c;

	c = 1;
	for (i = n - 1; i < n; i--) {
		dig = a[i] + 255 - b[i] + c;
		c = dig >> 8;
		d[i] = dig;
	}

	return 1 - c;
}

void bn_add(u8 *d, u8 *a, u8 *b, u8 *N, u32 n)
{
	if (bn_add_1(d, a, b, n))
		bn_sub_1(d, d, N, n);

	bn_reduce(d, N, n);
}

void bn_sub(u8 *d, u8 *a, u8 *b, u8 *N, u32 n)
{
	if (bn_sub_1(d, a, b, n))
		bn_add_1(d, d, N, n);
}

void bn_reduce(u8 *d, u8 *N, u32 n)
{
	if (bn_compare(d, N, n) >= 0)
		bn_sub_1(d, d, N, n);
}

static u8 bn_muladd_dig(u8 *d, u8 *a, u8 b, u32 n)
{
	u32 dig;
	u32 i;

	dig = 0;
	for (i = n - 1; i < n; i--) {
		dig += d[i] + a[i]*b;
		d[i] = dig;
		dig >>= 8;
	}

	return dig;
}

static void bn_reduce_extra_dig(u8 dig, u8 *d, u8 Np[8][256], u8 Nd[8], u32 n)
{
	u32 i;

	for (i = 7; i < 8; i--) {
		if (dig > Nd[i] ||
		    (dig == Nd[i] && bn_compare(d, Np[i], n) >= 0))
			dig -= Nd[i] + bn_sub_1(d, d, Np[i], n);
	}
}

void bn_mul(u8 *d, u8 *a, u8 *b, u8 *N, u32 n)
{
	u8 Np[8][256];
	u8 Nd[8];
	u32 i;

	Nd[0] = 0;
	bn_copy(Np[0], N, n);
	for (i = 0; i < 7; i++)
		Nd[i+1] = 2*Nd[i] + bn_add_1(Np[i+1], Np[i], Np[i], n);

	bn_zero(d, n);
	for (i = 0; i < n; i++) {
		u8 bd = d[0];
		memcpy(d, d+1, n-1);
		d[n-1] = 0;
		bn_reduce_extra_dig(bd, d, Np, Nd, n);

		bd = bn_muladd_dig(d, b, a[i], n);
		bn_reduce_extra_dig(bd, d, Np, Nd, n);
	}
}

void bn_exp(u8 *d, u8 *a, u8 *N, u32 n, u8 *e, u32 en)
{
	u8 t[512];
	u32 i;
	u8 mask;

	bn_zero(d, n);
	d[n-1] = 1;
	for (i = 0; i < en; i++)
		for (mask = 0x80; mask != 0; mask >>= 1) {
			bn_mul(t, d, d, N, n);
			if ((e[i] & mask) != 0)
				bn_mul(d, t, a, N, n);
			else
				bn_copy(d, t, n);
		}
}

// only for prime N -- stupid but lazy, see if I care
void bn_inv(u8 *d, u8 *a, u8 *N, u32 n)
{
	u8 t[512], s[512];

	bn_zero(s, n);
	s[n-1] = 2;
	bn_sub_1(t, N, s, n);
	bn_exp(d, a, N, n, t, n);
}
