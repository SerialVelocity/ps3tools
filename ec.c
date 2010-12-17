// Copyright 2007,2008  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <string.h>
#include <stdio.h>

#include "tools.h"

static u8 ec_p[20];
static u8 ec_a[20];
static u8 ec_b[20];
static u8 ec_N[21];
static u8 ec_G[40];
static u8 ec_Q[40];
static u8 ec_k[21];

int ecdsa_set_curve(u32 type)
{
	u8 Gx[20], Gy[20];

	if (ecdsa_get_params(type, ec_p, ec_a, ec_b, ec_N, Gx, Gy) < 0)
		return -1;

	memcpy(ec_G, Gx, 20);
	memcpy(ec_G + 20, Gy, 20);

#if 0
	bn_invert(ec_p, ec_p, sizeof ec_p);
	bn_invert(ec_a, ec_a, sizeof ec_a);
	bn_invert(ec_b, ec_b, sizeof ec_b);
	bn_invert(ec_N, ec_N, sizeof ec_N);
	bn_invert(ec_G, ec_G, sizeof ec_G);
#endif

	return 0;
}

void ecdsa_set_pub(u8 *Q)
{
	memcpy(ec_Q, Q, sizeof ec_Q);
}

void ecdsa_set_priv(u8 *k)
{
	memcpy(ec_k, k, sizeof ec_k);
}

int ecdsa_verify(u8 *hash, u8 *r, u8 *s)
{
	return -1;
}

int ecdsa_sign(u8 *hash, u8 *r, u8 *s)
{
	return -1;
}
