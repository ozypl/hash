/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "types.h"
#include "common.h"

#include "ext_secp256k1.h"

#if !defined (WITH_LIBSECP256K1)

#if !defined (WITH_GMPLIB)
#include "mini-gmp.h"
#include "mini-gmp.c"
#else
#include "gmp.h"
#endif

#define USE_NUM_NONE

//#define HAVE___INT128

#define USE_SCALAR_8X32
#define USE_SCALAR_INV_BUILTIN

#define USE_FIELD_10X26
#define USE_FIELD_INV_BUILTIN

#define ECMULT_WINDOW_SIZE   15
#define ECMULT_GEN_PREC_BITS  4

#include "secp256k1.c"

#endif

bool hc_secp256k1_pubkey_parse (secp256k1_pubkey *pubkey, u8 *buf, size_t length)
{
  secp256k1_context *t_ctx = secp256k1_context_create (SECP256K1_CONTEXT_NONE);

  if (secp256k1_ec_pubkey_parse (t_ctx, pubkey, buf, length) == 0)
  {
    secp256k1_context_destroy (t_ctx);

    return false;
  }

  secp256k1_context_destroy (t_ctx);

  return true;
}

bool hc_secp256k1_pubkey_tweak_mul (secp256k1_pubkey pubkey, u8 *buf, size_t length)
{
  secp256k1_context *sctx = secp256k1_context_create (SECP256K1_CONTEXT_VERIFY);

  if (secp256k1_ec_pubkey_tweak_mul (sctx, &pubkey, buf) == 0) return false;

  secp256k1_ec_pubkey_serialize (sctx, buf, &length, &pubkey, SECP256K1_EC_COMPRESSED);

  secp256k1_context_destroy (sctx);

  return true;
}

#if !defined (WITH_LIBSECP256K1)
void hc_secp256k1_bignum_mod (const u8 *in, const u8 in_len, u8 *out, const u8 out_len)
{
  // divisor:

  mpz_t d;
  mpz_init (d);

  u32 group_order[8];

  group_order[0] = 0xffffffff;
  group_order[1] = 0xffffffff;
  group_order[2] = 0xffffffff;
  group_order[3] = 0xfeffffff;

  group_order[4] = 0xe6dcaeba;
  group_order[5] = 0x3ba048af;
  group_order[6] = 0x8c5ed2bf;
  group_order[7] = 0x414136d0;

  mpz_import (d, out_len, 1, 1, 0, 0, group_order);

  // or use:
  // mpz_init_set_str (d, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);


  // divident:

  mpz_t n;
  mpz_init (n);

  mpz_import (n, in_len, 1, 1, 0, 0, in);


  // remainder:

  mpz_t r;
  mpz_init (r);

  mpz_mod (r, n, d);


  // mpz_t to binary:

  size_t export_len = 0;

  mpz_export (out, &export_len, 1, 1, 0, 0, r);

  // or mpz_export (out, NULL, 1, out_len, 1, 0, r) with much larger out buffer

  mpz_clear (r);
  mpz_clear (n);
  mpz_clear (d);


  // fix the out buffer to make it exactly 32 bytes

  for (size_t i = export_len; i < (size_t) out_len; i++)
  {
    for (int j = out_len - 1; j > 0; j--)
    {
      out[j] = out[j - 1];
    }

    out[0] = 0;

    export_len++;
  }
}

// BTW: there are other alternatives too e.g. using BN_mod () from OpenSSL
// (but we would need to compile/link OpenSSL in that case)

#else
// Alternative by using secp256k1_scalar_order_get_num () and secp256k1_scalar_order_get_num () with GMPLIB:

#include "util.h"

#define USE_NUM_GMP
#include "num_gmp_impl.h"

#define USE_SCALAR_8X32
#include "scalar.h"

#define USE_SCALAR_INV_BUILTIN
#include "scalar_impl.h"

void hc_secp256k1_bignum_mod (const u8 *in, const u8 in_len, u8 *out, const u8 out_len)
{
  secp256k1_num num;

  secp256k1_num_set_bin (&num, in, in_len);


  // group order:

  secp256k1_num order;

  secp256k1_scalar_order_get_num (&order);


  // the actual modulo operation:

  secp256k1_num_mod (&num, &order);


  // to binary conversion:

  secp256k1_num_get_bin (out, out_len, &num);
}
#endif

/*
// Another possibility would be to NOT have libsecp256k1 installed, but have gmplib fully compiled
// (not mini-gmp) in deps/gmp/
// => use USE_NUM_GMP in libsecp256k1

#if !defined (WITH_GMPLIB)
#if !defined (WITH_LIBSECP256K1)
// #define HAVE___INT128
#include "util.h"

#define USE_NUM_GMP
#include "num_gmp_impl.h"

#define USE_SCALAR_8X32
#include "scalar.h"

#define USE_SCALAR_INV_BUILTIN
#include "scalar_impl.h"

#define USE_FIELD_10X26
#define USE_FIELD_INV_NUM

#define ECMULT_WINDOW_SIZE   15
#define ECMULT_GEN_PREC_BITS  4

#include "secp256k1.c"
#endif

// => after this we call the libsecp256k1 compatible function with secp256k1_num_mod ()
*/
