/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EXT_SECP256K1_H

#include "secp256k1.h"

bool hc_secp256k1_pubkey_parse     (secp256k1_pubkey *pubkey, u8 *buf, size_t length);
bool hc_secp256k1_pubkey_tweak_mul (secp256k1_pubkey  pubkey, u8 *buf, size_t length);

void hc_secp256k1_bignum_mod (const u8 *in, const u8 in_len, u8 *out, const u8 out_len);

#endif // _EXT_SECP256K1_H
