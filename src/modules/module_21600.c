/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"
#include "emu_inc_hash_sha512.h"
#include "emu_inc_hash_sha256.h"
#include "emu_inc_cipher_aes.h"
#include "zlib.h"

#include "secp256k1.h"

// BIGNUM
#include <openssl/bn.h>

/*
// alternative to BIGNUM by using secp256k1_pubkey + gmplib:

#define HAVE___INT128
#include "util.h"

#define USE_NUM_GMP
#include "num_gmp_impl.h"

#define USE_SCALAR_4X64
#include "scalar.h"

#define USE_SCALAR_INV_NUM
#include "scalar_impl.h"
*/


static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_8_16;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_PASSWORD_MANAGER;
static const char *HASH_NAME      = "Electrum Wallet (Salt-Type 4-5)";
static const u64   KERN_TYPE      = 21600;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_HOOK23;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "btcr-test-password";
static const char *ST_HASH        = "$electrum$5*0328e536dd1fbbb85d78de1a8c21215d4646cd87d6b6545afcfb203e5bb32e0de4*61b1e287a5acff4b40e4abd73ff62dc233c1c7a6a54b3270949281b9d44bc6e746743733360500718826e50bb28ea99a6378dc0b0c578e9d0bf09c667671c82a1bd71c8121edbb4c9cbca93ab0e17e218558ead81755e62b0d4ad547aa1b3beb0b9ee43b11270261c9b38502f00e7f6f096811b7fdae6f3dce85c278d3751fec044027054218ccf20d404bab24380b303f094704e626348a218f44ab88ce2ac5fa7d450069fca3bb53f9359dbbaad0ea1b3859129b19c93ed7888130f8a534f84a629c67edc150a1c5882a83cb0add4615bb569e8dc471de4d38fc8b1e0b9b28040b5ea86093fcdeceaedb6b8f073f6f0ee5541f473a4b1c2bfae4fc91e4bbb40fa2185ecfa4c72010bcf8df05b1a7db45f64307dbc439f8389f0e368e38960b6d61ac88c07ce95a4b03d6d8b13f4c7dc7d7c447097865235ab621aeef38dc4172bf2dc52e701132480127be375fe98834f16d9895dce7f6cdfe900a2ce57eaa6c3036c1b9a661c3c9adbf84f4adfe6d4d9fa9f829f2957cfb353917dc77fd8dd4872b7d90cb71b7d3a29c9bfe3440e02449220acba410fa0af030f51aa2438f7478dbb277d62613112e4eebc66d5d7bdba793fb2073d449954f563284819189ffb5dbcdeb6c95c64bc24e0ef986bce07bafe96ab449ae2b6edaf4f98ffbd392a57bd93c2359444ec4046ae65b440adb96b6e4eef9d06bb04d2f3fa2e4175165bcadbf7e13cc3b6e65e67df901f96a2f154bc763b56b3736a335e1d1bc16e99736f757a4ae56c099645c917360b1ecf8dcefc7281541c6ff65d87cadab4a48f1f6b7b73a3e5a67e2e032abb56b499e73a9f3b69ce065e43b0174639785ae30635d105ebcc827dcf9b19bdd1a92879a5d4bc4e12b5630c188b1b96e3c586e19901b8f96084bcd59b2f4b201a3a8b6e633a5c194901d4609add9671b0bcc12b2b94ae873d201258b36315484e4b9c5f5d6289656baa93eec9e92aec88e2d73d86b9e3d1f24294e3d8ebe9a9f2f6edfbf28f530670c5b086fc4f74df89b4e4cbe06ee7e45cbd238b599d19c2d5da5523b12b1e7050ea0a9b47a5d22c6c3fc476f814f9705dc7ed3aeb1b44fc6b4d69f02a74963dce5057c3c049f92e595a4da5035cffc303a4cb162803aa3f816527a7e466b8424789a0d77e26819615662420c370457e29fcc1938fd754f3acfd21416ce3ab27e9febbc0e24fc7055eddc31e48faa014f9f3695c2e956f0e6c94c507a8d2f8c3aeb4b98b69b6340b6a3acb1acdde9581279f78ee10687616360c018e9f67d6c8bb5950e8fdabd3d0d5808824975aa4a50f88581472212f24ad58a700fe4787642b973924575fe71d1ecd7b2b6acd363f48c40bdd55f35f60a06dee544c266e608fd5a6d263f745e8b11d1160638eb301adfd1a88eddf6d0ccb9e1021e0bde9cf5163583a202b3dc95c255c8cc24*ec90c1ff54632e7c8cfb812eeb14d7ec49ddaf576dca10bfb16f965e6106ce48";

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

typedef struct electrum_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[8];
  u64  out[8];

} electrum_tmp_t;

typedef struct
{
  u64 ukey[8];

  u32 hook_success;

} electrum_hook_t;

typedef struct electrum_hook_salt
{
  u32 version;

  u32 data_len;

  u32 data_buf[4096];

  u32 mac[8];

  u8 ephemeral_pubkey_raw[33];

  secp256k1_pubkey ephemeral_pubkey_struct;

} electrum_hook_salt_t;

static const char *SIGNATURE_ELECTRUM = "$electrum$";

void module_hook23 (hc_device_param_t *device_param, const void *hook_salts_buf, const u32 salt_pos, const u64 pw_pos)
{
  electrum_hook_t *hook_items = (electrum_hook_t *) device_param->hooks_buf;

  electrum_hook_salt_t *electrums = (electrum_hook_salt_t *) hook_salts_buf;
  electrum_hook_salt_t *electrum  = &electrums[salt_pos];

  u32  version  = electrum->version;
  u32  data_len = electrum->data_len;

  u32 *data_buf = electrum->data_buf;
  u32 *mac      = electrum->mac;

  secp256k1_pubkey ephemeral_pubkey = electrum->ephemeral_pubkey_struct;

  // this hook data needs to be updated (the "hook_success" variable):

  electrum_hook_t *hook_item = &hook_items[pw_pos];

  const u64 *ukey_64 = (const u64 *) hook_item->ukey;

  u32 ukey[16];

  ukey[ 0] = v32b_from_v64 (ukey_64[0]);
  ukey[ 1] = v32a_from_v64 (ukey_64[0]);
  ukey[ 2] = v32b_from_v64 (ukey_64[1]);
  ukey[ 3] = v32a_from_v64 (ukey_64[1]);

  ukey[ 4] = v32b_from_v64 (ukey_64[2]);
  ukey[ 5] = v32a_from_v64 (ukey_64[2]);
  ukey[ 6] = v32b_from_v64 (ukey_64[3]);
  ukey[ 7] = v32a_from_v64 (ukey_64[3]);

  ukey[ 8] = v32b_from_v64 (ukey_64[4]);
  ukey[ 9] = v32a_from_v64 (ukey_64[4]);
  ukey[10] = v32b_from_v64 (ukey_64[5]);
  ukey[11] = v32a_from_v64 (ukey_64[5]);

  ukey[12] = v32b_from_v64 (ukey_64[6]);
  ukey[13] = v32a_from_v64 (ukey_64[6]);
  ukey[14] = v32b_from_v64 (ukey_64[7]);
  ukey[15] = v32a_from_v64 (ukey_64[7]);

  ukey[ 0] = byte_swap_32 (ukey[ 0]);
  ukey[ 1] = byte_swap_32 (ukey[ 1]);
  ukey[ 2] = byte_swap_32 (ukey[ 2]);
  ukey[ 3] = byte_swap_32 (ukey[ 3]);

  ukey[ 4] = byte_swap_32 (ukey[ 4]);
  ukey[ 5] = byte_swap_32 (ukey[ 5]);
  ukey[ 6] = byte_swap_32 (ukey[ 6]);
  ukey[ 7] = byte_swap_32 (ukey[ 7]);

  ukey[ 8] = byte_swap_32 (ukey[ 8]);
  ukey[ 9] = byte_swap_32 (ukey[ 9]);
  ukey[10] = byte_swap_32 (ukey[10]);
  ukey[11] = byte_swap_32 (ukey[11]);

  ukey[12] = byte_swap_32 (ukey[12]);
  ukey[13] = byte_swap_32 (ukey[13]);
  ukey[14] = byte_swap_32 (ukey[14]);
  ukey[15] = byte_swap_32 (ukey[15]);

  /*
   * Start with ECC
   */

  const u8 *ukey_ptr = (const u8 *) ukey;

  BIGNUM *p = BN_bin2bn (ukey_ptr, 64, NULL);

  // secp256k1_ecdsa_const_order_as_fe / secp256k1_scalar_order_get_num (&order):

  static const char *group_order = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

  BIGNUM *q = BN_new ();
  BN_hex2bn (&q, group_order);

  BN_CTX *ctx = BN_CTX_new ();
  BIGNUM *r = BN_new ();
  BN_mod (r, p, q, ctx);
  BN_CTX_free (ctx);

  BN_free (p);
  BN_free (q);

  unsigned char tmp_buf[33 + 3]; // +3 (instead of +1) to make it a multiple of 4

  memset (tmp_buf, 0, sizeof (tmp_buf));

  BN_bn2bin (r, tmp_buf);
  BN_free (r);


  /*
   * Alternative: use secp256k1 function with gmplib instead of BIGNUM from OpenSSL
   */

  /*

  // group order:

  secp256k1_num order;

  secp256k1_scalar_order_get_num (&order);


  secp256k1_num mod;

  secp256k1_num_set_bin (&mod, ukey_ptr, 64);


  // the actual modulo operation:

  secp256k1_num_mod (&mod, &order);


  // to binary conversion:

  unsigned char tmp_buf[33 + 3]; // +3 (instead of +1) to make it a multiple of 4

  memset (tmp_buf, 0, sizeof (tmp_buf));

  secp256k1_num_get_bin (tmp_buf, 32, &mod);

  */

  /*
   * /END of secp256k1 alternative
   */

  // we need to copy it because the secp256k1_ec_pubkey_tweak_mul () function has side effects

  secp256k1_pubkey pubkey = ephemeral_pubkey; // the copy of the struct is enough (shallow copy)

  secp256k1_context *sctx = secp256k1_context_create (SECP256K1_CONTEXT_VERIFY);

  if (secp256k1_ec_pubkey_tweak_mul (sctx, &pubkey, tmp_buf) == 0) return;

  size_t length = 33;

  secp256k1_ec_pubkey_serialize (sctx, tmp_buf, &length, &pubkey, SECP256K1_EC_COMPRESSED);
  secp256k1_context_destroy (sctx);

  u32 input[64];

  memset (input, 0, sizeof (input));

  u32 *output_ptr = (u32 *) tmp_buf;

  for (size_t z = 0; z < sizeof (tmp_buf) / 4; z++)
  {
    input[z] = byte_swap_32 (output_ptr[z]);
  }

  sha512_ctx_t sha512_ctx;

  sha512_init   (&sha512_ctx);
  sha512_update (&sha512_ctx, input, length);
  sha512_final  (&sha512_ctx);

  // ... now we have the result in sha512_ctx.h[0]...sha512_ctx.h[7]

  // distinguish between salt type 4 (mac verify) and salt type 5 (decrypt and decompress):

  if (version == 4)
  {
    u32 hmac_key[16];

    memset (hmac_key, 0, 64);

    hmac_key[0] = v32b_from_v64 (sha512_ctx.h[4]);
    hmac_key[1] = v32a_from_v64 (sha512_ctx.h[4]);

    hmac_key[2] = v32b_from_v64 (sha512_ctx.h[5]);
    hmac_key[3] = v32a_from_v64 (sha512_ctx.h[5]);

    hmac_key[4] = v32b_from_v64 (sha512_ctx.h[6]);
    hmac_key[5] = v32a_from_v64 (sha512_ctx.h[6]);

    hmac_key[6] = v32b_from_v64 (sha512_ctx.h[7]);
    hmac_key[7] = v32a_from_v64 (sha512_ctx.h[7]);

    sha256_hmac_ctx_t sha256_ctx;

    sha256_hmac_init (&sha256_ctx, hmac_key, 32);

    sha256_hmac_update_swap (&sha256_ctx, data_buf, data_len);

    sha256_hmac_final (&sha256_ctx);

    if ((mac[0] == sha256_ctx.opad.h[0]) &&
        (mac[1] == sha256_ctx.opad.h[1]) &&
        (mac[2] == sha256_ctx.opad.h[2]) &&
        (mac[3] == sha256_ctx.opad.h[3]))
    {
      hook_item->hook_success = 1;
    }
  }
  else // if (version == 5)
  {
    u32 iv[4];

    iv[0] = v32b_from_v64 (sha512_ctx.h[0]);
    iv[1] = v32a_from_v64 (sha512_ctx.h[0]);
    iv[2] = v32b_from_v64 (sha512_ctx.h[1]);
    iv[3] = v32a_from_v64 (sha512_ctx.h[1]);

    iv[0] = byte_swap_32 (iv[0]);
    iv[1] = byte_swap_32 (iv[1]);
    iv[2] = byte_swap_32 (iv[2]);
    iv[3] = byte_swap_32 (iv[3]);

    u32 key[4];

    key[0] = v32b_from_v64 (sha512_ctx.h[2]);
    key[1] = v32a_from_v64 (sha512_ctx.h[2]);
    key[2] = v32b_from_v64 (sha512_ctx.h[3]);
    key[3] = v32a_from_v64 (sha512_ctx.h[3]);

    key[0] = byte_swap_32 (key[0]);
    key[1] = byte_swap_32 (key[1]);
    key[2] = byte_swap_32 (key[2]);
    key[3] = byte_swap_32 (key[3]);

    // init AES

    AES_KEY aes_key;

    memset (&aes_key, 0, sizeof (aes_key));

    aes128_set_decrypt_key (aes_key.rdk, key, (u32 *) te0, (u32 *) te1, (u32 *) te2, (u32 *) te3, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3);

    int aes_len = 1024; // in my tests (very few) it also worked with only 128 input bytes !
    // int aes_len = 128;

    u32 data[4];
    u32 out[4];

    u32 out_full[256]; // 1024 / 4

    // we need to run it at least once:

    data[0] = data_buf[0];
    data[1] = data_buf[1];
    data[2] = data_buf[2];
    data[3] = data_buf[3];

    aes128_decrypt (aes_key.rdk, data, out, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3, (u32 *) td4);

    out[0] ^= iv[0];

    // early reject

    if ((out[0] & 0x0007ffff) != 0x00059c78) return;

    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    out_full[0] = out[0];
    out_full[1] = out[1];
    out_full[2] = out[2];
    out_full[3] = out[3];

    iv[0] = data[0];
    iv[1] = data[1];
    iv[2] = data[2];
    iv[3] = data[3];

    // for aes_len > 16 we need to loop

    for (int i = 16, j = 4; i < aes_len; i += 16, j += 4)
    {
      data[0] = data_buf[j + 0];
      data[1] = data_buf[j + 1];
      data[2] = data_buf[j + 2];
      data[3] = data_buf[j + 3];

      aes128_decrypt (aes_key.rdk, data, out, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3, (u32 *) td4);

      out[0] ^= iv[0];
      out[1] ^= iv[1];
      out[2] ^= iv[2];
      out[3] ^= iv[3];

      iv[0] = data[0];
      iv[1] = data[1];
      iv[2] = data[2];
      iv[3] = data[3];

      out_full[j + 0] = out[0];
      out_full[j + 1] = out[1];
      out_full[j + 2] = out[2];
      out_full[j + 3] = out[3];
    }

    // decompress with zlib:

    size_t  compressed_data_len   = aes_len;
    u8     *compressed_data       = (u8 *) out_full;

    size_t  decompressed_data_len = 16; // we do NOT need more than first bytes for validation
    u8     *decompressed_data     = (unsigned char *) hcmalloc (decompressed_data_len);

    z_stream inf;

    inf.zalloc = Z_NULL;
    inf.zfree  = Z_NULL;
    inf.opaque = Z_NULL;

    inf.next_in   = compressed_data;
    inf.avail_in  = compressed_data_len;

    inf.next_out  = decompressed_data;
    inf.avail_out = decompressed_data_len;

    // inflate:

    inflateInit2 (&inf, MAX_WBITS);

    int zlib_ret = inflate (&inf, Z_NO_FLUSH);

    inflateEnd (&inf);

    if ((zlib_ret != Z_OK) && (zlib_ret != Z_STREAM_END))
    {
      hcfree (decompressed_data);

      return;
    }

    if ((memcmp (decompressed_data, "{\n    \"",   7) == 0) ||
        (memcmp (decompressed_data, "{\r\n    \"", 8) == 0))
    {
      hook_item->hook_success = 1;
    }

    hcfree (decompressed_data);
  }
}

u64 module_hook_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 hook_size = (const u64) sizeof (electrum_hook_t);

  return hook_size;
}

u64 module_hook_salt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 hook_salt_size = (const u64) sizeof (electrum_hook_salt_t);

  return hook_salt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (electrum_tmp_t);

  return tmp_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = PW_MAX;

  return pw_max;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  hc_asprintf (&jit_build_options, "-D NO_UNROLL");

  return jit_build_options;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  electrum_hook_salt_t *electrum = (electrum_hook_salt_t *) hook_salt_buf;

  token_t token;

  token.token_cnt  = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ELECTRUM;

  token.len[0]     = 10;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = 66;
  token.len_max[2] = 66;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';
  token.len_min[3] = 128;
  token.len_max[3] = 32768;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '*';
  token.len_min[4] = 64;
  token.len_max[4] = 64;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *version_pos   = token.buf[1];
  const u8 *ephemeral_pos = token.buf[2];
  const u8 *data_buf_pos  = token.buf[3];
  const u8 *mac_pos       = token.buf[4];

  const u32 version = hc_strtoul ((const char *) version_pos, NULL, 10);

  const u32 data_len = token.len[3] / 2;

  /**
   * verify the version number
   */

  if ((version != 4) && (version != 5))
  {
    return (PARSER_SALT_VALUE);
  }

  /**
   * version 5 should be always 1024 raw bytes
   */

  if (version == 5)
  {
    if (data_len != 1024)
    {
      return (PARSER_SALT_VALUE);
    }
  }

  /**
   * store data
   */

  // version:

  electrum->data_len = data_len;

  // version:

  electrum->version = version;

  // ephemeral pubkey:

  for (u32 i = 0, j = 0; j < 66; i += 1, j += 2)
  {
    electrum->ephemeral_pubkey_raw[i] = hex_to_u8 (ephemeral_pos + j);
  }

  secp256k1_context *t_ctx = secp256k1_context_create (SECP256K1_CONTEXT_NONE);

  size_t length = 33;

  if (secp256k1_ec_pubkey_parse (t_ctx, &electrum->ephemeral_pubkey_struct, electrum->ephemeral_pubkey_raw, length) == 0)
  {
    secp256k1_context_destroy (t_ctx);

    return (PARSER_SALT_VALUE);
  }

  secp256k1_context_destroy (t_ctx);

  // data buf:

  u8* data_buf_ptr = (u8 *) electrum->data_buf;

  for (u32 i = 0, j = 0; j < data_len * 2; i += 1, j += 2)
  {
    data_buf_ptr[i] = hex_to_u8 (data_buf_pos + j);
  }

  // mac:

  for (u32 i = 0, j = 0; j < 64; i += 1, j += 8)
  {
    electrum->mac[i] = hex_to_u32 (mac_pos + j);

    electrum->mac[i] = byte_swap_32 (electrum->mac[i]);
  }

  // fake salt

  salt->salt_buf[0] = electrum->data_buf[0];
  salt->salt_buf[1] = electrum->data_buf[1];
  salt->salt_buf[2] = electrum->data_buf[2];
  salt->salt_buf[3] = electrum->data_buf[3];

  salt->salt_len = 16;

  salt->salt_iter = 1024 - 1;

  /**
   * fake digest
   */

  digest[0] = electrum->mac[0];
  digest[1] = electrum->mac[1];
  digest[2] = electrum->mac[2];
  digest[3] = electrum->mac[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  electrum_hook_salt_t *electrum = (electrum_hook_salt_t *) hook_salt_buf;

  // ephemeral pubkey:

  char ephemeral[66 + 1];

  memset (ephemeral, 0, sizeof (ephemeral));

  for (u32 i = 0, j = 0; i < 33; i += 1, j += 2)
  {
    const u8 *ptr = (const u8 *) electrum->ephemeral_pubkey_raw;

    snprintf (ephemeral + j, 66 + 1 - j, "%02x", ptr[i]);
  }

  // data buf:

  char data_buf[32768 + 1];

  memset (data_buf, 0, sizeof (data_buf));

  for (u32 i = 0, j = 0; i < electrum->data_len; i += 1, j += 2)
  {
    const u8 *ptr = (const u8 *) electrum->data_buf;

    snprintf (data_buf + j, 32768 + 1 - j, "%02x", ptr[i]);
  }

  // mac:

  char mac[64 + 1];

  memset (mac, 0, sizeof (mac));

  for (u32 i = 0, j = 0; i < 8; i += 1, j += 8)
  {
    const u32 *ptr = (const u32 *) electrum->mac;

    snprintf (mac + j, 64 + 1 - j, "%08x", ptr[i]);
  }

  int bytes_written = snprintf (line_buf, line_size, "%s%u*%s*%s*%s",
    SIGNATURE_ELECTRUM,
    electrum->version,
    ephemeral,
    data_buf,
    mac);

  return bytes_written;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
  module_ctx->module_esalt_size               = MODULE_DEFAULT;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = module_hook23;
  module_ctx->module_hook_salt_size           = module_hook_salt_size;
  module_ctx->module_hook_size                = module_hook_size;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
