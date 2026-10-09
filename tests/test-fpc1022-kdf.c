/*
 * FPC1022 (10a5:a920) KDF and TLS PSK Unit Tests
 *
 * Validates the NIST SP 800-108 counter mode KDF derivation,
 * HMAC signature verification, AES-256-CBC decryption, and
 * TLS 1.2 PSK client configuration for the FPC 10a5:a920 sensor.
 *
 * Copyright (c) 2026 Sergey Subbotin <ssubbotin@gmail.com>
 * Copyright (c) 2026 feraxhp <feraxhp+gh@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <glib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

#define FPC1022_TLS_KEY_MAGIC 0x0DEC0DED
#define FPC1022_TLS_PSK_SIZE  32

typedef struct __attribute__((packed))
{
  guint32 magic;
  guint32 key_offset;
  guint32 key_len;
  guint32 aad_offset;
  guint32 aad_len;
  guint32 sig_offset;
  guint32 sig_len;
} Fpc1022TlsKeyPkt;

/* Sealed TLS key packet sent to device (CMD_SET_TLS_KEY, 119 bytes) */
static const guint8 test_sealed_key_pkt[119] = {
  0xed, 0x0d, 0xec, 0x0d, 0x1c, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0x4c, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x57, 0x00, 0x00, 0x00,
  0x20, 0x00, 0x00, 0x00, 0xbd, 0xda, 0x29, 0xfc, 0xc0, 0x64, 0x48, 0xd1,
  0xca, 0x5a, 0xe7, 0xe1, 0x27, 0x7b, 0x65, 0xc6, 0x96, 0x76, 0xaa, 0xe4,
  0xfe, 0xca, 0xfa, 0x26, 0xba, 0xce, 0xbe, 0x80, 0x2b, 0xc8, 0xd6, 0x8d,
  0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x46, 0x50, 0x43, 0x5f, 0x4b, 0x45, 0x59, 0x5f,
  0x41, 0x41, 0x44, 0x6b, 0x48, 0x1b, 0xcd, 0x57, 0xb6, 0x32, 0x33, 0xb0,
  0xca, 0xaa, 0xf2, 0x54, 0x4a, 0x9b, 0x10, 0x20, 0xcb, 0xe1, 0xcb, 0x93,
  0x40, 0x74, 0x4c, 0x4a, 0x98, 0x09, 0xab, 0x64, 0xc6, 0x31, 0xf5
};

static const guint8 expected_psk[32] = {
  0x24, 0x55, 0xda, 0x35, 0x2c, 0xc5, 0xe4, 0xd1,
  0x16, 0x3c, 0x26, 0x13, 0x8e, 0x7b, 0xcd, 0x2c,
  0x57, 0xab, 0x29, 0x17, 0x91, 0x25, 0xbf, 0x98,
  0x82, 0x22, 0x3d, 0x81, 0x56, 0x0f, 0xf8, 0xbc
};

static int
test_sha256 (const void *data, gsize len, guint8 *out)
{
  unsigned int out_len = 0;
  return EVP_Digest (data, len, out, &out_len, EVP_sha256 (), NULL) && out_len == 32;
}

static int
test_hmac_sha256 (const guint8 *key, gsize key_len,
                  const guint8 *data, gsize data_len,
                  guint8 *out)
{
  EVP_MAC *mac = EVP_MAC_fetch (NULL, "HMAC", NULL);
  if (!mac)
    return 0;

  EVP_MAC_CTX *ctx = EVP_MAC_CTX_new (mac);
  if (!ctx)
    {
      EVP_MAC_free (mac);
      return 0;
    }

  char digest_name[] = "SHA256";
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string ("digest", digest_name, 0),
    OSSL_PARAM_construct_end ()
  };

  size_t out_len = 32;
  int ok = EVP_MAC_init (ctx, key, key_len, params) &&
           EVP_MAC_update (ctx, data, data_len) &&
           EVP_MAC_final (ctx, out, &out_len, 32) &&
           out_len == 32;

  EVP_MAC_CTX_free (ctx);
  EVP_MAC_free (mac);
  return ok;
}

static gboolean
derive_psk (const guint8 *data, gsize data_len, guint8 *psk_out)
{
  guint32 magic, key_offset, key_len, aad_offset, aad_len, sig_offset, sig_len;
  guint8 kdf_key[32];
  guint8 msg1[4 + 17 + 4];
  guint8 msg2[4 + 17 + 4];
  guint8 hmac_key[32];
  guint8 aes_key[32];
  guint8 iv_in[3 + 4];
  guint8 iv_full[32];
  guint8 sig_msg[13 + 32 + 11];
  guint8 comp_sig[32];
  EVP_CIPHER_CTX *ctx = NULL;
  int out_len = 0, final_len = 0;
  gboolean ok = FALSE;

  if (data_len < sizeof (Fpc1022TlsKeyPkt))
    return FALSE;

  Fpc1022TlsKeyPkt *pkt = (Fpc1022TlsKeyPkt *) data;
  magic = GUINT32_FROM_LE (pkt->magic);
  key_offset = GUINT32_FROM_LE (pkt->key_offset);
  key_len = GUINT32_FROM_LE (pkt->key_len);
  aad_offset = GUINT32_FROM_LE (pkt->aad_offset);
  aad_len = GUINT32_FROM_LE (pkt->aad_len);
  sig_offset = GUINT32_FROM_LE (pkt->sig_offset);
  sig_len = GUINT32_FROM_LE (pkt->sig_len);

  if (magic != FPC1022_TLS_KEY_MAGIC)
    return FALSE;

  if (aad_offset > data_len || aad_len > data_len - aad_offset ||
      key_offset > data_len || key_len > data_len - key_offset ||
      sig_offset > data_len || sig_len > data_len - sig_offset ||
      key_len != 32 || sig_len != 32 || aad_len != 11)
    return FALSE;

  if (memcmp (data + aad_offset, "FPC_KEY_AAD", 11) != 0)
    return FALSE;

  if (!test_sha256 ("FPC_SEALING_KEY", 16, kdf_key))
    return FALSE;

  msg1[0] = 0; msg1[1] = 0; msg1[2] = 0; msg1[3] = 1;
  memcpy (msg1 + 4, "application keys", 17);
  msg1[21] = 0; msg1[22] = 0; msg1[23] = 2; msg1[24] = 0;
  if (!test_hmac_sha256 (kdf_key, 32, msg1, sizeof (msg1), hmac_key))
    return FALSE;

  msg2[0] = 0; msg2[1] = 0; msg2[2] = 0; msg2[3] = 2;
  memcpy (msg2 + 4, "application keys", 17);
  msg2[21] = 0; msg2[22] = 0; msg2[23] = 2; msg2[24] = 0;
  if (!test_hmac_sha256 (kdf_key, 32, msg2, sizeof (msg2), aes_key))
    return FALSE;

  memcpy (sig_msg, "FPC_HMAC_KEY", 13);
  memcpy (sig_msg + 13, data + key_offset, 32);
  memcpy (sig_msg + 13 + 32, data + aad_offset, 11);
  if (!test_hmac_sha256 (hmac_key, 32, sig_msg, sizeof (sig_msg), comp_sig))
    return FALSE;

  if (CRYPTO_memcmp (comp_sig, data + sig_offset, 32) != 0)
    return FALSE;

  memcpy (iv_in, "iv", 3);
  iv_in[3] = 0x20; iv_in[4] = 0x20; iv_in[5] = 0xf0; iv_in[6] = 0x0d;
  if (!test_hmac_sha256 (hmac_key, 32, iv_in, sizeof (iv_in), iv_full))
    return FALSE;

  ctx = EVP_CIPHER_CTX_new ();
  if (!ctx)
    return FALSE;

  if (EVP_CipherInit_ex (ctx, EVP_aes_256_cbc (), NULL, aes_key, iv_full, 0) &&
      EVP_CIPHER_CTX_set_padding (ctx, 0) &&
      EVP_CipherUpdate (ctx, psk_out, &out_len, data + key_offset, 32) &&
      EVP_CipherFinal_ex (ctx, psk_out + out_len, &final_len))
    {
      ok = TRUE;
    }

  EVP_CIPHER_CTX_free (ctx);

  OPENSSL_cleanse (kdf_key, sizeof (kdf_key));
  OPENSSL_cleanse (hmac_key, sizeof (hmac_key));
  OPENSSL_cleanse (aes_key, sizeof (aes_key));
  OPENSSL_cleanse (iv_full, sizeof (iv_full));
  OPENSSL_cleanse (comp_sig, sizeof (comp_sig));

  return ok;
}

static void
test_key_packet_validation (void)
{
  guint8 psk[32];
  g_assert_true (derive_psk (test_sealed_key_pkt, sizeof (test_sealed_key_pkt), psk));
  g_assert_cmpmem (psk, 32, expected_psk, 32);
}

static void
test_key_packet_corrupt_magic (void)
{
  guint8 corrupt[sizeof (test_sealed_key_pkt)];
  guint8 psk[32];

  memcpy (corrupt, test_sealed_key_pkt, sizeof (corrupt));
  corrupt[0] = 0x00; /* invalidate magic */
  g_assert_false (derive_psk (corrupt, sizeof (corrupt), psk));
}

static void
test_key_packet_corrupt_signature (void)
{
  guint8 corrupt[sizeof (test_sealed_key_pkt)];
  guint8 psk[32];

  memcpy (corrupt, test_sealed_key_pkt, sizeof (corrupt));
  corrupt[118] ^= 0xff; /* flip bit in signature */
  g_assert_false (derive_psk (corrupt, sizeof (corrupt), psk));
}

static unsigned int
test_psk_client_cb (SSL *ssl, const char *hint, char *identity,
                    unsigned int max_identity_len, unsigned char *psk,
                    unsigned int max_psk_len)
{
  g_strlcpy (identity, "Disum PSK", max_identity_len);
  memcpy (psk, expected_psk, 32);
  return 32;
}

static void
test_tls_psk_client_hello (void)
{
  SSL_CTX *ctx = SSL_CTX_new (TLS_client_method ());
  g_assert_nonnull (ctx);

  SSL_CTX_set_min_proto_version (ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version (ctx, TLS1_2_VERSION);
  SSL_CTX_set_options (ctx, SSL_OP_NO_COMPRESSION);

  g_assert_true (SSL_CTX_set_cipher_list (ctx,
                                          "PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384:PSK-AES128-CBC-SHA256"));
  SSL_CTX_set_psk_client_callback (ctx, test_psk_client_cb);

  BIO *bio_in = BIO_new (BIO_s_mem ());
  BIO *bio_out = BIO_new (BIO_s_mem ());
  g_assert_nonnull (bio_in);
  g_assert_nonnull (bio_out);

  SSL *ssl = SSL_new (ctx);
  g_assert_nonnull (ssl);

  SSL_set_bio (ssl, bio_in, bio_out);
  SSL_set_connect_state (ssl);

  int ret = SSL_connect (ssl);
  g_assert_cmpint (ret, <=, 0);

  size_t pending = BIO_ctrl_pending (bio_out);
  g_assert_cmpuint (pending, >, 0);

  SSL_free (ssl);
  SSL_CTX_free (ctx);
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fpc1022/kdf/derivation", test_key_packet_validation);
  g_test_add_func ("/fpc1022/kdf/reject_corrupt_magic", test_key_packet_corrupt_magic);
  g_test_add_func ("/fpc1022/kdf/reject_corrupt_signature", test_key_packet_corrupt_signature);
  g_test_add_func ("/fpc1022/tls/client_hello", test_tls_psk_client_hello);
  return g_test_run ();
}
