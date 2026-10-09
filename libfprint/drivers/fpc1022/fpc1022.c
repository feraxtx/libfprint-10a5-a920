/*
 * FPC1022 driver for libfprint
 *
 * Supports FPC USB fingerprint sensors (10a5:a920).
 *
 * Copyright (c) 2026 Sergey Subbotin <ssubbotin@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "drivers_api.h"
#include "fpc1022.h"
#include "fpi-image.h"

#include <openssl/err.h>
#include <openssl/core_names.h>

#define FP_COMPONENT "fpc1022"

G_DEFINE_TYPE (FpiDeviceFpc1022, fpi_device_fpc1022, FP_TYPE_IMAGE_DEVICE);

static const FpIdEntry id_table[] = {
  { .vid = 0x10A5, .pid = 0xA920 },
  { .vid = 0,      .pid = 0      },
};

/* Sealed TLS key packet sent to device (CMD_SET_TLS_KEY, 119 bytes) */
static const guint8 fpc1022_sealed_key_pkt[119] = {
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

/* Nearest-neighbor 2x upscale: 64x176 -> 128x352 */
static FpImage *
fpc1022_scale_nn_2x (FpImage *src)
{
  int sw = src->width * 2;
  int sh = src->height * 2;
  FpImage *dst = fp_image_new (sw, sh);
  int x, y;

  for (y = 0; y < sh; y++)
    for (x = 0; x < sw; x++)
      dst->data[y * sw + x] = src->data[(y / 2) * src->width + (x / 2)];

  dst->flags = src->flags;
  dst->ppmm = src->ppmm;
  return dst;
}

/* ---- Cryptographic Helpers ---- */

static int
fpc1022_sha256 (const void *data, gsize len, guint8 *out)
{
  unsigned int out_len = 0;
  return EVP_Digest (data, len, out, &out_len, EVP_sha256 (), NULL) && out_len == 32;
}

static int
fpc1022_hmac_sha256 (const guint8 *key, gsize key_len,
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

/* Parse sealed key packet, verify HMAC signature, and decrypt AES-256-CBC PSK */
static gboolean
fpc1022_process_tls_key_packet (FpiDeviceFpc1022 *self,
                                const guint8 *data,
                                gsize data_len)
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
    {
      fp_err ("TLS key packet too short: %" G_GSIZE_FORMAT, data_len);
      return FALSE;
    }

  Fpc1022TlsKeyPkt *pkt = (Fpc1022TlsKeyPkt *) data;
  magic = GUINT32_FROM_LE (pkt->magic);
  key_offset = GUINT32_FROM_LE (pkt->key_offset);
  key_len = GUINT32_FROM_LE (pkt->key_len);
  aad_offset = GUINT32_FROM_LE (pkt->aad_offset);
  aad_len = GUINT32_FROM_LE (pkt->aad_len);
  sig_offset = GUINT32_FROM_LE (pkt->sig_offset);
  sig_len = GUINT32_FROM_LE (pkt->sig_len);

  if (magic != FPC1022_TLS_KEY_MAGIC)
    {
      fp_err ("TLS key packet invalid magic: 0x%08x", magic);
      return FALSE;
    }

  if (aad_offset > data_len || aad_len > data_len - aad_offset ||
      key_offset > data_len || key_len > data_len - key_offset ||
      sig_offset > data_len || sig_len > data_len - sig_offset ||
      key_len != 32 || sig_len != 32 || aad_len != 11)
    {
      fp_err ("TLS key packet bounds error");
      return FALSE;
    }

  if (memcmp (data + aad_offset, "FPC_KEY_AAD", 11) != 0)
    {
      fp_err ("TLS key packet unexpected AAD");
      return FALSE;
    }

  /* KDF key = SHA256("FPC_SEALING_KEY\0") */
  if (!fpc1022_sha256 ("FPC_SEALING_KEY", 16, kdf_key))
    return FALSE;

  /* NIST SP 800-108 Counter Mode KDF */
  msg1[0] = 0; msg1[1] = 0; msg1[2] = 0; msg1[3] = 1;
  memcpy (msg1 + 4, "application keys", 17);
  msg1[21] = 0; msg1[22] = 0; msg1[23] = 2; msg1[24] = 0; /* 512 bits */
  if (!fpc1022_hmac_sha256 (kdf_key, 32, msg1, sizeof (msg1), hmac_key))
    return FALSE;

  msg2[0] = 0; msg2[1] = 0; msg2[2] = 0; msg2[3] = 2;
  memcpy (msg2 + 4, "application keys", 17);
  msg2[21] = 0; msg2[22] = 0; msg2[23] = 2; msg2[24] = 0;
  if (!fpc1022_hmac_sha256 (kdf_key, 32, msg2, sizeof (msg2), aes_key))
    return FALSE;

  /* Verify HMAC signature: HMAC_SHA256(hmac_key, "FPC_HMAC_KEY\0" || key || aad) */
  memcpy (sig_msg, "FPC_HMAC_KEY", 13);
  memcpy (sig_msg + 13, data + key_offset, 32);
  memcpy (sig_msg + 13 + 32, data + aad_offset, 11);
  if (!fpc1022_hmac_sha256 (hmac_key, 32, sig_msg, sizeof (sig_msg), comp_sig))
    return FALSE;

  if (CRYPTO_memcmp (comp_sig, data + sig_offset, 32) != 0)
    {
      fp_err ("TLS key signature verification failed");
      return FALSE;
    }

  /* Derive IV: HMAC_SHA256(hmac_key, "iv\0" || 0x2020f00d)[:16] */
  memcpy (iv_in, "iv", 3);
  iv_in[3] = 0x20; iv_in[4] = 0x20; iv_in[5] = 0xf0; iv_in[6] = 0x0d;
  if (!fpc1022_hmac_sha256 (hmac_key, 32, iv_in, sizeof (iv_in), iv_full))
    return FALSE;

  /* Decrypt sealed key with AES-256-CBC */
  ctx = EVP_CIPHER_CTX_new ();
  if (!ctx)
    return FALSE;

  if (EVP_CipherInit_ex (ctx, EVP_aes_256_cbc (), NULL, aes_key, iv_full, 0) &&
      EVP_CIPHER_CTX_set_padding (ctx, 0) &&
      EVP_CipherUpdate (ctx, self->tls_psk, &out_len, data + key_offset, 32) &&
      EVP_CipherFinal_ex (ctx, self->tls_psk + out_len, &final_len))
    {
      ok = TRUE;
      fp_dbg ("Successfully derived and decrypted TLS PSK (%d bytes)", out_len + final_len);
    }
  else
    {
      fp_err ("AES-256-CBC decryption failed");
    }

  EVP_CIPHER_CTX_free (ctx);

  /* Securely wipe temporary cryptographic key material from stack */
  OPENSSL_cleanse (kdf_key, sizeof (kdf_key));
  OPENSSL_cleanse (msg1, sizeof (msg1));
  OPENSSL_cleanse (msg2, sizeof (msg2));
  OPENSSL_cleanse (hmac_key, sizeof (hmac_key));
  OPENSSL_cleanse (aes_key, sizeof (aes_key));
  OPENSSL_cleanse (iv_in, sizeof (iv_in));
  OPENSSL_cleanse (iv_full, sizeof (iv_full));
  OPENSSL_cleanse (sig_msg, sizeof (sig_msg));
  OPENSSL_cleanse (comp_sig, sizeof (comp_sig));

  return ok;
}

/* OpenSSL PSK client callback returning "Disum PSK" identity and key */
static unsigned int
fpc1022_psk_client_cb (SSL *ssl,
                       const char *hint,
                       char *identity,
                       unsigned int max_identity_len,
                       unsigned char *psk,
                       unsigned int max_psk_len)
{
  FpiDeviceFpc1022 *self = SSL_get_app_data (ssl);
  const char *id = "Disum PSK";

  fp_dbg ("PSK client callback invoked (hint: %s)", hint ? hint : "(null)");

  g_strlcpy (identity, id, max_identity_len);
  if (sizeof (self->tls_psk) > max_psk_len)
    {
      fp_err ("max_psk_len (%u) too small for PSK", max_psk_len);
      return 0;
    }

  memcpy (psk, self->tls_psk, sizeof (self->tls_psk));
  return sizeof (self->tls_psk);
}

/* Set up TLS client context using TLS 1.2 PSK */
static gboolean
fpc1022_init_tls_client (FpiDeviceFpc1022 *self)
{
  if (self->ssl)
    {
      SSL_free (self->ssl);
      self->ssl = NULL;
      self->bio_in = NULL;
      self->bio_out = NULL;
    }
  if (self->ssl_ctx)
    {
      SSL_CTX_free (self->ssl_ctx);
      self->ssl_ctx = NULL;
    }

  self->ssl_ctx = SSL_CTX_new (TLS_client_method ());
  if (!self->ssl_ctx)
    {
      fp_err ("Failed to create SSL_CTX");
      return FALSE;
    }

  SSL_CTX_set_min_proto_version (self->ssl_ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version (self->ssl_ctx, TLS1_2_VERSION);
  SSL_CTX_set_options (self->ssl_ctx, SSL_OP_NO_COMPRESSION);

  if (!SSL_CTX_set_cipher_list (self->ssl_ctx,
                                "PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384:PSK-AES128-CBC-SHA256"))
    {
      fp_err ("Failed to set TLS cipher list");
      return FALSE;
    }

  SSL_CTX_set_psk_client_callback (self->ssl_ctx, fpc1022_psk_client_cb);

  self->bio_in = BIO_new (BIO_s_mem ());
  self->bio_out = BIO_new (BIO_s_mem ());
  if (!self->bio_in || !self->bio_out)
    {
      fp_err ("Failed to create memory BIOs");
      if (self->bio_in)
        BIO_free (self->bio_in);
      if (self->bio_out)
        BIO_free (self->bio_out);
      self->bio_in = NULL;
      self->bio_out = NULL;
      return FALSE;
    }

  self->ssl = SSL_new (self->ssl_ctx);
  if (!self->ssl)
    {
      fp_err ("Failed to create SSL instance");
      BIO_free (self->bio_in);
      BIO_free (self->bio_out);
      self->bio_in = NULL;
      self->bio_out = NULL;
      return FALSE;
    }

  SSL_set_app_data (self->ssl, self);
  SSL_set_bio (self->ssl, self->bio_in, self->bio_out);
  SSL_set_connect_state (self->ssl);

  return TRUE;
}

/* ---- USB Control and Bulk Helpers ---- */

static GCancellable *
fpc1022_get_transfer_cancellable (FpiDeviceFpc1022 *self, FpiSsm *ssm)
{
  if (ssm == self->open_ssm)
    return fpi_device_get_cancellable (FP_DEVICE (self));

  return self->interrupt_cancellable;
}

static void
fpc1022_ctrl_cmd_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                     gpointer user_data, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  fpi_ssm_next_state (transfer->ssm);
}

static void
fpc1022_ctrl_cmd_ignore_error_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                                  gpointer user_data, GError *error)
{
  if (error)
    {
      fp_dbg ("Ignoring non-critical control error: %s", error->message);
      g_error_free (error);
    }

  fpi_ssm_next_state (transfer->ssm);
}

static void
fpc1022_send_ctrl_full (FpDevice *dev, FpiSsm *ssm,
                        guint8 request, guint16 value, guint16 index,
                        const guint8 *data, gsize data_len,
                        FpiUsbTransferCallback callback)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);

  fpi_usb_transfer_fill_control (transfer,
                                 G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                 G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                 G_USB_DEVICE_RECIPIENT_DEVICE,
                                 request, value, index, data_len);

  if (data && data_len > 0)
    memcpy (transfer->buffer, data, data_len);

  transfer->ssm = ssm;
  fpi_usb_transfer_submit (transfer, FPC1022_CTRL_TIMEOUT,
                           fpc1022_get_transfer_cancellable (self, ssm),
                           callback, NULL);
}

static void
fpc1022_send_ctrl (FpDevice *dev, FpiSsm *ssm,
                   guint8 request, guint16 value, guint16 index,
                   const guint8 *data, gsize data_len)
{
  fpc1022_send_ctrl_full (dev, ssm, request, value, index, data, data_len,
                          fpc1022_ctrl_cmd_cb);
}

static void
fpc1022_submit_bulk_read (FpDevice *dev, FpiSsm *ssm,
                          FpiUsbTransferCallback callback,
                          guint timeout_ms)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);

  fpi_usb_transfer_fill_bulk (transfer, FPC1022_EP_IN, FPC1022_EP_IN_MAX_BUF_SIZE);
  transfer->ssm = ssm;
  fpi_usb_transfer_submit (transfer, timeout_ms,
                           fpc1022_get_transfer_cancellable (self, ssm),
                           callback, NULL);
}

static gboolean
fpc1022_prepare_bulk_event (FpiDeviceFpc1022 *self,
                            FpiSsm *ssm,
                            gboolean *complete)
{
  guint32 event_len;

  if (self->bulk_recv_len < sizeof (Fpc1022EvtHdr))
    {
      *complete = FALSE;
      return TRUE;
    }

  if (self->evt_total_len == 0)
    {
      memcpy (&event_len,
              self->bulk_buf + G_STRUCT_OFFSET (Fpc1022EvtHdr, len),
              sizeof (event_len));
      self->evt_total_len = GUINT32_FROM_LE (event_len);

      if (self->evt_total_len < sizeof (Fpc1022EvtHdr) ||
          self->evt_total_len > FPC1022_BULK_EVENT_MAX_SIZE)
        {
          fp_err ("Invalid bulk event length: %" G_GSIZE_FORMAT,
                  self->evt_total_len);
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
          return FALSE;
        }
    }

  *complete = self->bulk_recv_len >= self->evt_total_len;
  return TRUE;
}

static void
fpc1022_consume_bulk_event (FpiDeviceFpc1022 *self)
{
  gsize remaining;

  g_assert (self->evt_total_len > 0);
  g_assert (self->evt_total_len <= self->bulk_recv_len);
  remaining = self->bulk_recv_len - self->evt_total_len;
  memmove (self->bulk_buf,
           self->bulk_buf + self->evt_total_len,
           remaining);
  self->bulk_recv_len = remaining;
  self->evt_total_len = 0;
}

/* ---- Open SSM Implementation ---- */

static void fpc1022_tls_handshake_step (FpDevice *dev, FpiSsm *ssm);
static void fpc1022_open_wait_init_continue (FpDevice *dev, FpiSsm *ssm);
static void fpc1022_open_bulk_read_continue (FpDevice *dev, FpiSsm *ssm);

static void
fpc1022_open_get_state_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                           gpointer user_data, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  fp_dbg ("Received GET_STATE response (%" G_GSSIZE_FORMAT " bytes)",
          transfer->actual_length);
  fpi_ssm_next_state (transfer->ssm);
}

static void
fpc1022_open_get_tls_key_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                             gpointer user_data, GError *error)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  if (!fpc1022_process_tls_key_packet (self, transfer->buffer, transfer->actual_length))
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  fpi_ssm_next_state (transfer->ssm);
}

static void
fpc1022_open_bulk_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                      gpointer user_data, GError *error)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  int cur_state;

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  if (self->bulk_recv_len + transfer->actual_length > sizeof (self->bulk_buf))
    {
      fp_err ("Bulk buffer overflow during open");
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  memcpy (self->bulk_buf + self->bulk_recv_len,
          transfer->buffer, transfer->actual_length);
  self->bulk_recv_len += transfer->actual_length;

  cur_state = fpi_ssm_get_cur_state (transfer->ssm);
  if (cur_state == FPC1022_OPEN_WAIT_INIT_RESULT)
    fpc1022_open_wait_init_continue (dev, transfer->ssm);
  else
    fpc1022_open_bulk_read_continue (dev, transfer->ssm);
}

static void
fpc1022_open_wait_init_continue (FpDevice *dev, FpiSsm *ssm)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  gboolean complete;

  if (!fpc1022_prepare_bulk_event (self, ssm, &complete))
    return;

  if (complete)
    {
      Fpc1022EvtHdr *hdr = (Fpc1022EvtHdr *) self->bulk_buf;
      guint32 code = GUINT32_FROM_LE (hdr->code);
      gsize event_len = self->evt_total_len;

      fp_dbg ("Open bulk event: code=0x%02x len=%" G_GSIZE_FORMAT, code, event_len);

      if (code == FPC1022_EVT_INIT_RESULT)
        {
          if (event_len >= 38)
            {
              guint16 width = *(guint16 *) (self->bulk_buf + 16);
              guint16 height = *(guint16 *) (self->bulk_buf + 18);
              char fw[16] = { 0 };
              memcpy (fw, self->bulk_buf + 20, MIN (sizeof (fw) - 1, event_len - 20));
              fp_dbg ("Sensor INIT_RESULT: %dx%d, fw=%s",
                      GUINT16_FROM_LE (width), GUINT16_FROM_LE (height), fw);
            }
          fpc1022_consume_bulk_event (self);
          fpi_ssm_next_state (ssm);
          return;
        }

      /* Consume unexpected event and keep waiting */
      fpc1022_consume_bulk_event (self);
    }

  fpc1022_submit_bulk_read (dev, ssm, fpc1022_open_bulk_cb, FPC1022_DATA_TIMEOUT);
}

static void
fpc1022_open_tls_send_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                          gpointer user_data, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  fpc1022_tls_handshake_step (dev, transfer->ssm);
}

static void
fpc1022_open_bulk_read_continue (FpDevice *dev, FpiSsm *ssm)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  gboolean complete;

  if (!fpc1022_prepare_bulk_event (self, ssm, &complete))
    return;

  if (complete)
    {
      Fpc1022EvtHdr *hdr = (Fpc1022EvtHdr *) self->bulk_buf;
      guint32 code = GUINT32_FROM_LE (hdr->code);
      gsize event_len = self->evt_total_len;

      fp_dbg ("Handshake bulk event: code=0x%02x len=%" G_GSIZE_FORMAT, code, event_len);

      if (code == FPC1022_EVT_TLS)
        {
          if (event_len > FPC1022_EVT_HDR_SIZE)
            {
              BIO_write (self->bio_in,
                         self->bulk_buf + FPC1022_EVT_HDR_SIZE,
                         event_len - FPC1022_EVT_HDR_SIZE);
            }
          fpc1022_consume_bulk_event (self);
          fpc1022_tls_handshake_step (dev, ssm);
          return;
        }

      fpc1022_consume_bulk_event (self);
    }

  fpc1022_submit_bulk_read (dev, ssm, fpc1022_open_bulk_cb, FPC1022_DATA_TIMEOUT);
}

static void
fpc1022_tls_handshake_step (FpDevice *dev, FpiSsm *ssm)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  int ret;
  size_t pending;

  if (SSL_is_init_finished (self->ssl))
    {
      self->tls_established = TRUE;
      fp_dbg ("TLS 1.2 handshake completed! Cipher: %s",
              SSL_get_cipher_name (self->ssl));
      fpi_ssm_mark_completed (ssm);
      return;
    }

  ret = SSL_connect (self->ssl);
  if (ret <= 0)
    {
      int err = SSL_get_error (self->ssl, ret);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
        {
          fp_err ("SSL_connect failed with error %d", err);
          ERR_print_errors_fp (stderr);
          fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
          return;
        }
    }

  pending = BIO_ctrl_pending (self->bio_out);
  if (pending > 0)
    {
      guint8 chunk[64];
      int n = BIO_read (self->bio_out, chunk, MIN (pending, sizeof (chunk)));
      if (n > 0)
        {
          fp_dbg ("Sending TLS handshake data (%d bytes, pending: %" G_GSIZE_FORMAT ")",
                  n, pending - n);
          fpc1022_send_ctrl_full (dev, ssm, FPC1022_CMD_TLS_DATA, 1, 0,
                                  chunk, n, fpc1022_open_tls_send_cb);
          return;
        }
    }

  if (SSL_is_init_finished (self->ssl))
    {
      self->tls_established = TRUE;
      fp_dbg ("TLS 1.2 handshake completed! Cipher: %s",
              SSL_get_cipher_name (self->ssl));
      fpi_ssm_mark_completed (ssm);
      return;
    }

  fpc1022_open_bulk_read_continue (dev, ssm);
}

static void
fpc1022_open_ssm_run (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  FpiUsbTransfer *transfer;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case FPC1022_OPEN_INDICATE_S_STATE:
      fp_dbg ("Sending CMD_INDICATE_S_STATE (S0)");
      fpc1022_send_ctrl (dev, ssm, FPC1022_CMD_INDICATE_S_STATE,
                         FPC1022_S_STATE_S0, 0, NULL, 0);
      break;

    case FPC1022_OPEN_GET_STATE:
      fp_dbg ("Sending CMD_GET_STATE");
      transfer = fpi_usb_transfer_new (dev);
      fpi_usb_transfer_fill_control (transfer,
                                     G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                     G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     FPC1022_CMD_GET_STATE, 0, 0, 72);
      transfer->ssm = ssm;
      fpi_usb_transfer_submit (transfer, FPC1022_CTRL_TIMEOUT,
                               fpc1022_get_transfer_cancellable (self, ssm),
                               fpc1022_open_get_state_cb, NULL);
      break;

    case FPC1022_OPEN_CMD_INIT:
      {
        guint32 init_token = GUINT32_TO_LE (FPC1022_INIT_TOKEN_BASE);
        fp_dbg ("Sending CMD_INIT (token 0x%08x)", FPC1022_INIT_TOKEN_BASE);
        fpc1022_send_ctrl (dev, ssm, FPC1022_CMD_INIT, 0x0001, 0,
                           (guint8 *) &init_token, sizeof (init_token));
      }
      break;

    case FPC1022_OPEN_WAIT_INIT_RESULT:
      fp_dbg ("Waiting for EVT_INIT_RESULT on bulk IN");
      fpc1022_open_wait_init_continue (dev, ssm);
      break;

    case FPC1022_OPEN_SET_TLS_KEY:
      fp_dbg ("Sending CMD_SET_TLS_KEY (119 bytes)");
      fpc1022_send_ctrl (dev, ssm, FPC1022_CMD_SET_TLS_KEY, 0, 0,
                         fpc1022_sealed_key_pkt, sizeof (fpc1022_sealed_key_pkt));
      break;

    case FPC1022_OPEN_GET_TLS_KEY:
      fp_dbg ("Sending CMD_GET_TLS_KEY");
      transfer = fpi_usb_transfer_new (dev);
      fpi_usb_transfer_fill_control (transfer,
                                     G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                     G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     FPC1022_CMD_GET_TLS_KEY, 0, 0, 119);
      transfer->ssm = ssm;
      fpi_usb_transfer_submit (transfer, FPC1022_CTRL_TIMEOUT,
                               fpc1022_get_transfer_cancellable (self, ssm),
                               fpc1022_open_get_tls_key_cb, NULL);
      break;

    case FPC1022_OPEN_TLS_INIT:
      fp_dbg ("Sending CMD_TLS_INIT");
      if (!fpc1022_init_tls_client (self))
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
          return;
        }
      fpc1022_send_ctrl (dev, ssm, FPC1022_CMD_TLS_INIT, 1, 0, NULL, 0);
      break;

    case FPC1022_OPEN_TLS_HANDSHAKE:
      fp_dbg ("Beginning TLS 1.2 PSK client handshake");
      fpc1022_tls_handshake_step (dev, ssm);
      break;

    default:
      g_assert_not_reached ();
    }
}

static GError *
fpc1022_cleanup_resources (FpImageDevice *dev)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  GError *error = NULL;

  g_cancellable_cancel (self->interrupt_cancellable);
  g_clear_object (&self->interrupt_cancellable);

  if (self->ssl)
    {
      SSL_free (self->ssl);
      self->ssl = NULL;
      self->bio_in = NULL;
      self->bio_out = NULL;
    }

  if (self->ssl_ctx)
    {
      SSL_CTX_free (self->ssl_ctx);
      self->ssl_ctx = NULL;
    }

  g_clear_pointer (&self->tls_rx_buf, g_byte_array_unref);

  OPENSSL_cleanse (self->tls_psk, sizeof (self->tls_psk));

  self->tls_established = FALSE;
  self->bulk_recv_len = 0;
  self->evt_total_len = 0;

  g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (dev)),
                                  0, 0, &error);

  return error;
}

static void
fpc1022_open_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpImageDevice *img_dev = FP_IMAGE_DEVICE (dev);
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);

  self->open_ssm = NULL;

  if (error)
    {
      g_autoptr(GError) cleanup_error = NULL;

      cleanup_error = fpc1022_cleanup_resources (img_dev);
      if (cleanup_error)
        fp_warn ("Failed to clean up after open error: %s",
                 cleanup_error->message);
      fpi_image_device_open_complete (img_dev, error);
      return;
    }

  fp_dbg ("FPC1022 open and TLS tunnel established successfully");
  fpi_image_device_open_complete (img_dev, NULL);
}

/* ---- Capture SSM Implementation ---- */

static void fpc1022_capture_continue (FpDevice *dev, FpiSsm *ssm);
static void fpc1022_start_deactivation (FpImageDevice *dev);

static void
fpc1022_capture_bulk_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                         gpointer user_data, GError *error)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);

  if (error)
    {
      if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          g_error_free (error);
          if (self->deactivating)
            fpi_ssm_mark_completed (transfer->ssm);
          return;
        }
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  if (self->bulk_recv_len + transfer->actual_length > sizeof (self->bulk_buf))
    {
      fp_err ("Bulk buffer overflow during capture");
      self->bulk_recv_len = 0;
      self->evt_total_len = 0;
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  memcpy (self->bulk_buf + self->bulk_recv_len,
          transfer->buffer, transfer->actual_length);
  self->bulk_recv_len += transfer->actual_length;

  fpc1022_capture_continue (dev, transfer->ssm);
}

static void
fpc1022_capture_process_event (FpDevice *dev, FpiSsm *ssm)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  Fpc1022EvtHdr *hdr = (Fpc1022EvtHdr *) self->bulk_buf;
  guint32 code = GUINT32_FROM_LE (hdr->code);
  gsize event_len = self->evt_total_len;
  int state = fpi_ssm_get_cur_state (ssm);

  fp_dbg ("Capture USB event: code=0x%02x len=%" G_GSIZE_FORMAT " state=%d",
          code, event_len, state);

  if (state == FPC1022_CAPTURE_WAIT_EVENT)
    {
      switch (code)
        {
        case FPC1022_EVT_FINGER_DOWN:
          fp_dbg ("Finger touch detected (EVT_FINGER_DOWN)");
          fpc1022_consume_bulk_event (self);
          fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), TRUE);
          fpi_ssm_jump_to_state (ssm, FPC1022_CAPTURE_GET_IMAGE);
          return;

        case FPC1022_EVT_FINGER_UP:
          fp_dbg ("Finger up event received");
          fpc1022_consume_bulk_event (self);
          fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), FALSE);
          fpc1022_capture_continue (dev, ssm);
          return;

        case FPC1022_EVT_HELLO:
          fp_dbg ("Sensor hello/ready event, awaiting finger");
          fpc1022_consume_bulk_event (self);
          fpc1022_capture_continue (dev, ssm);
          return;

        default:
          fp_dbg ("Ignoring event 0x%02x while waiting for finger", code);
          fpc1022_consume_bulk_event (self);
          fpc1022_capture_continue (dev, ssm);
          return;
        }
    }

  if (state == FPC1022_CAPTURE_RECV_IMAGE)
    {
      if (code == FPC1022_EVT_TLS)
        {
          if (event_len > FPC1022_EVT_HDR_SIZE)
            {
              BIO_write (self->bio_in,
                         self->bulk_buf + FPC1022_EVT_HDR_SIZE,
                         event_len - FPC1022_EVT_HDR_SIZE);
            }
          fpc1022_consume_bulk_event (self);

          guint8 dec_buf[2048];
          int n;
          while ((n = SSL_read (self->ssl, dec_buf, sizeof (dec_buf))) > 0)
            {
              g_byte_array_append (self->tls_rx_buf, dec_buf, n);
            }

          fp_dbg ("Decrypted %u / %d TLS image bytes",
                  self->tls_rx_buf->len, FPC1022_TLS_MSG_MAX_SIZE);

          if (self->tls_rx_buf->len >= FPC1022_TLS_MSG_MAX_SIZE)
            {
              fp_dbg ("Full decrypted image message received!");
              fpi_ssm_jump_to_state (ssm, FPC1022_CAPTURE_GET_FW_VERSION);
              return;
            }

          fpc1022_capture_continue (dev, ssm);
          return;
        }

      if (code == FPC1022_EVT_FINGER_UP)
        {
          fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), FALSE);
          fpc1022_consume_bulk_event (self);
          fpc1022_capture_continue (dev, ssm);
          return;
        }

      fpc1022_consume_bulk_event (self);
      fpc1022_capture_continue (dev, ssm);
      return;
    }

  if (state == FPC1022_CAPTURE_CONSUME_ACK)
    {
      if (code == FPC1022_EVT_TLS)
        {
          if (event_len > FPC1022_EVT_HDR_SIZE)
            {
              BIO_write (self->bio_in,
                         self->bulk_buf + FPC1022_EVT_HDR_SIZE,
                         event_len - FPC1022_EVT_HDR_SIZE);
              guint8 dummy[128];
              while (SSL_read (self->ssl, dummy, sizeof (dummy)) > 0)
                ;
            }
        }

      fpc1022_consume_bulk_event (self);

      if (self->tls_rx_buf->len >= FPC1022_TLS_MSG_MAX_SIZE)
        {
          g_autoptr(FpImage) img = NULL;
          FpImage *scaled = NULL;

          fp_dbg ("Extracting %dx%d image and upscaling 2x to 128x352",
                  FPC1022_IMG_WIDTH, FPC1022_IMG_HEIGHT);

          img = fp_image_new (FPC1022_IMG_WIDTH, FPC1022_IMG_HEIGHT);
          memcpy (img->data,
                  self->tls_rx_buf->data + FPC1022_TLS_MSG_HDR_SIZE,
                  FPC1022_IMG_SIZE);
          img->flags = 0;
          scaled = fpc1022_scale_nn_2x (img);

          g_byte_array_set_size (self->tls_rx_buf, 0);
          fpi_image_device_image_captured (FP_IMAGE_DEVICE (dev), scaled);
          fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), FALSE);
          fpi_ssm_mark_completed (ssm);
          return;
        }

      fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  /* Catch-all for unexpected states */
  fpc1022_consume_bulk_event (self);
  fpc1022_capture_continue (dev, ssm);
}

static void
fpc1022_capture_continue (FpDevice *dev, FpiSsm *ssm)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  gboolean complete;
  gboolean waiting_finger;
  guint timeout;

  if (!fpc1022_prepare_bulk_event (self, ssm, &complete))
    return;

  if (complete)
    {
      fpc1022_capture_process_event (dev, ssm);
      return;
    }

  waiting_finger = fpi_ssm_get_cur_state (ssm) == FPC1022_CAPTURE_WAIT_EVENT;
  timeout = waiting_finger ? FPC1022_FINGER_TIMEOUT : FPC1022_DATA_TIMEOUT;
  fpc1022_submit_bulk_read (dev, ssm, fpc1022_capture_bulk_cb, timeout);
}

static void
fpc1022_capture_ssm_run (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case FPC1022_CAPTURE_ARM_SENSOR:
      {
        guint32 token = GUINT32_TO_LE (self->arm_token++);
        fp_dbg ("Arming sensor for finger detection (token 0x%08x)",
                GUINT32_FROM_LE (token));
        fpc1022_send_ctrl (dev, ssm, FPC1022_CMD_ARM, 0x0001, 0,
                           (guint8 *) &token, sizeof (token));
      }
      break;

    case FPC1022_CAPTURE_WAIT_EVENT:
      fp_dbg ("Waiting for finger event on bulk IN");
      fpc1022_capture_continue (dev, ssm);
      break;

    case FPC1022_CAPTURE_GET_IMAGE:
      fp_dbg ("Requesting image capture (CMD_GET_IMG)");
      g_byte_array_set_size (self->tls_rx_buf, 0);
      fpc1022_send_ctrl (dev, ssm, FPC1022_CMD_GET_IMG, 0x0000, 0, NULL, 0);
      break;

    case FPC1022_CAPTURE_RECV_IMAGE:
      fp_dbg ("Receiving TLS encrypted image chunks");
      fpc1022_capture_continue (dev, ssm);
      break;

    case FPC1022_CAPTURE_GET_FW_VERSION:
      fp_dbg ("Housekeeping: CMD_GET_FW_VERSION");
      fpc1022_send_ctrl (dev, ssm, FPC1022_CMD_GET_FW_VERSION, 0x0000, 0, NULL, 0);
      break;

    case FPC1022_CAPTURE_GET_DEAD_PIXELS:
      fp_dbg ("Housekeeping: CMD_GET_DEAD_PIXELS");
      fpc1022_send_ctrl (dev, ssm, FPC1022_CMD_GET_DEAD_PIXELS, 0x0000, 0, NULL, 0);
      break;

    case FPC1022_CAPTURE_GET_KPI:
      {
        fp_dbg ("Housekeeping: CMD_GET_KPI");
        FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);
        fpi_usb_transfer_fill_control (transfer,
                                       G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                       G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                       G_USB_DEVICE_RECIPIENT_DEVICE,
                                       FPC1022_CMD_GET_KPI, 0, 0, 28);
        transfer->ssm = ssm;
        fpi_usb_transfer_submit (transfer, FPC1022_CTRL_TIMEOUT,
                                 fpc1022_get_transfer_cancellable (self, ssm),
                                 fpc1022_ctrl_cmd_ignore_error_cb, NULL);
      }
      break;

    case FPC1022_CAPTURE_CONSUME_ACK:
      fp_dbg ("Consuming TLS ack packet on bulk IN");
      fpc1022_capture_continue (dev, ssm);
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
fpc1022_capture_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);

  self->capture_ssm = NULL;

  if (self->deactivating)
    {
      if (error)
        g_error_free (error);
      fpc1022_start_deactivation (FP_IMAGE_DEVICE (dev));
      return;
    }

  if (error)
    {
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), FALSE);
      fpi_image_device_session_error (FP_IMAGE_DEVICE (dev), error);
      return;
    }

  fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), FALSE);
}

/* ---- Deactivate SSM Implementation ---- */

static void
fpc1022_deact_ssm_run (FpiSsm *ssm, FpDevice *dev)
{
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case FPC1022_DEACT_ABORT:
      fp_dbg ("Sending CMD_ABORT for deactivation");
      fpc1022_send_ctrl_full (dev, ssm, FPC1022_CMD_ABORT, 1, 0, NULL, 0,
                              fpc1022_ctrl_cmd_ignore_error_cb);
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
fpc1022_deact_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  if (error)
    fp_err ("Deactivation error: %s", error->message);

  fpi_image_device_deactivate_complete (FP_IMAGE_DEVICE (dev), error);
}

static void
fpc1022_start_deactivation (FpImageDevice *dev)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  FpiSsm *ssm;

  g_clear_object (&self->interrupt_cancellable);
  self->interrupt_cancellable = g_cancellable_new ();

  ssm = fpi_ssm_new (FP_DEVICE (dev), fpc1022_deact_ssm_run,
                     FPC1022_DEACT_NUM_STATES);
  fpi_ssm_start (ssm, fpc1022_deact_ssm_done);
}

/* ---- FpImageDevice vfuncs ---- */

static void
fpc1022_img_open (FpImageDevice *dev)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  GError *error = NULL;

  fp_dbg ("Opening FPC1022 device");

  /* Claim USB interface 0 */
  if (!g_usb_device_claim_interface (fpi_device_get_usb_device (FP_DEVICE (dev)),
                                     0, 0, &error))
    {
      fpi_image_device_open_complete (dev, error);
      return;
    }

  self->tls_rx_buf = g_byte_array_new ();
  self->bulk_recv_len = 0;
  self->evt_total_len = 0;
  self->tls_established = FALSE;
  self->deactivating = FALSE;
  self->arm_token = FPC1022_INIT_TOKEN_BASE + 1;
  self->interrupt_cancellable = g_cancellable_new ();

  /* Start open SSM */
  self->open_ssm = fpi_ssm_new (FP_DEVICE (dev), fpc1022_open_ssm_run,
                                FPC1022_OPEN_NUM_STATES);
  fpi_ssm_start (self->open_ssm, fpc1022_open_ssm_done);
}

static void
fpc1022_img_close (FpImageDevice *dev)
{
  GError *error;

  fp_dbg ("Closing FPC1022 device");

  error = fpc1022_cleanup_resources (dev);
  fpi_image_device_close_complete (dev, error);
}

static void
fpc1022_activate (FpImageDevice *dev)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);

  fp_dbg ("Activating FPC1022 device");

  self->deactivating = FALSE;

  if (!self->tls_established)
    {
      fpi_image_device_activate_complete (dev,
                                          fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
      return;
    }

  fpi_image_device_activate_complete (dev, NULL);
}

static void
fpc1022_change_state (FpImageDevice *dev, FpiImageDeviceState state)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);

  if (state != FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON ||
      self->deactivating || self->capture_ssm)
    return;

  /* Start capture loop */
  self->capture_ssm = fpi_ssm_new (FP_DEVICE (dev), fpc1022_capture_ssm_run,
                                   FPC1022_CAPTURE_NUM_STATES);
  fpi_ssm_start (self->capture_ssm, fpc1022_capture_ssm_done);
}

static void
fpc1022_deactivate (FpImageDevice *dev)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);

  fp_dbg ("Deactivating FPC1022 device");

  self->deactivating = TRUE;

  if (self->capture_ssm)
    {
      g_cancellable_cancel (self->interrupt_cancellable);
      return;
    }

  fpc1022_start_deactivation (dev);
}

/* ---- GObject Boilerplate ---- */

static void
fpi_device_fpc1022_init (FpiDeviceFpc1022 *self)
{
}

static void
fpi_device_fpc1022_class_init (FpiDeviceFpc1022Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *img_class = FP_IMAGE_DEVICE_CLASS (klass);

  dev_class->id = "fpc1022";
  dev_class->full_name = "FPC Fingerprint Reader (Disum 10a5:a920)";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->temp_hot_seconds = -1;
  dev_class->temp_cold_seconds = 0;

  img_class->img_open = fpc1022_img_open;
  img_class->img_close = fpc1022_img_close;
  img_class->activate = fpc1022_activate;
  img_class->change_state = fpc1022_change_state;
  img_class->deactivate = fpc1022_deactivate;

  img_class->img_width = FPC1022_IMG_WIDTH * FPC1022_IMG_SCALE;
  img_class->img_height = FPC1022_IMG_HEIGHT * FPC1022_IMG_SCALE;
  img_class->algorithm = FPI_DEVICE_ALGO_SIGFM;
  img_class->score_threshold = FPC1022_SCORE_THRESHOLD;
}
