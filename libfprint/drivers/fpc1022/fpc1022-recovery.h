/*
 * FPC1022 driver for libfprint - error recovery policy
 *
 * Pure helpers (no USB/TLS dependencies) so they can be unit tested.
 *
 * Copyright (c) 2026 feraxhp <feraxhp+gh@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#pragma once

#include <glib.h>

/* What to do when a bulk/control transfer of the capture SSM fails */
typedef enum {
  FPC1022_ERR_COMPLETE = 0,   /* cancelled: finish SSM silently, owner decides */
  FPC1022_ERR_REARM,          /* idle finger-wait poll timeout: re-arm sensor */
  FPC1022_ERR_FAIL,           /* real error: fail SSM, force TLS renegotiation */
} Fpc1022ErrAction;

static inline Fpc1022ErrAction
fpc1022_classify_transfer_error (gboolean cancelled,
                                 gboolean timed_out,
                                 gboolean waiting_finger)
{
  if (cancelled)
    return FPC1022_ERR_COMPLETE;

  if (timed_out && waiting_finger)
    return FPC1022_ERR_REARM;

  return FPC1022_ERR_FAIL;
}
