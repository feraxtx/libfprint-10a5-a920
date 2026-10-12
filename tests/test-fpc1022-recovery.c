/*
 * FPC1022 (10a5:a920) error recovery policy unit tests
 *
 * Copyright (c) 2026 feraxhp <feraxhp+gh@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <glib.h>

#include "../libfprint/drivers/fpc1022/fpc1022-recovery.h"

static void
test_cancel_always_completes (void)
{
  /* A cancelled transfer must always finish the SSM (the old code left it
   * hanging unless the device was deactivating). */
  g_assert_cmpint (fpc1022_classify_transfer_error (TRUE, FALSE, FALSE), ==,
                   FPC1022_ERR_COMPLETE);
  g_assert_cmpint (fpc1022_classify_transfer_error (TRUE, FALSE, TRUE), ==,
                   FPC1022_ERR_COMPLETE);
  g_assert_cmpint (fpc1022_classify_transfer_error (TRUE, TRUE, TRUE), ==,
                   FPC1022_ERR_COMPLETE);
}

static void
test_idle_timeout_rearms (void)
{
  g_assert_cmpint (fpc1022_classify_transfer_error (FALSE, TRUE, TRUE), ==,
                   FPC1022_ERR_REARM);
}

static void
test_timeout_mid_transfer_fails (void)
{
  /* A timeout while receiving an image is a real error */
  g_assert_cmpint (fpc1022_classify_transfer_error (FALSE, TRUE, FALSE), ==,
                   FPC1022_ERR_FAIL);
}

static void
test_other_errors_fail (void)
{
  g_assert_cmpint (fpc1022_classify_transfer_error (FALSE, FALSE, TRUE), ==,
                   FPC1022_ERR_FAIL);
  g_assert_cmpint (fpc1022_classify_transfer_error (FALSE, FALSE, FALSE), ==,
                   FPC1022_ERR_FAIL);
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fpc1022/recovery/cancel_completes", test_cancel_always_completes);
  g_test_add_func ("/fpc1022/recovery/idle_timeout_rearms", test_idle_timeout_rearms);
  g_test_add_func ("/fpc1022/recovery/timeout_mid_transfer_fails", test_timeout_mid_transfer_fails);
  g_test_add_func ("/fpc1022/recovery/other_errors_fail", test_other_errors_fail);
  return g_test_run ();
}
