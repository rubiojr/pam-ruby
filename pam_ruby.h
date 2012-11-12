/*
 * $Id: pam_ruby.h,v 1.4 2001/08/16 06:34:22 ttate Exp $
 */

#ifndef PAM_RUBY_H
#define PAM_RUBY_H

#include <ruby.h>
#include <intern.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
# include <security/pam_appl.h>
#endif

#ifdef HAVE_SECURITY_PAM_MISC_H
# include <security/pam_misc.h>
#endif

#ifndef PAM_EXTERN
# define PAM_EXTERN
#endif

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>

typedef struct {
  const char  *sym;
  pam_handle_t *pamh;
  int   flags;
  int   argc;
  const char  **argv;
} dispatch_data_t;

#if defined(DEBUG)
# define PAM_RUBY_DEBUG(code) code
#else
# define PAM_RUBY_DEBUG(code)
#endif

#endif
