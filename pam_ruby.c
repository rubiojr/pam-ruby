#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "pam_ruby.h"
#include "pam.h"  /* Ruby/PAM header file */

static VALUE rb_dispatcher, rb_mod_dispatcher;
static int   pam_ruby_initialized = 0;

static VALUE
rb_pam_syslog(VALUE self, VALUE pri, VALUE msg)
{
  syslog(NUM2INT(pri), "[pam_ruby] %s", STR2CSTR(msg));
  return Qnil;
}

static VALUE
rb_pam_dispatch(int argc, VALUE argv[], VALUE self)
{
  VALUE sym, proc;

  switch( rb_scan_args(argc, argv, "11", &sym, &proc) ){
  case 1:
    proc = rb_block_proc();
    break;
  case 2:
    /* do nothing */
    break;
  default:
    rb_bug("rb_pam_dispatch");
  };

  Check_Type(sym, T_SYMBOL);

  rb_hash_aset(rb_dispatcher, sym, proc);

  return Qnil;
}

static VALUE
rb_pam_module_dispatch(VALUE mod, VALUE dispatch)
{
  rb_mod_dispatcher = dispatch;
  return Qnil;
}

static int
pam_ruby_init(const char *filename)
{
  if( pam_ruby_initialized ) return 0;

  pam_ruby_initialized = 1;

  PAM_RUBY_DEBUG({syslog(LOG_DEBUG, "[pam_ruby] pam_ruby_init()");});
  ruby_init();

  if( rb_eval_string("defined?(PAM)") == Qnil ){
    PAM_RUBY_DEBUG({syslog(LOG_DEBUG, "[pam_ruby] Init_pam()");});
    Init_pam();
  }
  else{
    PAM_RUBY_DEBUG({syslog(LOG_DEBUG,
			   "[pam_ruby] Init_pam() have already been called.");});
  };

  rb_dispatcher = rb_hash_new();
  rb_mod_dispatcher = Qnil;

  rb_define_const(rb_mPAM, "DISPATCHER", rb_dispatcher);
  rb_define_const(rb_mPAM, "MODULE_DISPATCHER", rb_mod_dispatcher);
  rb_define_module_function(rb_mPAM, "dispatch", rb_pam_dispatch, -1);
  rb_define_module_function(rb_mPAM, "module_dispatch", rb_pam_module_dispatch, 1);
  rb_define_module_function(rb_mPAM, "syslog",   rb_pam_syslog, 2);
#define rb_pam_define_const(c) rb_define_const(rb_mPAM, #c, INT2NUM(c))
#ifdef LOG_EMERG
  rb_pam_define_const(LOG_EMERG);
#endif
#ifdef LOG_ALERT
  rb_pam_define_const(LOG_ALERT);
#endif
#ifdef LOG_CRIT
  rb_pam_define_const(LOG_CRIT);
#endif
#ifdef LOG_ERR
  rb_pam_define_const(LOG_ERR);
#endif
#ifdef LOG_WARNING
  rb_pam_define_const(LOG_WARNING);
#endif
#ifdef LOG_NOTICE
  rb_pam_define_const(LOG_NOTICE);
#endif
#ifdef LOG_INFO
  rb_pam_define_const(LOG_INFO);
#endif
#ifdef LOG_DEBUG
  rb_pam_define_const(LOG_DEBUG);
#endif
#undef rb_pam_define_const

  PAM_RUBY_DEBUG({syslog(LOG_DEBUG, "[pam_ruby] rb_f_require('%s')", filename);});
  //rb_f_require(rb_mKernel, rb_tainted_str_new2(filename));
  rb_f_require(rb_mKernel, rb_str_new2(filename));

  return 0;
}

static VALUE
cary2rary(const char **argv, int len)
{
  VALUE ary;
  int i;

  ary = rb_ary_new();
  for( i=0; i < len; i++ ){
    rb_ary_push(ary, rb_tainted_str_new2(argv[i]));
  }

  return ary;
}

static int
pam_ruby_dispatch_call(dispatch_data_t *data)
{
  const char *sym = data->sym;
  pam_handle_t *pamh = data->pamh;
  int flags = data->flags;
  int argc  = data->argc;
  const char **argv = data->argv;

  VALUE proc, res;
  VALUE args;
  int result;

  PAM_RUBY_DEBUG({
    int i;
    syslog(LOG_DEBUG, "[pam_ruby] rb_pam_dispatch_call()");
    syslog(LOG_DEBUG,
	   "[pam_ruby] sym='%s', pamh=0x%x, flags=0x%x, argc=%d\n",
	   sym, pamh, flags, argc);
    for( i=0; i < argc; i++ ){
      syslog(LOG_DEBUG, "[pam_ruby] argv[%d]='%s'\n", i, argv[i]);
    }
  });

  if( argc < 1 )
    return PAM_SYSTEM_ERR;

  argc --;
  argv ++;
  args = cary2rary(argv,argc);

  PAM_RUBY_DEBUG({
    syslog(LOG_DEBUG, "[pam_ruby] args=%s",
	   STR2CSTR(rb_funcall(args, rb_intern("inspect"), 0)));
  });
  if( rb_mod_dispatcher == Qnil ){
    proc = rb_hash_aref(rb_dispatcher, ID2SYM(rb_intern(sym)));

    PAM_RUBY_DEBUG({
      syslog(LOG_DEBUG, "[pam_ruby] proc=%s",
	     STR2CSTR(rb_funcall(proc, rb_intern("inspect"), 0)));
    });

    if( proc ){
      rb_funcall(proc, rb_intern("call"), 3,
		 rb_pam_handle_new(pamh), INT2NUM(flags), args);
      return PAM_SUCCESS;
    }
    else{
      syslog(LOG_ERR, "[pam_ruby] dispatcher `%s' is not defined", sym);
      return PAM_SYSTEM_ERR;
    };
  }
  else{
    PAM_RUBY_DEBUG({
      syslog(LOG_DEBUG, "[pam_ruby] rb_mod_dispatcher = %s",
	     STR2CSTR(rb_funcall(rb_mod_dispatcher, rb_intern("inspect"), 0)));
    });
    rb_funcall(rb_mod_dispatcher, rb_intern(sym), 3,
	       rb_pam_handle_new(pamh), INT2NUM(flags), args);
    return PAM_SUCCESS;
  };
};

static int
pam_ruby_dispatch_rescue(VALUE data, VALUE exc)
{
  int i;
  VALUE exc_backtrace;
  VALUE exc_message;

  exc_backtrace = rb_funcall(exc, rb_intern("backtrace"), 0);
  exc_message   = rb_funcall(exc, rb_intern("message"), 0);

  syslog(LOG_ERR, "[pam_ruby] exception: %s",
	 STR2CSTR(rb_funcall(exc, rb_intern("inspect"), 0)));

  PAM_RUBY_DEBUG({
    syslog(LOG_ERR, "[pam_ruby] exception: %s",
	   STR2CSTR(rb_funcall(exc, rb_intern("inspect"), 0)));
    syslog(LOG_ERR, "[pam_ruby] %s",
	   STR2CSTR(exc_message));
    syslog(LOG_ERR, "[pam_ruby] %s",
	   STR2CSTR(rb_funcall(exc_backtrace, rb_intern("inspect"),0)));
  });

  for( i=0; i < RBPAM_MAX_ERRORS; i++ ){
    if( rb_pam_errors[i] == CLASS_OF(exc) ){
      return i;
    };
  };

  syslog(LOG_ERR, "[pam_ruby] %s",
	 STR2CSTR(rb_funcall(exc_backtrace, rb_intern("inspect"),0)));

  return PAM_SYSTEM_ERR;
};

static int
pam_ruby_dispatch(const char *sym, pam_handle_t *pamh, int flags,
		  int argc, const char **argv)
{
  dispatch_data_t data = {sym, pamh, flags, argc, argv};

  pam_ruby_init(argv[0]); /* should call pam_ruby_init() before rb_eException */
  return (int)rb_rescue2((VALUE(*)())pam_ruby_dispatch_call, (VALUE)(&data),
			 (VALUE(*)())pam_ruby_dispatch_rescue, Qnil,
			 rb_eException);
};

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh,
		    int flags, int argc, const char *argv[])
{
  return pam_ruby_dispatch("authenticate", pamh, flags, argc, argv);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	       int argc, const char *argv[])
{
  return pam_ruby_dispatch("setcred", pamh, flags, argc, argv);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc, const char *argv[])
{
  return pam_ruby_dispatch("open_session", pamh, flags, argc, argv);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc, const char *argv[])
{
  return pam_ruby_dispatch("close_session", pamh, flags, argc, argv);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		 int argc, const char *argv[])
{
  return pam_ruby_dispatch("chauthtok", pamh, flags, argc, argv);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		 int argc, const char *argv[])
{
  return pam_ruby_dispatch("acct_mgmt", pamh, flags, argc, argv);
}

#ifdef PAM_STATIC
struct pam_module _modstruct =
{
  "pam_ruby",
  pam_sm_authenticate,
  pam_sm_setcred,
  pam_sm_acct_mgmt,
  pam_sm_open_session,
  pam_sm_close_session,
  pam_sm_chauthtok
}
#endif
