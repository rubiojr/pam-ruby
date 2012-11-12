#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

static struct pam_conv conv = {
  misc_conv,
  NULL
};

int
main(int argc, char *argv[])
{
  pam_handle_t *pamh=NULL;
  int retval;
  const char *user="nobody";
  const char *service="ruby";
  
  if(argc == 3) {
    service = argv[1];
    user = argv[2];
  }
  else{
    fprintf(stderr, "Usage: check_user <service> <username>\n");
    exit(1);
  }
  
  retval = pam_start(service, user, &conv, &pamh);
  
  if (retval == PAM_SUCCESS)
    retval = pam_authenticate(pamh, 0);
  
  if (retval == PAM_SUCCESS)
    retval = pam_acct_mgmt(pamh, 0);
  
  if (retval == PAM_SUCCESS) {
    fprintf(stdout, "authenticated\n");
  } else {
    fprintf(stdout, "not authenticated\n");
  }
  
  pam_end(pamh,retval);
  
  exit(0);
}
