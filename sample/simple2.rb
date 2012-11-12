#
# key value pairs
# one user:password each line
#
def get_entry(auth, user)
  File.open(auth){|f|
    f.each_line{|line|
      next if line.strip.chomp.empty?
      a_user, a_pass = line.chomp.split(":")
      return [a_user,a_pass] if user == a_user
    }
  }
  return nil
end
  
PAM.dispatch(:authenticate){|pamh, flags, args|
  # checking for the name and password of the user
  authfile = args[0]
  puts "Using password file #{authfile}"

  # The user trying to authenticate
  # i.e. 'su root' will return 'root'
  user = pamh.get_item(PAM::PAM_USER)

  # Prompt for the password
  msg = PAM::Message.new(PAM::PAM_PROMPT_ECHO_OFF, "PAM/Ruby Password: ")
  rs = pamh.conv([msg])
  pass = rs[0].resp

  # Try to find the user in the password file
  if entry = get_entry(authfile, user)
    r_user, r_pass = entry
    raise PAM::PAM_AUTH_ERR, "the password is not correct" if r_pass != pass
  else
    raise PAM::PAM_USER_UNKNOWN, "can't find the entry for #{user}"
  end
}

PAM.dispatch(:acct_mgmt){|pamh, flags, args|
  PAM::PAM_SUCCESS
}

PAM.dispatch(:open_session){|pamh, flags, args|
  # raise PAM::PAM_SESSION_ERR, "not available"
  PAM::PAM_SUCCESS
}

PAM.dispatch(:close_session){|pamh, flags, args|
  #raise PAM::PAM_SESSION_ERR, "not available"
  PAM::PAM_SUCCESS
}

PAM.dispatch(:chauthtok){
 # raise PAM::PAM_AUTHTOK_ERR, "not available"
  PAM::PAM_SUCCESS
}

PAM.dispatch(:setcred){
  #raise PAM::PAM_CRED_UNAVAIL, "not available"
  PAM::PAM_SUCCESS
}
