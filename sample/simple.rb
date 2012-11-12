
def get_entry(auth, user)
  File.open(auth){|f|
    f.each_line{|line|
      line.chop!
      a_user,a_pass,a_time,a_chpass = line.split(":")
      return [a_user,a_pass,a_time,a_chpass]
    }
  }
  return nil
end
  
PAM.dispatch(:authenticate){|pamh, flags, args|
  # checking for the name and password of the user
  authfile = args[0]
  user = pamh.get_item(PAM::PAM_USER)
  msg1 = PAM::Message.new(PAM::PAM_PROMPT_ECHO_ON, "Login: ")
  msg2 = PAM::Message.new(PAM::PAM_PROMPT_ECHO_OFF, "Password: ")
  msgs = [msg1, msg2]
  rs = pamh.conv(msgs)
  r_user = rs[0].resp
  r_pass = rs[1].resp
  entry = get_entry(authfile, r_user)
  if( !entry )
    raise PAM::PAM_USER_UNKNOWN, "can't find the entry for #{r_user}"
  end
  if( entry[1] != r_pass )
    raise PAM::PAM_AUTH_ERR, "the password is not correct"
  end
}

PAM.dispatch(:acct_mgmt){|pamh, flags, args|
  # checking for the access time
  t = Time.now
  authfile = args[0]
  user = pamh.get_item(PAM::PAM_USER)
  entry = get_entry(authfile, user)
  if( !entry )
    raise PAM::PAM_USER_UNKNOWN
  end 
  t1,t2 = entry[2].split("-")
  t1_hour = t1.to_i
  t2_hour = t2.to_i
  if( !(t1_hour < t.hour && t.hour < t2_hour) )
    raise PAM::PAM_PERM_DENIED, "out of the time"
  end
}

PAM.dispatch(:open_session){|pamh, flags, args|
  # raise PAM::PAM_SESSION_ERR, "not available"
}

PAM.dispatch(:close_session){|pamh, flags, args|
  raise PAM::PAM_SESSION_ERR, "not available"
}

PAM.dispatch(:chauthtok){
  raise PAM::PAM_AUTHTOK_ERR, "not available"
}

PAM.dispatch(:setcred){
  raise PAM::PAM_CRED_UNAVAIL, "not available"
}
