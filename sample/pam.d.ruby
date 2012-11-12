#%PAM-1.0
auth       required	/lib/security/pam_ruby.so /lib/security/ruby/simple.rb /tmp/passwd
account    required	/lib/security/pam_ruby.so /lib/security/ruby/simple.rb /tmp/passwd
password   required	/lib/security/pam_ruby.so /lib/security/ruby/simple.rb /tmp/passwd
session    required	/lib/security/pam_ruby.so /lib/security/ruby/simple.rb /tmp/passwd
