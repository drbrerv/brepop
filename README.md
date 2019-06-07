# brepop

A minimized, simplified RFC1939 (POP3) implementation with customized authentication.  As it currently stands, this
code is heavily reliant on co-existing on a system with a Postfix-based e-mail server.

This code doesn't do socket/server handling.  inetd/xinet or something similar is recommended for that.

# Configuration

Here is an example of a valid configuration:

```yaml
---
postlock_path: /usr/sbin/postlock
brepop_path: /your/path/to/brepop.py
pwfile: /etc/brepop/passwd
logfile: /var/log/brepop.log
spamlog: /var/log/brepopspam.log
maildir: /var/mail
```
