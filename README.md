# brepop

A minimized, simplified RFC1939 (POP3) implementation with customized authentication.  As it currently stands, this
code is heavily reliant on living on a system with a Postfix-based e-mail server.  Specifically, it expects MBOX-style
mailboxes and makes use of the `postlock` facility for mailbox locking.

This code ~~doesn't do~~ now does socket/server/daemon handling, which can be enabled by way of the `-d` option.  Without
this option, inetd/xinetd or something similar is recommended for socket management.

# Invocation

Usage: brepop.py [-d|-p port] [path_to_config_file]

#### The Options, Enumerated

   -d           Run as a standalone, backgrounded  daemon process that manages its own sockets.  This functionality consumes
                the server socket parameters outlined in the configuration example below (`bind_*` options)

   -p port      This option is used by the main server to assist with the management of mailbox locks.  IT IS NOT RECOMMENDED
                FOR USE FROM THE COMMAND LINE.

   config_path  The path to a YAML-formatted configuration file (example provided below).  This can override the default path
                for the file, which is /etc/brepop/config.yaml.

   It should be noted that the `-d` and `-p` options are mutually exclusive.  The configuration from the configuration file is
   currently not consumed by the mailbox locking mechanism invoked with the `-p` option.

# Configuration

A valid configuration example:

```yaml
---
postlock_path: /usr/sbin/postlock
brepop_path: /your/path/to/brepop.py
pwfile: /etc/brepop/passwd
logfile: /var/log/brepop.log
spamlog: /var/log/brepopspam.log
maildir: /var/mail
# optional server socket params
# bind_address: 127.0.0.1
# bind_port: 110
```
