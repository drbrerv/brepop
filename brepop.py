#!/usr/bin/env python3

import sys
import random
import os
import socket
import signal
import time
import crypt
import yaml

from re import match, search, I

class CodeDictMapper( object ):
    def __init__( self, *args, **kwargs ):
        self._items = dict( *args, **kwargs )

    def mapHandler( self, line ):
        for regex in self._items.keys():
            mobj = match( regex, line, I )
            if mobj is not None:
                return [self._items[regex], mobj]
        return None

class BrePopServer:
    def __init__( self, config_path=None ):
        self.default_config = '/etc/brepop/config.yaml'
        self.config_param_keys = [
            'postlock_path',
            'brepop_path',
            'pwfile',
            'logfile',
            'spamlog',
            'maildir'
        ]
        self.initerror = False
        self.user = {}
        self.inbox = []
        self.mbox = ''
        self.state = 0
        self.lock = 0
        self.version = "1.0"
        self.message = []
        self.deleted = {}
        self.spam = []
        self.EOL = "\015\012"
        self.config = self.build_config( config_path )
        if not self.validate_config():
            self.initerror = True
            return
        self.options = {'welcome': 'Welcome to brepop.  Some stuff may be jacked up', 'timeout': 600, 'linetimeout': 600}
        self.spamlog = self.config['spamlog']
        random.seed( os.getpid() )
        self.code_map_noauth = {
            '^QUIT': self.handle_quit_noauth,
            '^VERSION': self.handle_version,
            '^USER\s*(\S*)': self.handle_user,
            '^PASS\s*(\S*)': self.handle_pass,
            '^APOP': self.handle_apop,
            '^CAPA': self.handle_capa
        }
        self.code_map_auth = {
            '^STAT': self.handle_stat,
            '^VERSION': self.handle_version,
            '^LIST\s*(\d*)': self.handle_list,
            '^UIDL\s*(\d*)': self.handle_uidl,
            '^TOP\s*(\d+)\s*(\d+)': self.handle_top,
            '^RETR\s*(\d*)': self.handle_retr,
            '^DELE\s*(\d*)': self.handle_dele,
            '^QUIT': self.handle_quit_auth,
            '^NOOP': self.handle_noop,
            '^RSET': self.handle_reset,
            '^CAPA': self.handle_capa
        }
        self.NoAuthObject = CodeDictMapper( self.code_map_noauth )
        self.AuthObject = CodeDictMapper( self.code_map_auth )
        self.logger('Server initialization complete')

    def build_config( self, filepath=None ):
        ourdata = builtConfig = None
        if filepath is None and self.default_config is None:
            return None
        elif filepath is not None:
            if os.path.isfile( filepath ):
                with open( filepath, 'r' ) as fpo:
                    ourdata = fpo.read()
        elif self.default_config is not None:
            if os.path.isfile( self.default_config ):
                with open( self.default_config, 'r' ) as dco:
                    ourdata = dco.read()
        try:
            builtConfig = yaml.safe_load( ourdata )
        except Exception:
            return None
        return builtConfig

    def validate_config( self ):
        # right now we have some file paths to check, which is easy enough
        rval = True
        for item in self.config_param_keys:
            if item in self.config:
                if not os.path.isfile( self.config[item] ):
                    print( "ConfigValidationError item: " + \
                            self.config[item] + \
                            " is not a valid filepath" )
                    rval = False
            else:
                print("ConfigValidationError: " + item + " not set.")
                rval = False
            return rval

    def logger( self, msg ):
        pid = os.getpid()
        exe = sys.argv[0].split('/')[-1]
        str_msg = msg.rstrip()
        tstr = time.strftime( '%a %b %d %H:%M:%S %Y', time.localtime( time.time() ) )
        logstr = "%s %s[%ld]: %s\n" % (tstr, exe, pid, str_msg)
        logfile = open( self.config['logfile'], 'a' )
        logfile.write( logstr )
        logfile.close()

    def brepopAuth( self, user ):
        name = user['name']
        passwd = user['pass'].rstrip()
        ip = user['ip']
        authgood = 0
        pwfile = open( self.config['pwfile'], 'r' )
        for ln in pwfile:
            ln = ln.rstrip()
            (pname,pwd,sname) = ln.split(':')
            if name == pname:
                if crypt.crypt( passwd, pwd ) == pwd:
                    authgood = 1
                    self.mbox = self.config['maildir'] + '/%s' % (sname)
                    break
        if authgood == 1:
            self.logger( 'Authentication passed for user: ' + name )
            return True
        else:
            self.logger( 'Authentication failed for user: ' + name )
            return False

    def brepopList( self, user ):
        self.inbox = self.newmessage( user, '' )
        for mdict in iter( self.inbox ):
            for mid in mdict.keys():
                self.message.append( mid )

    def newmessage( self, user, ip ):
        ct = 0
        message = mid = ''
        self.brepopLockHandler()
        mailbox = open( self.mbox, 'r' )
        for ln in mailbox:
            if match( '^From ', ln ) and ct > 0:
                # new message 
                if search( '\S+', message ):
                    # ...but not the first
                    if mid:
                        self.inbox.append( {mid:message} )
                    else:
                        self.spam.append( message )
                message = mid = ''
            midmatch = search('^Message-I[Dd]{1}: (\S+)$', ln )
            if midmatch and not mid:
                mid = midmatch.group(1)
            message += ln
            ct += 1
        if mid:
            self.inbox.append( {mid:message} )
        else:
            self.spam.append( message )
        mailbox.close()
        self.brepopLockHandler()
        return self.inbox

    def boxsize( self, box ):
        totalsize = 0
        for msg in box:
            totalsize += self.brepopSize( msg )
        return totalsize

    def brepopSize( self, mid ):
        for mydict in self.inbox:
            if mid in mydict:
                return len( mydict[mid] )

    def brepopDelete( self, user ):
        if len( self.deleted ):
            self.brepopLockHandler()
            boxobj = open( self.mbox, 'w' )
            for mydict in self.inbox:
                for mkey in mydict.keys():
                    if self.deleted[mkey[0]] != 1:
                        boxobj.write( mydict[mkey[0]] )
            boxobj.close()
            self.brepopLockHandler()
        if len( self.spam ):
            spamobj = open( self.spamlog, 'a' )
            for spam_msg in self.spam:
                spamobj.write( spam_msg )
            spamobj.close()
        return 1

    def scanlisting( self, mnum ):
        mydict = self.inbox[mnum - 1]
        mykeys = mydict.keys()
        return '%ld %ld' % (mnum, len( mydict[mykeys[0]] ))

    def brepopLockHandler( self ):
        if self.lock == 0:
            connected = 0
            listener = None
            rport = random.randint( 7200, 7299 )
            while connected == 0:
                listener = socket.socket( socket.AF_INET, socket.SOCK_STREAM, 0 )
                try:
                    listener.bind( ('127.0.0.1', rport) )
                except OSError:
                    listener.close()
                    rport += 1
                    continue
                listener.listen( 5 )
                if listener is None:
                    rport += 1
                    if rport == 7300:
                        rport = 7200
                else:
                    connected = 1
            pid = os.fork()
            if pid > 0:
                # os.waitid( os.P_PID, pid, os.WNOHANG )
                os.waitpid( pid, os.WNOHANG )
                (comm, junk2) = listener.accept()
                buf = str( comm.recv( 1024 ).decode('UTF-8') ).rstrip()
                listener.close()
                self.lock = int( buf )
            elif pid == 0:
                # print( " ".join( [self.config['postlock_path'], self.mbox, self.config['brepop_path'], '-p', str(rport)] ) )
                os.execl( self.config['postlock_path'], 'postlock', self.mbox, self.config['brepop_path'], '-p', str(rport) )
        else:
            os.kill( self.lock, signal.SIGTERM )
            self.lock = 0
        return 1

    def brepopRetrieve( self, mid ):
        for mdict in self.inbox:
            for mkey,mval in mdict.items():
                if mkey == mid:
                    return mval

    def capabilities( self, state ):
        response = '+OK capability list follows.'
        capa = [ 'TOP', 'USER', 'UIDL', 'IMPLEMENTATION brepop version_' + self.version ]
        # we're skipping logindelay and expiretime functionality here.  the logic exists in
        # the perl version, but is unused because the parameters are unset
        return response + self.EOL + self.EOL.join( capa ) + self.EOL + '.' + self.EOL

    # Handler functions.  Start with common between "unauthenticated" and authenticated sessions

    def handle_version( self, mob ):
            sys.stdout.write('+OK brepop ' + self.version + self.EOL )

    def handle_capa( self, mob ):
        sys.stdout.write( self.capabilities( self.state ) )

    # End common handler functions

    # Handler functions for unauthenticated sessions:

    def handle_quit_noauth( self, mob ):
            sys.stdout.write('+OK Bye, closing connection...' + self.EOL)
            sys.stdin.close()
            self.logger( 'Closing session for unauthenticated user' )
            return 'QUIT'

    def handle_user( self, mob ):
            self.user['name'] = mob.group( 1 )
            self.user['pass'] = ''
            sys.stdout.write('+OK ' + self.user['name'] + ' selected' + self.EOL )

    def handle_pass( self, mob ):
        self.user['pass'] = mob.group( 1 )
        self.user['ip'] = '127.0.0.1'
        if self.user['name'] :
            if self.brepopAuth( self.user ):
                self.state = 1
                self.brepopList( self.user['name'] )
                ct = len( self.message )
                bsize = self.boxsize( self.message )
                sys.stdout.write('+OK ' + self.user['name'] + "'s maildrop has " + \
                        str(ct) + ' messages (' + str(bsize) + ' octets)' + self.EOL)
            else:
                self.user['name'] = ''
                sys.stdout.write('-ERR Unable to lock maildrop at this time with that auth info' + self.EOL)
        else:
            sys.stdout.write('-ERR You can only use PASS right after USER' + self.EOL)

    def handle_apop( self, mob ):
        sys.stdout.write('-ERR APOP authentication not yet implemented, try USER/PASS' + self.EOL)

    def handle_default_noauth( self, mob ):
        sys.stdout.write('-ERR That must be something I have not implemented yet, or you need to authenticate.' + self.EOL)

    # End handler functions for unauthenticated sessions

    # Handler functions for autheticated sessions:

    def handle_stat( self, mob ):
        ct = len( self.message )
        bsize = self.boxsize( self.message )
        sys.stdout.write("+OK " + str(ct) + " " + str(bsize) + self.EOL)

    def handle_list( self, mob ):
        mnum = mob.group( 1 )
        if mnum:
            if int( mnum ) <= len(self.message):
                slist = self.scanlisting( mnum )
                sys.stdout.write('+OK ' + slist + self.EOL )
            else:
                ct = len( self.message )
                sys.stdout.write('-ERR Cannot find message ' + mnum + ' (only ' + ct + ' in drop)' + self.EOL)
        else:
            mnum = 1
            sys.stdout.write('+OK scan listing follows' + self.EOL)
            for mdict in self.inbox:
                for mid, mtext in mdict.items():
                    if not mid in self.deleted:
                        sys.stdout.write( str(mnum) + ' ' + str(len(mtext)) + self.EOL)
                mnum += 1
            sys.stdout.write('.' + self.EOL)

    def handle_uidl( self, mob ):
        mnum = 0
        if len( mob.group(1) ):
            mnum = int( mob.group( 1 ) )
        if mnum:
            if mnum <= len(self.message):
                sys.stdout.write('+OK' + str(mnum) + ' ' + self.message[mnum-1] + self.EOL)
            else:
                ct = len( self.message )
                sys.stdout.write('-ERR Cannot find message $msgnum (only ' + str(ct) + ' in drop)' + self.EOL)
        else:
            mnum = 1
            sys.stdout.write('+OK message-id listing follows' + self.EOL)
            for mid in self.message:
                if not mid in self.deleted:
                    sys.stdout.write( str(mnum) + ' ' + str(mid) + self.EOL)
                    mnum += 1
            sys.stdout.write('.' + self.EOL)

    def handle_top( self, mob ):
        (mnum, lct) = int( mob.group( 1, 2 ) )
        (headers, body) = self.brepopRetrieve( self.message[mnum - 1] ).split("\n\n", 2)
        hlen = len(headers)
        blen = len(body)
        sys.stdout.write('+OK top of message follows (' + hlen + ' octets in head and ' + blen +\
                ' octets in body up to ' + lct + ' lines)' + self.EOL)
        lnum = 0
        for headln in headers.split("\n"):
            per = ''
            if match('^.', headln):
                per = '.'
            lnum += 1
            if lnum <= lct:
                sys.stdout.write(per + headln + self.EOL)
        sys.stdout.write('.' + self.EOL)

    def handle_retr( self, mob ):
        mnum = int( mob.group( 1 ) )
        if mnum <= len( self.message ):
            sys.stdout.write('+OK sending ' + str(mnum) + self.EOL)
            mid = self.message[mnum - 1]
            msg = self.brepopRetrieve( mid )
            if not search("\n\n", msg):
                self.logger('Suffering and pain')
            for msgline in msg.split("\n"):
                per = ''
                if match('^\.', msgline):
                    per = '.'
                sys.stdout.write(per + msgline + self.EOL)
            sys.stdout.write('.' + self.EOL)
        else:
            ct = len( self.message )
            sys.stdout.write('-ERR Cannot find message ' + str(mnum) + ' (only ' + str(ct) + ' in drop)' + self.EOL)

    def handle_dele( self, mob ):
        mnum = int( mob.group( 1 ) )
        if mnum <= len(self.message):
            self.deleted[self.message[mnum - 1]] = 1
            sys.stdout.write('+OK marking message number ' + str(mnum) + ' for later deletion' + self.EOL)
        else:
            ct = len(self.message)
            sys.stdout.write('-ERR Cannot find message ' + str(mnum) + ' (only ' + ct + ' in drop)' + self.EOL)

    def handle_noop( self, mob ):
        sys.stdout.write('+OK nothing to do.' + self.EOL)

    def handle_reset( self, mob ):
        self.deleted = {}
        sys.stdout.write('+OK now no messages are marked for deletion at end of session.' + self.EOL )

    def handle_default_auth( self, mob ):
        sys.stdout.write('-ERR That must be something I have not implemented yet.' + self.EOL)

    def handle_quit_auth( self, mob ):
        self.brepopDelete( self.user['name'] )
        sys.stdout.write('+OK Bye, closing connection...' + self.EOL)
        self.logger('Closing session for user: ' + self.user['name'] )
        return 'QUIT'

    # End handler functions for autheticated sessions

    # Object class external call-in point

    def handle_session( self ):
        mapObjectPtr = self.NoAuthObject
        defaultHandlerPtr = self.handle_default_noauth
        sys.stdout.write('+OK ' + self.options['welcome'] + self.EOL )
        sys.stdout.flush()
        for iline in sys.stdin:
            matched = 0
            if self.state == 1:
                mapObjectPtr = self.AuthObject
                defaultHandlerPtr = self.handle_default_auth
            else:
                mapObjectPtr = self.NoAuthObject
                defaultHandlerPtr = self.handle_default_noauth
            mhret = mapObjectPtr.mapHandler( iline )
            if mhret is not None:
                if mhret[0]( mhret[1] ) == 'QUIT':
                    return 1
            else:
                defaultHandlerPtr( mhret )
            sys.stdout.flush()
        self.logger('Client closed connection for user: ' + self.user['name'] )
        return 1

    # End

class LockingChild:
    def __init__( self, servport ):
        # print('connecting to port: ' + servport )
        mypid = str( os.getpid() )
        try:
            client = socket.create_connection( ('127.0.0.1', int(servport)) )
        except Exception as e:
            print("connection failed: " + str(e) )
        client.send( bytes( mypid, 'UTF-8') )
        time.sleep( 300 )

###########################
# Main deal
#
# Usage: brepop.py [-p|path_to_config_file]
#
###########################

conf_path = None
if len( sys.argv ) > 1:
    pt = 0
    if sys.argv[1] == '-p':
        pt = sys.argv[2]
        mycli = LockingChild( pt )
        sys.exit( 0 )
    else:
        for arg in sys.argv:
            if os.path.isfile( arg ):
                conf_path = arg
                break
else:
    servinst = BrePopServer( conf_path )
    if not servinst.initerror:
        servinst.handle_session()
        sys.exit( 0 )
    else:
        sys.exit( 1 )
