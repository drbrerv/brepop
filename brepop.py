#!/usr/bin/env python3

import sys
import random
import os
import daemon
import socket
import socketserver
import signal
import time
import crypt
import yaml
import json

from re import match, search, I

class ConfigImage:
    def __init__( self, config_path=None ):
        self.initerror = False
        self.default_config = '/etc/brepop/config.yaml'
        self.config_filepath_keys = [
            'postlock_path',
            'brepop_path',
            'pwfile',
            'logfile',
            'spamlog'
        ]
        self.config_dir_keys = [
            'maildir'
        ]
        self.config = self.build_config( config_path ) or {}
        if not self.validate_config():
            self.initerror = True
            return

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
        rval = True
        if self.config is None:
            rval = False
        else:
            for item in self.config_filepath_keys:
                if item in self.config:
                    if not os.path.isfile( self.config[item] ):
                        print( "ConfigValidationError item: " + \
                                self.config[item] + \
                                " is not a valid filepath" )
                        rval = False
                else:
                    print("ConfigValidationError: " + item + " not set.")
                    rval = False
            for item in self.config_dir_keys:
                if item in self.config:
                    if not os.path.isdir( self.config[item] ):
                        print( "ConfigValidationError item: " + \
                                self.config[item] + \
                                " is not a valid directory" )
                        rval = False
                else:
                    print("ConfigValidationError: " + item + " not set.")
                    rval = False
            if 'bind_port' in self.config:
                if type(self.config['bind_port']) == type(str()):
                    bpint = int(self.config['bind_port'])
                    self.config['bind_port'] = bpint
        return rval

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
    def __init__( self, config_obj=None, inStream=None, outStream=None ):
        self.initerror = False
        if config_obj is None:
            ci = ConfigImage()
            self.config = ci.config
        else:
            self.config = config_obj
        self.user = {}
        self.inbox = []
        self.mbox = ''
        self.iline = ''
        self.state = 0
        self.lock = 0
        self.version = "1.0"
        self.message = []
        self.deleted = {}
        self.spam = []
        self.EOL = "\015\012"
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
        if inStream is not None:
            self.reader = inStream
        else:
            self.reader = sys.stdin
        if outStream is not None:
            self.writer = outStream
        else:
            self.writer = sys.stdout
        self.NoAuthObject = CodeDictMapper( self.code_map_noauth )
        self.AuthObject = CodeDictMapper( self.code_map_auth )
        self.logger('Server initialization complete')

    def write_abstractor( self, msg ):
        if isinstance( self.writer, socket.SocketType ):
            self.writer.send( bytes(msg, 'utf-8' ) )
        else:
            self.writer.write( msg )
            self.writer.flush()

    def read_abstractor( self ):
        if isinstance( self.reader, socket.SocketType ):
            self.iline = self.reader.makefile().readline()
        else:
            self.iline = self.reader.readline()
        if len( self.iline ) > 0 :
            return True
        else:
            return False

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
            self.write_abstractor('+OK brepop ' + self.version + self.EOL )

    def handle_capa( self, mob ):
        self.write_abstractor( self.capabilities( self.state ) )

    # End common handler functions

    # Handler functions for unauthenticated sessions:

    def handle_quit_noauth( self, mob ):
            self.write_abstractor('+OK Bye, closing connection...' + self.EOL)
            self.reader.close()
            self.logger( 'Closing session for unauthenticated user' )
            return 'QUIT'

    def handle_user( self, mob ):
            self.user['name'] = mob.group( 1 )
            self.user['pass'] = ''
            self.write_abstractor('+OK ' + self.user['name'] + ' selected' + self.EOL )

    def handle_pass( self, mob ):
        self.user['pass'] = mob.group( 1 )
        self.user['ip'] = '127.0.0.1'
        if self.user['name'] :
            if self.brepopAuth( self.user ):
                self.state = 1
                self.brepopList( self.user['name'] )
                ct = len( self.message )
                bsize = self.boxsize( self.message )
                self.write_abstractor('+OK ' + self.user['name'] + "'s maildrop has " + \
                        str(ct) + ' messages (' + str(bsize) + ' octets)' + self.EOL)
            else:
                self.user['name'] = ''
                self.write_abstractor('-ERR Unable to lock maildrop at this time with that auth info' + self.EOL)
        else:
            self.write_abstractor('-ERR You can only use PASS right after USER' + self.EOL)

    def handle_apop( self, mob ):
        self.write_abstractor('-ERR APOP authentication not yet implemented, try USER/PASS' + self.EOL)

    def handle_default_noauth( self, mob ):
        self.write_abstractor('-ERR That must be something I have not implemented yet, or you need to authenticate.' + self.EOL)

    # End handler functions for unauthenticated sessions

    # Handler functions for autheticated sessions:

    def handle_stat( self, mob ):
        ct = len( self.message )
        bsize = self.boxsize( self.message )
        self.write_abstractor("+OK " + str(ct) + " " + str(bsize) + self.EOL)

    def handle_list( self, mob ):
        mnum = mob.group( 1 )
        if mnum:
            if int( mnum ) <= len(self.message):
                slist = self.scanlisting( mnum )
                self.write_abstractor('+OK ' + slist + self.EOL )
            else:
                ct = len( self.message )
                self.write_abstractor('-ERR Cannot find message ' + mnum + ' (only ' + ct + ' in drop)' + self.EOL)
        else:
            mnum = 1
            self.write_abstractor('+OK scan listing follows' + self.EOL)
            for mdict in self.inbox:
                for mid, mtext in mdict.items():
                    if not mid in self.deleted:
                        self.write_abstractor( str(mnum) + ' ' + str(len(mtext)) + self.EOL)
                mnum += 1
            self.write_abstractor('.' + self.EOL)

    def handle_uidl( self, mob ):
        mnum = 0
        if len( mob.group(1) ):
            mnum = int( mob.group( 1 ) )
        if mnum:
            if mnum <= len(self.message):
                self.write_abstractor('+OK' + str(mnum) + ' ' + self.message[mnum-1] + self.EOL)
            else:
                ct = len( self.message )
                self.write_abstractor('-ERR Cannot find message $msgnum (only ' + str(ct) + ' in drop)' + self.EOL)
        else:
            mnum = 1
            self.write_abstractor('+OK message-id listing follows' + self.EOL)
            for mid in self.message:
                if not mid in self.deleted:
                    self.write_abstractor( str(mnum) + ' ' + str(mid) + self.EOL)
                    mnum += 1
            self.write_abstractor('.' + self.EOL)

    def handle_top( self, mob ):
        (mnum, lct) = int( mob.group( 1, 2 ) )
        (headers, body) = self.brepopRetrieve( self.message[mnum - 1] ).split("\n\n", 2)
        hlen = len(headers)
        blen = len(body)
        self.write_abstractor('+OK top of message follows (' + hlen + ' octets in head and ' + blen +\
                ' octets in body up to ' + lct + ' lines)' + self.EOL)
        lnum = 0
        for headln in headers.split("\n"):
            per = ''
            if match('^.', headln):
                per = '.'
            lnum += 1
            if lnum <= lct:
                self.write_abstractor(per + headln + self.EOL)
        self.write_abstractor('.' + self.EOL)

    def handle_retr( self, mob ):
        mnum = int( mob.group( 1 ) )
        if mnum <= len( self.message ):
            self.write_abstractor('+OK sending ' + str(mnum) + self.EOL)
            mid = self.message[mnum - 1]
            msg = self.brepopRetrieve( mid )
            if not search("\n\n", msg):
                self.logger('Suffering and pain')
            for msgline in msg.split("\n"):
                per = ''
                if match('^\.', msgline):
                    per = '.'
                self.write_abstractor(per + msgline + self.EOL)
            self.write_abstractor('.' + self.EOL)
        else:
            ct = len( self.message )
            self.write_abstractor('-ERR Cannot find message ' + str(mnum) + ' (only ' + str(ct) + ' in drop)' + self.EOL)

    def handle_dele( self, mob ):
        mnum = int( mob.group( 1 ) )
        if mnum <= len(self.message):
            self.deleted[self.message[mnum - 1]] = 1
            self.write_abstractor('+OK marking message number ' + str(mnum) + ' for later deletion' + self.EOL)
        else:
            ct = len(self.message)
            self.write_abstractor('-ERR Cannot find message ' + str(mnum) + ' (only ' + ct + ' in drop)' + self.EOL)

    def handle_noop( self, mob ):
        self.write_abstractor('+OK nothing to do.' + self.EOL)

    def handle_reset( self, mob ):
        self.deleted = {}
        self.write_abstractor('+OK now no messages are marked for deletion at end of session.' + self.EOL )

    def handle_default_auth( self, mob ):
        self.write_abstractor('-ERR That must be something I have not implemented yet.' + self.EOL)

    def handle_quit_auth( self, mob ):
        self.brepopDelete( self.user['name'] )
        self.write_abstractor('+OK Bye, closing connection...' + self.EOL)
        self.logger('Closing session for user: ' + self.user['name'] )
        return 'QUIT'

    # End handler functions for autheticated sessions

    # Object class external call-in point

    def handle_session( self ):
        mapObjectPtr = self.NoAuthObject
        defaultHandlerPtr = self.handle_default_noauth
        self.write_abstractor('+OK ' + self.options['welcome'] + self.EOL )
        # for iline in self.reader:
        while self.read_abstractor():
            matched = 0
            if self.state == 1:
                mapObjectPtr = self.AuthObject
                defaultHandlerPtr = self.handle_default_auth
            else:
                mapObjectPtr = self.NoAuthObject
                defaultHandlerPtr = self.handle_default_noauth
            mhret = mapObjectPtr.mapHandler( self.iline )
            if mhret is not None:
                if mhret[0]( mhret[1] ) == 'QUIT':
                    break
            else:
                defaultHandlerPtr( mhret )
        self.logger('Client closed connection for user: ' + self.user['name'] )
        return 1

    # End

class LockingChild:
    def __init__( self, servport ):
        mypid = str( os.getpid() )
        try:
            client = socket.create_connection( ('127.0.0.1', int(servport)) )
        except Exception as e:
            print("connection failed: " + str(e) )
        client.send( bytes( mypid, 'UTF-8') )
        time.sleep( 300 )

class SocketHandler( socketserver.BaseRequestHandler ):
    def handle( self ):
        self.serverInstance = BrePopServer( None, self.request, self.request )
        self.serverInstance.handle_session()

###########################
# Main deal
#
# Usage: brepop.py [-d|-p port] [path_to_config_file]
#
###########################

conf_path = None
lockingChild = daemonize = False
if len( sys.argv ) > 1:
    pt = 0
    for num, arg in enumerate( sys.argv[1:], 1 ):
        if os.path.isfile( arg ):
            conf_path = arg
        elif arg == '-p':
            pt = sys.argv[num + 1]
            lockingChild = True
        elif arg == '-d':
            daemonize = True
        else:
            print("USAGE: " + sys.argv[0] + " [-d|-p port] [path_to_config_file]")
            sys.exit( 1 )
if lockingChild:
    # LockingChild doesn't consume config (yet)
    mycli = LockingChild( pt )
    sys.exit( 0 )
cimg = ConfigImage( conf_path )
if cimg.initerror:
    sys.exit( 1 )
else:
    confimg = cimg.config
if daemonize:
    with daemon.DaemonContext():
        try:
            ssObj = socketserver.TCPServer( (confimg['bind_address'], confimg['bind_port']), SocketHandler )
        except KeyError:
            print("Unable to create socket sever with config: " + json.dumps(confimg) )
            sys.exit( 1 )
        except Exception as e:
            print("Unable to create socket server for unknown error, but check out your config: " + str(e)  + " config: " + json.dumps(confimg) )
            sys.exit( 1 )
        ssObj.serve_forever()
else:
    servinst = BrePopServer( confimg )
    if not servinst.initerror:
        servinst.handle_session()
        sys.exit( 0 )
    else:
        sys.exit( 1 )
