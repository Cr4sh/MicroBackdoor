import os

class Conf(object):

    # remote server address where backdoor_server.py is running
    SERVER_ADDR = '127.0.0.1'

    SERVER_DIR_PATH = os.path.dirname(os.path.realpath(__file__))
    CERT_DIR_PATH = SERVER_DIR_PATH
    CERT_NAME = 'server'

    # host/port where backdoor_server.py is listening for client connection
    LISTEN_HOST = '0.0.0.0'
    LISTEN_PORT = 28115

    # host/port for backdoor_server.py process communication RPC
    MANAGER_HOST = '127.0.0.1'
    MANAGER_PORT = 21377

    # host/port for backdoor_server.py control endpoints
    MAPPER_HOST = '127.0.0.1'
    MAPPER_PORT_MIN = 30000
    MAPPER_PORT_MAX = 60000

    # server name field for HTTP response headers
    HTTP_SERVER_NAME = 'nginx'
    HTTP_STATIC = os.path.join(SERVER_DIR_PATH, 'static')

    # admin pannel location, login and password
    HTTP_PATH = '/c3a1f6e1'
    HTTP_RELAM = 'Restricted Access'
    HTTP_USERS = { 'admin': 'jGCq4WBabhGSJtUY' }
    HTTP_DIGEST_KEY = 'a565c27146791cfb'

    # address and port of the web server
    HTTP_ADDR = '0.0.0.0'
    HTTP_PORT = 24416

    REDIS_HOST = '127.0.0.1'
    REDIS_PORT = 6379
    REDIS_DB = 15

    CLIENT_VERSION = 2
    CLIENT_TIMEOUT = 120 # in seconds

    LOG_DIR_PATH = os.path.join(SERVER_DIR_PATH, 'logs')
    DOWNLOADS_DIR_PATH = os.path.join(SERVER_DIR_PATH, 'downloads')

    LOG_FILE_PATH = os.path.join(SERVER_DIR_PATH, 'server.log')
    LOG_FILE_PATH_HTTP = os.path.join(SERVER_DIR_PATH, 'access.log')

    PGID_FILE_PATH = os.path.join(SERVER_DIR_PATH, 'server.pgid')

    TIME_FORMAT = '%m/%d/%y %I:%M:%S %p'
    VERBOSE = False

#
# EoF
#
