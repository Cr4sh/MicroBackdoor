#!/usr/bin/env python3
# Author: Silas Cutler
# Config extractor for MicroBackdoor  (https://github.com/Cr4sh/MicroBackdoor)

import sys
import struct
import pefile
import hexdump

def main():
	if len(sys.argv) != 2:
		print("Usage: {} <MicroBackdoor Sample>\n".format(sys.argv[0]))
		return False

	try:
		indata = open(sys.argv[1], 'rb').read()
		pe = pefile.PE(data=indata, fast_load=True)
	except Exception as e :
		print("[x] Unable to parse {}. Error: {}".format(sys.argv[1], e))
		return False


	for section in pe.sections:
		if b'.conf' in section.Name:
			config = indata[section.PointerToRawData: section.PointerToRawData + section.Misc_VirtualSize]
			if b"END CERTIFICATE" in config and len(config) > 1000:
				c2_server = config[:32].strip().replace(b'\x00', b'').decode("utf-8") 
				c2_port   = struct.unpack('<h', config[32:34])[0]
				cert      = config[34:].strip().replace(b'\x00', b'').decode("utf-8") 


				print("C2 Server Address: {}:{}".format(c2_server, c2_port))
				print("Embedeed cert:\n{}".format(cert)) 
				return True
	print("[X] Unable to find MicroBackdoor configuration")	

if __name__ == "__main__":
	main()

