#!/usr/bin/python
# -*- coding: utf8 -*-

import argparse
import string


def convert(data):
    output_str = ""

    for i in range(len(data)):
        current = data[i]
        o = lambda x: x if isinstance(x, int) else ord(x) # handle data being bytes not string
        output_str += chr(o(current))

    result = '0x' + ',0x'.join(hex(ord(x))[2:] for x in output_str)
    return result


if __name__ == '__main__':
	#------------------------------------------------------------------------
	# Parse arguments
	print("Convert .bin to csharp format\n")
	print("Author: James Yeung\n")
	parser = argparse.ArgumentParser()
	parser.add_argument("shellcodeFile", help="File name containing the raw shellcode to be converted")
	args = parser.parse_args() 

	#------------------------------------------------------------------------
	# Open shellcode file and read all bytes from it
	try:
		shellcodeBytes = open(args.shellcodeFile, "rb").read()
		print ("[*]: Shellcode file [{}] successfully loaded".format(args.shellcodeFile))
	except IOError:
		print ("[!] Could not open or read file [{}]".format(args.shellcodeFile))
		quit()

	print ("[*]: Shellcode size: [{}] bytes".format(len(shellcodeBytes)))

	transformedShellcode = convert(shellcodeBytes)
	print(transformedShellcode)
