#!/usr/bin/env python3
import os
import sys
import struct

def normalize_line(line):
    line = line.strip().rstrip(';')
    i = line.find('=')
    if i != -1:
        line = line[i+1:].strip()

    line = line.replace('bytearray', ' ').strip()
    line = line.replace('(', ' ').replace(')', ' ').strip()

    if line.startswith('b"'):
        line = line[2:].strip()

    if line.startswith("b'"):
        line = line[2:].strip()

    line = line.strip('"').strip("'")
    line = line.replace('0x', ' ').strip().replace(',', ' ').strip()
    line = line.replace('\\x', ' ').strip()
    return line

def normalize_input(contents):
    new_contents = ''
    contents = contents.replace('\r', ' ')
    for line in contents.split('\n'):
        new_contents += ' ' + normalize_line(line)

    new_contents = new_contents.strip()
    if not new_contents:
        return None

    if ' ' not in new_contents:
        # probably received a string in the hex form aabbccddeeff
        if len(new_contents) % 2 != 0:
            print('Odd number of chars. Are you sure you pasted the right shellcode?')
            return None

        return new_contents

    else:
        splitted = new_contents.split()
        new_contents = ''
        for item in splitted:
            if len(item) == 1:
                item = '0{0}'.format(item)

            elif len(item) > 2:
                print('Could not identify your shellcode properly')
                return None

            new_contents += ' ' + item

        new_contents = new_contents.strip()
        return new_contents

def custom_hex(value):
    return '0x{0:016x}n'.format(value)


def main():
    if len(sys.argv) != 1:
        print('Usage:\n')
        print('\tRun the following command and just paste your shellcode in stdin:\n\t\t./{0}\n'.format(sys.argv[0]))
        return 1

    print('Paste your shellcode below and then press CTRL+d:\n')
    
    contents = sys.stdin.read()
    contents = normalize_input(contents)

    try:
        print('\n\nProcessing the following shellcode:')
        print(contents)

        contents = bytes.fromhex(contents)
        print('\nOriginal shellcode size: {0} bytes'.format(len(contents)))
    except Exception as e:
        print('Something went wrong while decoding your shellcode.')
        print(e)
        return 1
    
    contents = bytearray(contents)
    while len(contents) % 8 != 0:
        contents += bytearray([0x90])
    
    contents = bytes(contents)
    contents_copy = contents[:]
    result_array = []
    while len(contents) != 0:
        uint64_bytes = contents[:8]
        contents = contents[8:]
        result_array.append(struct.unpack('<Q', uint64_bytes)[0])
    
    print('Size after adding leading nops: {0}\n'.format(len(contents)))
    result_str = 'var shellcode = ['
    result_array = list(map(lambda x: custom_hex(x), result_array))
    result_str += ', '.join(result_array)
    result_str += '];'
    
    print('\n\n----------[ JavaScript Code ]----------\n')
    print('// shellcode:')
    print('// {0}'.format(contents_copy.hex(sep=' ')))

    print(result_str)
    print('\n')


    return 0 

if __name__ == '__main__':
    ret = main()
    sys.exit(ret)
