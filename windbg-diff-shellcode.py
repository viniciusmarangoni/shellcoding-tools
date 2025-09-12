#!/usr/bin/env python3
import os
import sys
import textwrap
import subprocess


def normalize_windbg_line(line):
    line = line.strip()
    if not line:
        return ''

    i = line.rfind('  ')
    if i != -1:
        line = line[:i]

    splitted = line.split()
    if len(splitted[0]) > 2:
        splitted = splitted[1:]

    joined = ' '.join(splitted)

    return joined

def normalize_windbg_memory(data):
    data = data.replace('\r', ' ')
    new_contents = ''
    for line in data.split('\n'):
        new_contents += ' ' + normalize_windbg_line(line)

    if not new_contents:
        return None

    if ' ' not in new_contents:
        # probably received a string in the hex form aabbccddeeff
        if len(contents) % 2 != 0:
            print('Odd number of chars. Are you sure you pasted the right memory contents?')
            return None

    else:
        splitted = new_contents.split()
        new_contents = ''
        for item in splitted:
            if len(item) == 1:
                item = '0{0}'.format(item)

            elif len(item) > 2:
                print('Could not identify the memory contents properly')
                return None

            new_contents += ' ' + item

        new_contents = new_contents.strip()
        return new_contents

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
        if len(contents) % 2 != 0:
            print('Odd number of chars. Are you sure you pasted the right shellcode?')
            return None

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


def show_diff(shellcode_contents, memory_contents):
    print('\n\n\n-------- DIFF --------\n')
    diff_char_index = -1
    for i, c in enumerate(shellcode_contents):
        if i >= len(memory_contents):
            break

        if c != memory_contents[i]:
            diff_char_index = i
            break

    j = max(0, i-2)
    if diff_char_index != -1:
        print('Shellcode index: {0}\n'.format(i))
        print('shellcode: {0}'.format(shellcode_contents[j:j+4].hex(sep=' ')))
        print('memory   : {0}'.format(memory_contents[j:j+4].hex(sep=' ')))

    print('\n-------- DIFF --------\n')

def main():
    if len(sys.argv) != 1:
        print('Usage:\n')
        print('Run this program. It will request for you to post your shellcode.')
        print('Then it will request you to paste your WinDBG memory.')
        return 1

    print('Paste your shellcode below and then press CTRL+d:\n')
    
    contents = sys.stdin.read()
    contents = normalize_input(contents)
    shellcode_contents = b''
    try:
        print('\n\nProcessing the following shellcode:')
        print(contents)

        contents = bytes.fromhex(contents)
        print('\nShellcode size: {0} bytes'.format(len(contents)))
        shellcode_contents = contents
    except Exception as e:
        print('Something went wrong while decoding your shellcode.')
        print(e)
        return 1

    print('\nNow paste the piece of memory from WinDBG that you want to compare and then press CTRL+d:\n')
    memory_contents = sys.stdin.read()
    memory_contents = normalize_windbg_memory(memory_contents)

    try:
        print('\n\nProcessing the following memory_contents:')
        print(memory_contents)

        memory_contents = bytes.fromhex(memory_contents)
        print('\nMemory contents size: {0} bytes'.format(len(memory_contents)))
    except Exception as e:
        print('Something went wrong while decoding memory contents.')
        print(e)
        return 1

    show_diff(shellcode_contents, memory_contents)



if __name__ == '__main__':
    ret = main()
    sys.exit(ret)
