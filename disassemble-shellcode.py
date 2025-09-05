#!/usr/bin/env python3
import os
import sys
import textwrap
import subprocess

OBJ_TMP_FILE = '/tmp/shellcode-assemble.o'

def cleanup():
    if os.path.isfile(OBJ_TMP_FILE):
        os.remove(OBJ_TMP_FILE)


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
        print('\nShellcode size: {0} bytes'.format(len(contents)))
    except Exception as e:
        print('Something went wrong while decoding your shellcode.')
        print(e)
        return 1

    cleanup()

    f = open(OBJ_TMP_FILE, 'wb')
    f.write(contents)
    f.close()

    print('\nWhich architecture are you using?')
    print('1 - x86')
    print('2 - x64 (Default)')

    ans = input('\nSelect an option: ').strip()

    if ans == '1':
        arch = 'i386'    

    elif ans == '2' or ans == '':
        arch = 'i386:x86-64'

    else:
        print('Invalid option')
        return 1

    print('\n\n\nDisassembling for architecture {0}'.format(arch))
    result = subprocess.Popen('objdump -z -M intel -b binary -m {0} -D {1} 2>&1'.format(arch, OBJ_TMP_FILE), shell=True, stdout=subprocess.PIPE)
    result.wait()
    output = result.communicate()[0]
    
    if result.returncode != 0:
        print(output)
        print('Something went wrong while decompiling shellcode.')
        return 1

    output = output.decode()
    i = output.find('<.data>:\n')
    i = output.rfind('\n', 0, i)

    output = output[i:]
    
    print('\n')
    print('---------- [ Objdump Output (Intel syntax) ]----------\n{0}\n'.format(output))


if __name__ == '__main__':
    ret = main()
    cleanup()
    sys.exit(ret)
