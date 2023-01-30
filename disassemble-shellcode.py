#!/usr/bin/env python3
import os
import sys
import textwrap
import subprocess

OBJ_TMP_FILE = '/tmp/shellcode-assemble.o'

def cleanup():
    if os.path.isfile(OBJ_TMP_FILE):
        os.remove(OBJ_TMP_FILE)


def normalize_input(contents):
    if '=' in contents:
        i = contents.find('=')
        contents = contents[i+1:]

    contents = contents.replace('\n', ' ').replace('\r', ' ')
    if 'bytearray' in contents:
        contents = contents.replace('bytearray', ' ')

    contents = contents.strip()

    if 'b"' in contents:
        contents = contents.replace('b"', ' ')

    if "b'" in contents:
        contents = contents.replace("b'", ' ')

    if "'" in contents:
        contents = contents.replace("'", "")

    if '"' in contents:
        contents = contents.replace('"', '')
    
    if ',' in contents:
        contents = contents.replace(',', ' ')

    if '0x' in contents:
        contents = contents.replace('0x', ' ')

    if '{' in contents:
        contents = contents.replace('{', ' ')

    if '}' in contents:
        contents = contents.replace('}', ' ')

    if '(' in contents:
        contents = contents.replace('(', ' ')

    if ')' in contents:
        contents = contents.replace(')', ' ')

    if '\\x' in contents:
        contents = contents.replace('\\x', ' ')

    contents = contents.strip()
    if ' ' not in contents:
        # probably received a string in the hex form aabbccddeeff
        if len(contents) % 2 != 0:
            print('Odd number of chars. Are you sure you pasted the right shellcode?')
            return None

    else:
        splitted = contents.split()
        new_contents = []

        for item in splitted:
            if len(item) != 2:
                print('')
                should_replace = False

                if len(item) % 2 != 0:
                    new_item = '0{0}'.format(item)
                else:
                    new_item = item

                eval_value = int('0x{0}'.format(new_item), 16)
                if eval_value <= 0xff:
                    new_value = eval_value.to_bytes(1, 'little').hex()
                    should_replace = True

                elif eval_value > 0xff and eval_value <= 0xffff:
                    new_value = eval_value.to_bytes(2, 'little').hex()
                    should_replace = True

                elif eval_value > 0xffff and eval_value <= 0xffffffff:
                    new_value = eval_value.to_bytes(4, 'little').hex()
                    should_replace = True

                elif eval_value > 0xffffffffff and eval_value <= 0xffffffffffffffff:
                    new_value = eval_value.to_bytes(8, 'little').hex()
                    should_replace = True

                else:
                    print('[Warning] Processing a strange hex value: "{0}". I dont know what it is. Expect errors.'.format(item))
                    should_replace = False
                    
                if should_replace:
                    print('[Warning] Processing a strange hex value: "{0}". I will assume it was 0x{1} and will pack to little endian ({2}) for you.'.format(item, item, new_value))
                    item = new_value

            new_contents.append(item)

        contents = ''.join(new_contents).strip()

    return contents


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
        print(' '.join(textwrap.wrap(contents, 2)))

        contents = bytes.fromhex(contents)
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
