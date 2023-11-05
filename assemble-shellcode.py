#!/usr/bin/env python3
import os
import sys
import subprocess

ASSEMBLY_TMP_FILE = '/tmp/shellcode-assemble.s'
OBJ_TMP_FILE = '/tmp/shellcode-assemble.o'

def cleanup():
    if os.path.isfile(ASSEMBLY_TMP_FILE):
        os.remove(ASSEMBLY_TMP_FILE)

    if os.path.isfile(OBJ_TMP_FILE):
        os.remove(OBJ_TMP_FILE)

def main():
    if len(sys.argv) not in [1, 2] or (len(sys.argv) == 2 and sys.argv[1] in ['-h', '--help']):
        print('Usage:\n')
        print('\tIf you want to paste the assembly code in stdin:\n\t\t./{0}\n'.format(sys.argv[0]))
        print('\tIf you want to specify a file that contains the assembly code:\n\t\t./{0} file-with-assembly.s\n\n'.format(sys.argv[0]))
        print('We assume that you are using the Intel syntax. If you want to use the AT&T syntax, start your assembly code with the following line:\n\n.att_syntax noprefix\n\n')
        return 1

    if len(sys.argv) == 1:
        print('Paste your assembly code below and then press CTRL+d:\n')
        contents = sys.stdin.read().encode()

    elif len(sys.argv) == 2:
        file_path = sys.argv[1]
        if not os.path.isfile(file_path):
            print('File not found: {0}'.format(file_path))
            return 1

        f = open(file_path, 'rb')
        contents = f.read()
        f.close()

    cleanup()

    if b'.intel_syntax' not in contents:
        contents = b'.intel_syntax noprefix\n_main:\n' + contents + b'\n'

    if b'_start:' in contents:
        contents = contents.replace(b'_start:', b'_main:')

    f = open(ASSEMBLY_TMP_FILE, 'wb')
    f.write(contents)
    f.close()

    print('\nWhich architecture are you using?')
    print('1 - x86')
    print('2 - x64 (Default)')

    ans = input('\nSelect an option: ').strip()

    if ans == '1':
        arch = '-m32'    

    elif ans == '2' or ans == '':
        arch = '-m64'

    else:
        print('Invalid option')
        return 1

    dialect = '-masm=intel'

    print('\n\nAssembling instructions for architecture {0}'.format(arch))
    result = subprocess.Popen('gcc {0} {1} -c {2} -o {3} 2>&1'.format(arch, dialect, ASSEMBLY_TMP_FILE, OBJ_TMP_FILE), shell=True, stdout=subprocess.PIPE)
    result.wait()

    if result.returncode != 0 or not os.path.isfile(OBJ_TMP_FILE):
        print('Error while assembling: {0}\n'.format(result.returncode))
        print(result.communicate()[0].decode())

        return 1

    result = subprocess.Popen('objdump -z -M intel -d {0} 2>&1'.format(OBJ_TMP_FILE), shell=True, stdout=subprocess.PIPE)
    result.wait()
    output = result.communicate()[0]
    
    if result.returncode != 0:
        print('Something went wrong while getting shellcode.')
        print(output)
        return 1

    output = output.decode()
    i = output.find('<_main>:\n')
    i = output.rfind('\n', 0, i)

    output = output[i:]
    
    shellcode_lines = []
    for line in output.split('\n'):
        s = line.split('\t')

        if len(s) > 1:
            if len(s) > 2:
                shellcode_lines.append('\t'.join([s[1].strip(), s[2].strip()]))

            else:
                shellcode_lines.append(s[1].strip())

    python_shellcode = 'shellcode = bytearray('
    string_literal = 'char shellcode[] = "'

    largest_line = 0
    for line in shellcode_lines:
        s = len(line.split('\t')[0].replace(' ', '\\x'))
        if s > largest_line:
            largest_line = s

    largest_line = largest_line + 16

    for line in shellcode_lines:
        splitted = line.split('\t')
        line = splitted[0]

        string_literal += '\\x{0}'.format('\\x'.join(line.split()))
        line_to_append = '\n    b"\\x{0}"'.format('\\x'.join(line.split()))
            
        if len(splitted) == 2:
            line_to_append += '{0}# {1}'.format((' ' * (largest_line - len(line_to_append))), splitted[1])

        python_shellcode += line_to_append

    python_shellcode += '\n)'
    string_literal += '"'

    print('\n')
    print('---------- [ Objdump Output (Intel syntax) ]----------\n{0}\n'.format(output))
    print('---------- [ Python Bytearray ]----------\n{0}\n'.format(python_shellcode))
    print('---------- [ C String ]----------\n{0}\n'.format(string_literal))

    payload_size = (len(string_literal) - 21) // 4
    print('\n\nPayload size: {0} {1}'.format(payload_size, "bytes" if payload_size != 1 else "byte"))

    if '\\x00' in string_literal:
        print('!!! CAUTION - NULL BYTE FOUND !!!')


if __name__ == '__main__':
    ret = main()
    cleanup()
    sys.exit(ret)
