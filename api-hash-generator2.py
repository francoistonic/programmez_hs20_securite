import os
import unicorn
import unicorn.x86_const
import pefile

def emulate_murmurhash2(data):
    '''
    This function uses the Unicorn module to emulate the Murmurhash2 algorithm, it takes a string as first argument (ECX register) and returns the corresponding hash (EAX register).
    '''

    #Assembly code (copied from malware sample offset 0x0040838f)
    code = b"\x56\x57\x8B\xF9\x8B\xD7\x8D\x4A\x01\x8A\x02\x42\x84\xC0\x75\xF9\x2B\xD1\x8B\xF2\x83\xF6\x20\x83\xFA\x04\x7C\x4D\x53\x8B\xDA\xC1\xEB\x02\x6B\xC3\xFC\x03\xD0\x0F\xB6\x4F\x03\x0F\xB6\x47\x02\xC1\xE1\x08\x0B\xC8\x69\xF6\x95\xE9\xD1\x5B\x0F\xB6\x47\x01\xC1\xE1\x08\x0B\xC8\x0F\xB6\x07\xC1\xE1\x08\x83\xC7\x04\x0B\xC8\x69\xC9\x95\xE9\xD1\x5B\x8B\xC1\xC1\xE8\x18\x33\xC1\x69\xC8\x95\xE9\xD1\x5B\x33\xF1\x83\xEB\x01\x75\xBF\x5B\x83\xEA\x01\x74\x1C\x83\xEA\x01\x74\x0E\x83\xEA\x01\x75\x1D\x0F\xB6\x47\x02\xC1\xE0\x10\x33\xF0\x0F\xB6\x47\x01\xC1\xE0\x08\x33\xF0\x0F\xB6\x07\x33\xC6\x69\xF0\x95\xE9\xD1\x5B\x8B\xC6\xC1\xE8\x0D\x33\xC6\x69\xC8\x95\xE9\xD1\x5B\x5F\x5E\x8B\xC1\xC1\xE8\x0F\x33\xC1"
    CODE_OFFSET = 0x1000000

    try:
        mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)    # architecture x86 32 bits
        mu.mem_map(CODE_OFFSET, 4*1024*1024)
        mu.mem_write(CODE_OFFSET, code)
        libname = 0x7000000
 
        mu.mem_map(libname, 4*1024*1024)
        mu.mem_write(libname, data)
 
        stack_base = 0x00300000
        stack_size = 0x00100000

        mu.mem_map(stack_base, stack_size)
        mu.mem_write(stack_base, b"\x00" * stack_size)
 
        mu.reg_write(unicorn.x86_const.UC_X86_REG_ESP, stack_base + 0x800)
 
        mu.reg_write(unicorn.x86_const.UC_X86_REG_EBP, stack_base + 0x1000)
 
        mu.reg_write(unicorn.x86_const.UC_X86_REG_ECX, libname)

        mu.emu_start(CODE_OFFSET, CODE_OFFSET + len(code))

    except unicorn.UcError as e:
        print(f"Unicorn emulation error: {e}")

    result = mu.reg_read(unicorn.x86_const.UC_X86_REG_EAX)
    return result

def dump_hash_dlls():
    '''
    This function uses the pefile module to extract the APIs exported by the DLL files, and using emulate_murmurhash2(), returns the corresponding Murmurhash2 hash for each of them.
    '''

    dlls_dir = 'dlls_dir/'    # Directory where found Windows .DLL files

    for (dirpath, dirnames, filenames) in os.walk(dlls_dir):
        for filename in filenames:
            if filename.endswith('.dll'):

                pe = pefile.PE('{}'.format(dlls_dir+filename))

                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    export_name = exp.name

                    if not export_name:
                        continue

                    try:
                        export_hash = emulate_murmurhash2(export_name)
                        print(f'{hex(export_hash)} : {export_name.decode()}')
                    except Exception as err:
                        print('Exception occurred while emulating murmurhash2 with export_name: {}. Error: {} '.format(export_name, err))

                        continue

dump_hash_dlls()
