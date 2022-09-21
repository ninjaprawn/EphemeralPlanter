import pefile
import struct
import sys

class Dll():
    def __init__(self, file_name: str):
        self.file_name = file_name
        self._pe = pefile.PE(file_name)
        self.imports = {}
        self.base_addr = self._pe.OPTIONAL_HEADER.ImageBase
        self.entry_point = self._pe.OPTIONAL_HEADER.AddressOfEntryPoint + self.base_addr
        if self._pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0:
            self.entry_point = 0
        self._imports_reverse_lookup = {}
        self.exports = {}
        self.sections = []
        self._sections_lookup = {}
        self.dll_main = 0
        self._setup()

    def _setup(self):
        # Setup imports
        if hasattr(self._pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self._pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    # TODO: Handle unique cases wheres there are multiple imports of the same function name
                    if imp.name is not None:
                        self.imports[imp.name.decode()] = imp.address
                        self._imports_reverse_lookup[imp.address] = imp.name.decode()
        # Setup exports
        if hasattr(self._pe, "DIRECTORY_ENTRY_EXPORT"):        
            for exp in self._pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name != None:
                    self.exports[exp.name.decode()] = self._pe.OPTIONAL_HEADER.ImageBase + exp.address
        # Setup sections
        for section in self._pe.sections:
            self.sections.append(section)
            # TODO: Handle unique cases where there are multiple of the same section name
            clean_name = section.Name.decode()
            clean_name = clean_name[:clean_name.index("\x00")]
            self._sections_lookup[clean_name] = section
        if self.entry_point != 0:
            self.guess_dll_main()

    def get_name_for_import(self, va):
        if va not in self._imports_reverse_lookup:
            return None
        return self._imports_reverse_lookup[va]

    def get_export_va(self, name):
        if name not in self.exports:
            return None
        return self.exports[name]

    def get_section(self, name):
        if name not in self._sections_lookup:
            return None
        return self._sections_lookup[name]

    def get_section_for_va(self, va):
        for section in self.sections:
            section_data = section.get_data()
            section_va_start = section.VirtualAddress + self._pe.OPTIONAL_HEADER.ImageBase
            if va >= section_va_start and va < section_va_start + len(section_data):
                return section
        return None

    def has_export(self, name):
        if name in self.exports:
            return True
        return False

    # Look for a data section. Doesn't currently work on obfuscated DLLs
    def get_section_for_data_va(self, va):
        potential_section = self.get_section_for_va(va)
        if potential_section is None:
            return None
        clean_name = potential_section.Name.decode()
        clean_name = clean_name[:clean_name.index("\x00")]
        if clean_name == ".data" or clean_name == ".rdata":
            return potential_section
        return None

    def get_bytes_for_va(self, va, n):
        potential_section = self.get_section_for_va(va)
        if potential_section is None:
            return None
        rva = va - self._pe.OPTIONAL_HEADER.ImageBase - potential_section.VirtualAddress
        return potential_section.get_data()[rva:rva+n+1]

    def get_utf8_for_va(self, va):
        potential_section = self.get_section_for_data_va(va)
        if potential_section is None:
            return None
        rva = va - self._pe.OPTIONAL_HEADER.ImageBase - potential_section.VirtualAddress
        section_data = potential_section.get_data()
        n = 0
        for i in range(rva, len(section_data)):
            if section_data[i] == 0x00: # NULL terminator
                n = i
                break
        return section_data[rva:n+1]
        
    def get_utf16_for_va(self, va):
        potential_section = self.get_section_for_data_va(va)
        if potential_section is None:
            return None
        rva = va - self._pe.OPTIONAL_HEADER.ImageBase - potential_section.VirtualAddress
        section_data = potential_section.get_data()
        n = 0
        for i in range(rva, len(section_data), 2):
            if section_data[i] == 0x00 and section_data[i+1] == 0x00: # NULL terminator
                n = i+1
                break
        return section_data[rva:n+1]

    # Use this if unknown type of string
    def get_utf_string_for_va(self, va):
        potential_section = self.get_section_for_data_va(va)
        if potential_section is None:
            return None
        rva = va - self._pe.OPTIONAL_HEADER.ImageBase - potential_section.VirtualAddress
        section_data = potential_section.get_data()
        if section_data[rva] != 0x0 and section_data[rva+1] == 0x0 and section_data[rva+3] == 0x0:
            return self.get_utf16_for_va(va)
        return self.get_utf8_for_va(va)

    # Determine the address of DllMain 
    def guess_dll_main(self):
        text_section = self.get_section_for_va(self.entry_point)
        if text_section is None:
            print("couldn't find section")
            return
        address_offset = self.entry_point - self.base_addr
        section_data = text_section.get_data()
        text_addr_base = text_section.VirtualAddress + self.base_addr
        # Find first jump call (valid is within section)
        idx = self.entry_point - text_addr_base
        crt_func_idx = None
        while idx < len(section_data):
            if section_data[idx] == 0xe9: # jmp start
                jmp_addr = idx+text_addr_base
                jmp_val = struct.unpack("I", section_data[idx+1:idx+5])[0] 
                # jmp adds to addr after instruction (5 bytes), and is a 32bit val
                jmp_dst = ((idx + jmp_val + 5) & 0xFFFFFFFF) + text_addr_base
                crt_func_idx = jmp_dst - text_addr_base
                break
            idx += 1
        if crt_func_idx is None:
            return
        # Find 2 internal calls consecutive of each other which call dllmain
        idx = crt_func_idx
        candidate = 0
        while idx < len(section_data):
            if section_data[idx] == 0xe8: # call start
                jmp_addr = idx+text_addr_base
                jmp_val = struct.unpack("I", section_data[idx+1:idx+5])[0]
                # jmp adds to addr after instruction (5 bytes), and is a 32bit val
                jmp_dst = ((idx + jmp_val + 5) & 0xFFFFFFFF) + text_addr_base
                if jmp_dst != candidate:
                    candidate = jmp_dst
                else:
                    self.dll_main = jmp_dst
                    break
            idx += 1

    def set_bytes_at_va(self, va, bytes):
        self._pe.set_bytes_at_rva(va - self.base_addr, bytes)
  
# Generate an x64 call instruction to a specific address
def generate_call_instruction(src_addr, dst_addr):
    call_part = b"\xFF\x15"
    call_offset = dst_addr - (src_addr+6)
    if call_offset < 0:
        call_offset += 2**32
    return bytes(bytearray(call_part) + bytearray(struct.pack("I", call_offset)))

def generate_jmp_instruction(src_addr, dst_addr):
    call_part = b"\x48\xe9"
    call_offset = dst_addr - (src_addr+6)
    if call_offset < 0:
        call_offset += 2**32
    return bytes(bytearray(call_part) + bytearray(struct.pack("I", call_offset)))


# Actual Code
testing_dll = Dll("oo2net_9_win64.dll")

if testing_dll.dll_main == 0:
    print("[!] Could not find `DllMain`")
    sys.exit()
print("[+] Found `DllMain` ({})".format(hex(testing_dll.dll_main)))

text_addr_base = testing_dll.get_section(".text").VirtualAddress + testing_dll.base_addr

# TODO: Figure out a thing to find a good spot for writing custom code. Using this hard coded address for now
custom_part = 0x180008000
print("[+] Found section to overwrite ({})".format(hex(custom_part)))

# Overwrite DllMain with jmp
testing_dll.set_bytes_at_va(testing_dll.dll_main, generate_jmp_instruction(testing_dll.dll_main, custom_part))

# Create a new DllMain that just disables ThreadCalls
c_addr = custom_part+text_addr_base

# Get code from a DLL, and fix it to be copied into another DLL
def get_custom_code(start_addr, global_imports, target_func_name="DllMain"):
    dll = Dll("E:\\gamehax\\lostark\\LostArkRev\\EphL\\x64\\Release\\EphemeralLoader.dll")

    # Get the start address of the function to copy
    target_func_addr = dll.get_export_va(target_func_name)
    if not target_func_addr:
        return None
    print(f"{target_func_name} address is {hex(target_func_addr)}")

    # Grab .text section and .data section
    text_section = dll.get_section(".text")
    if text_section is None:
        return None
    data_section = dll.get_section(".rdata")
    if data_section is None:
        return None

    data_section_data = data_section.get_data()
    data_addr_base = data_section.VirtualAddress + dll.base_addr
    text_section_data = text_section.get_data()
    text_addr_base = text_section.VirtualAddress + dll.base_addr
    target_func_rva = target_func_addr - text_addr_base
    blocks_to_copy = []
    data_to_copy = []
    external_call_idxs = []
    potential_end = 0
    for i in range(len(text_section_data)):
        if potential_end != 0 and i > potential_end:
            print("Should be finished now!")
            break
        current_addr = text_addr_base+i
        if text_section_data[i] == 0xff and text_section_data[i+1] == 0x15: # Call ext
            # Get operand
            call_op = struct.unpack("I", text_section_data[i+2:i+6])[0]
            # Get the actual address call_op is referencing
            actual_addr = current_addr + 6 + call_op
            potential_import_name = dll.get_name_for_import(actual_addr)
            if potential_import_name is not None:
                if potential_import_name in global_imports:
                    external_call_idxs.append((i, potential_import_name))
                else:
                    print(f"Import {potential_import_name} is not in main binary!")
                    return None
        elif text_section_data[i]&0xF8 == 0x58 and text_section_data[i+1] == 0xc3 and text_section_data[i+2] == 0x0: # POP->RET
            # Note that normally, POP instruction is 0x58 + register as a value. So we check for a general POP followed by a RET
            # TODO: Add proper end determination
            potential_end = i+2
            print("POP->RET found at " + hex(potential_end+text_addr_base))
            break
            dst_op = struct.unpack("I", text_section_data[i+2:i+6])[0]
            dst = i + 6 + dst_op
            for j in range(dst, len(text_section_data)):
                if text_section_data[j] == 0xc3: # RET found
                    potential_end = j+1
                    break
        elif text_section_data[i] == 0xe8: # Call to local function
            call_op = struct.unpack("I", text_section_data[i+1:i+5])[0]
            actual_addr = current_addr + 5 + call_op
            if actual_addr >= text_addr_base and actual_addr < text_addr_base+len(text_section_data):
                print("Call found!")
                blocks_to_copy.append((i, actual_addr))
        elif text_section_data[i]&0x48 == 0x48 and text_section_data[i+1] == 0x8d and text_section_data[i+2]&0b11000111 == 0b00000101: # LEA realtive to rip
            # Last condition is for checking RIP relative mode. 
            op_offset = struct.unpack("I", text_section_data[i+3:i+7])[0]
            actual_addr = current_addr + 7 + op_offset            
            if actual_addr >= data_addr_base and actual_addr < data_addr_base+len(data_section_data):
                print("Data found!")
                data_to_copy.append((i, actual_addr))

    target_func_block = text_section_data[target_func_rva:potential_end]

    out = bytearray(target_func_block)

    # Fix import calls to point to the target DLL imports
    for call in external_call_idxs:
        offset_of_code, import_name = call
        call_ins = generate_call_instruction(start_addr + offset_of_code, global_imports[import_name])
        # Replace the current call with the new (corrected) one
        out[offset_of_code:offset_of_code+6] = call_ins

    # Get the blocks of code that are called to be copied
    other_blocks = {} # Real address : code body
    for bl in blocks_to_copy:
        if bl[1] not in other_blocks:
            block_rva = bl[1] - text_addr_base
            sz = 0
            for i in range(block_rva, len(text_section_data)):
                # TODO: Add proper end determination
                if text_section_data[i] == 0xc3: # RET
                    sz = i
                    break
            other_blocks[bl[1]] = text_section_data[block_rva:sz+1]

    # Add blocks to output and track the offset to them.
    added = {}
    for bl in blocks_to_copy:
        if bl[1] not in added:
            added[bl[1]] = len(out)
            out += other_blocks[bl[1]]
        ins_offset = bl[0]
        new_offset_to_block = added[bl[1]]-(ins_offset+5)
        by = struct.pack("I", new_offset_to_block)
        out[ins_offset+1:ins_offset+5] = by

     # Get the blocks of data that are referenced to be copied. Can only copy null-terminated strings
    other_data = {} # Real address : data
    for bl in data_to_copy:
        if bl[1] not in other_data:
            block_rva = bl[1] - data_addr_base
            sz = 0
            is_unicode = False
            if data_section_data[block_rva] != 0x0 and data_section_data[block_rva+1] == 0x0 and data_section_data[block_rva+3] == 0x0:
                is_unicode = True
            for i in range(block_rva, len(data_section_data)):
                if is_unicode:
                    if data_section_data[i] == 0x00 and data_section_data[i+1] == 0x00 and data_section_data[i+2] == 0x00: # NULL terminator
                        sz = i+2
                        break
                else:
                    if data_section_data[i] == 0x00: # NULL terminator
                        sz = i
                        break
            other_data[bl[1]] = dll.get_utf_string_for_va(bl[1])
            
    # Add blocks to output and track the offset to them.
    added_data = {}
    for bl in data_to_copy:
        if bl[1] not in added_data:
            # need to 4byte align
            padding = 4-(len(out)&3)
            for i in range(padding):
                out += b"\x00"
            added_data[bl[1]] = len(out)
            out += other_data[bl[1]]
        ins_offset = bl[0]
        new_offset_to_block = added_data[bl[1]]-(ins_offset+7)
        by = struct.pack("I", new_offset_to_block)
        out[ins_offset+3:ins_offset+7] = by
    
    return bytes(out)


testing_dll.set_bytes_at_va(custom_part, get_custom_code(custom_part, testing_dll.imports))


'''# Call DisableThreadLibraryCalls
pe.set_bytes_at_rva(c_addr, generate_call_instruction(imports["DisableThreadLibraryCalls"], c_addr+pe.OPTIONAL_HEADER.ImageBase))
c_addr += 6
# PUSH RCX
pe.set_bytes_at_rva(c_addr, b"\x51")
c_addr += 1
# LEA RCX, qword ptr [<TO FILL>]
pe.set_bytes_at_rva(c_addr, b"\x48\x8D\x0D\x00\x00\x00\x00")
loc_to_mov_ptr = c_addr+3
c_addr += 7
# Call OutputDebugStringA
pe.set_bytes_at_rva(c_addr, generate_call_instruction(imports["OutputDebugStringA"], c_addr+pe.OPTIONAL_HEADER.ImageBase))
c_addr += 6
# POP RCX
pe.set_bytes_at_rva(c_addr, b"\x59")
c_addr += 1
# MOV EAX,0x1
pe.set_bytes_at_rva(c_addr, b"\xB8\x01\x00\x00\x00")
c_addr += 5
# RET
pe.set_bytes_at_rva(c_addr, b"\xC3")
c_addr += 1
# Custom string
pe.set_bytes_at_rva(c_addr, b"Injected >:)\x00\x00\x00")
# Fix original MOV to point to the string
pe.set_bytes_at_rva(loc_to_mov_ptr, struct.pack("I", c_addr-(loc_to_mov_ptr+4)))'''



testing_dll._pe.write(filename="oo2net_9_win64.custom.dll")
print("[+] Written exe")