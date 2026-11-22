use std::path::Path;
use std::process::Command;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use goblin::pe::PE;
use iced_x86::Decoder;
use iced_x86::DecoderOptions;
use iced_x86::Formatter;
use iced_x86::Instruction;
use iced_x86::NasmFormatter;
use itertools::Itertools;

const USAGE: &str =
    "usage: shellcode_gen <output dir> | shellcode_gen flatten <input.exe> <output.bin>";

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.as_slice() {
        [command, input, output] if command == "flatten" => {
            rewrite_shellcode(input, Path::new(output))
        }
        [output_path] => generate(Path::new(output_path)),
        _ => bail!(USAGE),
    }
}

/// Flattens every stage and writes the stages and GameScript exploits to `output_path`.
fn generate(output_path: &Path) -> Result<()> {
    if !output_path.exists() {
        std::fs::create_dir(output_path)?;
    }

    let stage1_output = output_path.join("stage1.bin");
    rewrite_shellcode(
        "../shellcode_stage1/target/x86_64-pc-windows-msvc/release/shellcode_stage1.exe",
        &stage1_output,
    )?;

    let stage1_network_output = output_path.join("stage1_network.bin");
    rewrite_shellcode(
        "../shellcode_stage1_network/target/x86_64-pc-windows-msvc/release/shellcode_stage1_network.exe",
        &stage1_network_output,
    )?;

    rewrite_shellcode(
        "../shellcode_stage2/target/x86_64-pc-windows-msvc/release/shellcode_stage2.exe",
        &output_path.join("stage2.bin"),
    )?;

    // generate the exploit code to load the stage1 code
    let gamescript_exploit = generate_gamescript_exploit(&stage1_output, true)?;

    // generate the exploit code to load the stage1 network code
    let gamescript_network_exploit = generate_gamescript_exploit(&stage1_network_output, false)?;

    let gs_path = output_path.join("gamescript_autosave.txt");
    std::fs::write(gs_path, gamescript_exploit.as_bytes())?;

    let gs_network_path = output_path.join("gamescript_autosave_network.txt");
    std::fs::write(gs_network_path, gamescript_network_exploit.as_bytes())?;

    println!("done! artifacts can be found in outputs/");

    Ok(())
}

/// Writes the `.text` section of the PE at `src_path` to `dst_path`. Callers
/// enter at offset 0, so a jump to the entry point precedes the code when the
/// entry point is elsewhere.
pub fn rewrite_shellcode(src_path: &str, dst_path: &Path) -> Result<()> {
    println!("[*] Flattening shellcode for file {src_path}");

    let buffer = std::fs::read(src_path)?;
    let pe = PE::parse(&buffer)?;
    let optional_header = pe
        .header
        .optional_header
        .context("PE has no optional header")?;
    let text = pe
        .sections
        .iter()
        .find(|section| section.name().ok() == Some(".text"))
        .context("PE has no .text section")?;

    // Nothing applies base relocations to the flattened code, so any absolute
    // address in it would point into the PE's preferred image base.
    let relocations = optional_header
        .data_directories
        .get_base_relocation_table()
        .map_or(0, |directory| directory.size);
    if relocations != 0 {
        bail!("{src_path} has {relocations:#x} bytes of base relocations; flattened code must be position independent");
    }

    let entry_offset = optional_header
        .standard_fields
        .address_of_entry_point
        .checked_sub(u64::from(text.virtual_address))
        .context("entry point precedes .text")?;

    let start = text.pointer_to_raw_data as usize;
    // The virtual size excludes the padding to the file alignment.
    let size = text.virtual_size as usize;
    let code = buffer
        .get(start..start + size)
        .context(".text extends past the end of the file")?;

    // Only `.text` is emitted, so the entry point must be inside it.
    if entry_offset >= size as u64 {
        bail!("entry offset {entry_offset:#x} is outside .text (size {size:#x})");
    }

    println!("[*] section text addr: {start:#x}, size: {size:#x}");
    println!("[*] entry offset: {entry_offset:#x}");

    let mut shellcode = entry_jump(entry_offset)?;
    shellcode.extend_from_slice(code);
    show_disassemble(&shellcode, 5);

    std::fs::write(dst_path, &shellcode)?;

    Ok(())
}

/// Returns the stub placed before `.text`. The code is position independent, so
/// moving it behind the stub needs no fixups. Patching the stub over the start of
/// `.text` instead would corrupt whichever function the linker placed there.
fn entry_jump(entry_offset: u64) -> Result<Vec<u8>> {
    const JMP_REL32: u8 = 0xE9;
    const JMP_REL32_LEN: usize = 5;
    const INT3: u8 = 0xCC;
    // Keeps the 16-byte alignment of the code and data in `.text`.
    const STUB_LEN: usize = 16;

    if entry_offset == 0 {
        return Ok(Vec::new());
    }

    // The displacement is relative to the end of the jump instruction.
    let displacement = entry_offset + (STUB_LEN - JMP_REL32_LEN) as u64;
    let displacement = i32::try_from(displacement).context("entry offset does not fit in rel32")?;

    let mut stub = vec![JMP_REL32];
    stub.extend_from_slice(&displacement.to_le_bytes());
    stub.resize(STUB_LEN, INT3);

    Ok(stub)
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

fn generate_gamescript_exploit(shellcode_path: &Path, is_local_shellcode: bool) -> anyhow::Result<String> {
    // Use decimal encoding to produce a smaller script. Decimal is at most 3
    // chars while hex is at min 3, at most 5.
    let shellcode_data: String = std::fs::read(shellcode_path)?
        .iter()
        .map(|b| format!("{}", *b))
        .intersperse(",".to_string())
        .collect();

    let exploit_data = include_str!("../gs_exploit_template.txt");
    let (shellcode_flavor, ip_notice) = match is_local_shellcode {
        true => (
            "LOCAL EXECUTION",
            "// Host IP is not mandatory for the local-shellcode, it can help with debugging though"
        ),
        false => ("NETWORK LOADER", ""),
    };

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

    // host_ip.txt is optional and lives in the repository root.
    let host_ip = std::fs::read_to_string("../../host_ip.txt");
    let host_ip = host_ip.as_deref().unwrap_or("[YOUR IP HERE]");

    Ok(exploit_data
        .replace("<SHELLCODE_FLAVOR>", shellcode_flavor)
        .replace("<IP_NOTICE>", ip_notice)
        .replace("<SHELLCODE_GEN_PLZ_REPLACE_ME>", &shellcode_data)
        .replace("<HOST_IP>", host_ip)
        .replace("<GIT_VERSION>", &commit)
        .replace("<GIT_DATE>", &commit_date))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns the offset into `.text` that the stub branches to.
    fn stub_target(entry_offset: u64) -> u64 {
        let stub = entry_jump(entry_offset).unwrap();
        assert_eq!(stub.len() % 16, 0, "stub shifts the alignment of .text");

        let mut decoder = Decoder::new(64, &stub, DecoderOptions::NONE);
        let instruction = decoder.decode();

        instruction.near_branch_target() - stub.len() as u64
    }

    #[test]
    fn entry_at_start_of_text_needs_no_stub() {
        assert!(entry_jump(0).unwrap().is_empty());
    }

    #[test]
    fn stub_branches_to_entry_offset() {
        for entry_offset in [0x2, 0x7F, 0x80, 0xFF, 0x100, 0x513, 0x1_0000, 0x12_3456] {
            assert_eq!(
                stub_target(entry_offset),
                entry_offset,
                "entry offset {entry_offset:#X}"
            );
        }
    }
}
