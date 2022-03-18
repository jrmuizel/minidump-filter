use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
};

use memmap2::{Mmap, MmapMut};
use minidump::{
    format::MINIDUMP_STREAM_TYPE, Minidump, MinidumpMemory, MinidumpMemoryInfoList,
    MinidumpMemoryList, MinidumpModuleList, MinidumpSystemInfo, MinidumpThreadList,
};
use num_traits::cast::FromPrimitive;

fn filter(
    output: &mut MmapMut,
    start: u32,
    length: u32,
    address_size: usize,
    modules: &MinidumpModuleList,
) -> usize {
    let start = start as usize;
    let length = length as usize;
    let mut amount_zeroed = 0;
    for i in (start..start + length).step_by(address_size) {
        let addr = u64::from_le_bytes(output[i..i + address_size].try_into().unwrap());
        if modules.module_at_address(addr).is_none() {
            output[i..i + address_size].fill(0);
            amount_zeroed += address_size;
        }
    }
    amount_zeroed
}

fn main() {
    let path = std::env::args().nth(1).unwrap();

    let dump = Minidump::read_path(std::env::args().nth(1).unwrap()).unwrap();
    for s in dump.all_streams() {
        println!(
            "{:?} {} {}",
            MINIDUMP_STREAM_TYPE::from_u32(s.stream_type),
            s.location.rva,
            s.location.data_size
        );
    }
    let system_stream = dump.get_stream::<MinidumpSystemInfo>().unwrap();
    let pointer_width = system_stream.cpu.pointer_width().unwrap() as usize;

    let modules = dump.get_stream::<MinidumpModuleList>().unwrap();
    for m in modules.iter() {
        if !(m.name.starts_with("C:\\Program Files\\Mozilla Firefox")
            || m.name.starts_with("C:\\Windows\\System32"))
        {
            println!("sensitive module name {}, not stripping", m.name);
            return;
        }
    }
    let threads = dump.get_stream::<MinidumpThreadList<'_>>().unwrap();
    let memory = dump.get_stream::<MinidumpMemoryList>().unwrap();

    let mut memory_regions: HashMap<_, _> = memory
        .iter()
        .map(|m| ((m.desc.memory.rva, m.desc.memory.data_size), false))
        .collect();

    /*
    for m in memory.iter() {
        println!("{:x} {} {}", m.base_address, m.desc.memory.rva, m.desc.memory.data_size)
    }*/

    for t in threads.threads.iter() {
        // ensure that all stack regions are accounted for in the memory list
        assert!(
            memory_regions.contains_key(&(t.raw.stack.memory.rva, t.raw.stack.memory.data_size))
        );
        //println!("{:?} {:?}", t.raw.stack.memory.rva, t.raw.stack.memory.data_size);
    }

    let f = File::open(path).unwrap();
    let raw_input = unsafe { Mmap::map(&f).unwrap() };

    let f = OpenOptions::new()
        .write(true)
        .create(true)
        .read(true)
        .truncate(true)
        .open("filtered.dmp")
        .unwrap();
    f.set_len(raw_input.len() as u64).unwrap();
    let mut output = unsafe { Mmap::map(&f).unwrap().make_mut().unwrap() };
    output.copy_from_slice(&raw_input);

    let mut total_zeroed = 0;
    let mut total_considered = 0;
    for m in memory.iter() {
        total_considered += m.desc.memory.data_size;
        total_zeroed += filter(
            &mut output,
            m.desc.memory.rva,
            m.desc.memory.data_size,
            pointer_width,
            &modules,
        );
    }
    println!(
        "{} ({:.1}%) bytes considered, {:.1}% bytes kept",
        total_considered,
        (total_considered * 100) as f32 / output.len() as f32,
        ((total_considered as usize - total_zeroed) * 100) as f32 / output.len() as f32
    );
}
