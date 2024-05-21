use std::collections::{BTreeMap, HashMap};
use std::ffi::{c_void, CStr};
use std::fmt::Write;
use std::fs;
use std::marker::PhantomData;
use std::mem::{self, MaybeUninit};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cpp_demangle::Symbol as CppSymbol;
use libbpf_sys as bpf;
use object::{Object, ObjectSymbol};

use public::{proto::metric, queue::DebugSender, sender::Profile};

use super::ctypes::{get_process_starttime, get_sys_boot_time_ns, stack_trace_key_t, symbol_t};
use super::process::{self, MemoryArea};
use super::stack::{merge_stacks_in, StackTrace};

static PROFILE_SENDER: RwLock<Option<DebugSender<Profile>>> = RwLock::new(None);

pub fn set_profile_sender(sender: DebugSender<Profile>) {
    *PROFILE_SENDER.write().unwrap() = Some(sender);
}

#[no_mangle]
pub unsafe extern "C" fn poll_cuda_memory_output(
    output_fd: i32,
    stack_map_fd: i32,
    symbol_map_fd: i32,
) {
    thread::spawn(move || {
        let mut ctx = PollCtx {
            resolver: StackResolver {
                stack_map_fd,
                symbol_map_fd,
                ..Default::default()
            },
            ..Default::default()
        };
        let opts = bpf::perf_buffer_opts {
            sz: mem::size_of::<bpf::perf_buffer_opts>() as u64,
            ..Default::default()
        };
        let perf_buffer = bpf::perf_buffer__new(
            output_fd,
            8,
            Some(cuda_memory_sample),
            Some(cuda_memory_lost),
            &mut ctx as *mut PollCtx as *mut c_void,
            &opts as *const bpf::perf_buffer_opts,
        );
        let mut ret = 0;
        println!("start polling");
        while ret >= 0 {
            ret = bpf::perf_buffer__poll(perf_buffer, 100);
        }
        println!("end polling");
        bpf::perf_buffer__free(perf_buffer);
    });
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct MallocKey(u32, u64);

struct BpfMapIterator<K: Copy, V: Copy> {
    fd: i32,
    key: K,
    value: PhantomData<V>,
}

impl<K: Copy, V: Copy> BpfMapIterator<K, V> {
    fn new(fd: i32) -> Self {
        Self {
            fd,
            key: unsafe { MaybeUninit::<K>::zeroed().assume_init() },
            value: Default::default(),
        }
    }
}

impl<K: Copy, V: Copy> Iterator for BpfMapIterator<K, V> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let mut next_key = MaybeUninit::<K>::uninit();
            let mut value = MaybeUninit::<V>::uninit();
            if bpf::bpf_map_get_next_key(
                self.fd,
                &self.key as *const K as *const c_void,
                next_key.as_mut_ptr() as *mut c_void,
            ) != 0
            {
                return None;
            }
            let next_key = next_key.assume_init();
            self.key = next_key;
            if bpf::bpf_map_lookup_elem(
                self.fd,
                &next_key as *const K as *const c_void,
                value.as_mut_ptr() as *mut c_void,
            ) != 0
            {
                return None;
            }
            Some((next_key, value.assume_init()))
        }
    }
}

#[derive(Default)]
struct Symbol {
    addr: u64,
    size: u64,
    name: String,
}

#[derive(Default)]
struct FileSymbolMap(BTreeMap<u64, Symbol>);

impl FileSymbolMap {
    fn new<P: AsRef<Path>>(filename: P) -> Self {
        let mut ret = BTreeMap::new();
        let Ok(data) = fs::read(filename.as_ref()) else {
            return FileSymbolMap(ret);
        };
        let Ok(file) = object::File::parse(&*data) else {
            return FileSymbolMap(ret);
        };
        for symbol in file.symbols() {
            match (symbol.address(), symbol.size(), symbol.name()) {
                (addr, size, Ok(name)) if addr != 0 => {
                    let name = if let Ok(demangled) = CppSymbol::new(name) {
                        demangled.to_string()
                    } else {
                        name.to_owned()
                    };
                    let _ = ret.insert(addr, Symbol { addr, size, name });
                }
                _ => (),
            }
        }
        for symbol in file.dynamic_symbols() {
            match (symbol.address(), symbol.size(), symbol.name()) {
                (addr, size, Ok(name)) if addr != 0 => {
                    let name = if let Ok(demangled) = CppSymbol::new(name) {
                        demangled.to_string()
                    } else {
                        name.to_owned()
                    };
                    let _ = ret.insert(addr, Symbol { addr, size, name });
                }
                _ => (),
            }
        }
        FileSymbolMap(ret)
    }

    fn resolve_addr(&self, addr: u64) -> Option<String> {
        let Some(symbol) = self.0.range(..=addr).last().map(|kv| kv.1) else {
            return None;
        };
        if symbol.addr + symbol.size < addr {
            return None;
        }
        Some(symbol.name.clone())
    }
}

#[derive(Default)]
struct SymbolMap {
    mem_areas: HashMap<u32, Vec<MemoryArea>>,
    files: HashMap<String, FileSymbolMap>,
}

impl SymbolMap {
    fn resolve_addr(&mut self, pid: u32, addr: u64) -> String {
        let mem_areas = self
            .mem_areas
            .entry(pid)
            .or_insert_with(|| process::get_executable_memory_areas(pid).unwrap_or_default());
        let Some(pos) = mem_areas
            .iter()
            .position(|area| area.m_start <= addr && area.m_end > addr)
        else {
            return format!("[unknown] 0x{addr:016x}");
        };
        let mem_area = &mem_areas[pos];
        if !self.files.contains_key(&mem_area.path) {
            self.files
                .insert(mem_area.path.clone(), FileSymbolMap::new(&mem_area.path));
        }
        self.files
            .get(&mem_area.path)
            .unwrap()
            .resolve_addr(addr - mem_area.m_start)
            .unwrap_or_else(|| format!("[{}]", &mem_area.path))
    }
}

#[derive(Default)]
struct StackResolver {
    native_symbol_map: SymbolMap,
    stack_map_fd: i32,
    symbol_map_fd: i32,
}

impl StackResolver {
    fn generate_native_stack(&mut self, pid: u32, stack_id: u64) -> Option<String> {
        let mut stack = MaybeUninit::<StackTrace>::uninit();
        let stack = unsafe {
            if bpf::bpf_map_lookup_elem(
                self.stack_map_fd,
                &stack_id as *const u64 as *const c_void,
                stack.as_mut_ptr() as *mut c_void,
            ) != 0
            {
                return None;
            }
            stack.assume_init()
        };
        let mut stack_str = String::new();
        for i in (0..stack.len).rev() {
            let _ = write!(
                &mut stack_str,
                "{};",
                self.native_symbol_map
                    .resolve_addr(pid, stack.addrs[i as usize])
            );
        }
        if !stack_str.is_empty() {
            stack_str.pop();
        }
        Some(stack_str)
    }

    fn generate_python_stack(&mut self, id: u64) -> Option<String> {
        let mut stack = MaybeUninit::<StackTrace>::uninit();
        let stack = unsafe {
            if bpf::bpf_map_lookup_elem(
                self.stack_map_fd,
                &id as *const u64 as *const c_void,
                stack.as_mut_ptr() as *mut c_void,
            ) != 0
            {
                return None;
            }
            stack.assume_init()
        };
        let symbol_map: HashMap<u64, symbol_t> =
            HashMap::from_iter(BpfMapIterator::new(self.symbol_map_fd).map(|(k, v)| (v, k)));
        let mut stack_str = String::new();
        for i in (0..stack.len).rev() {
            let addr = &stack.addrs[i as usize];
            if *addr == 0 {
                let _ = write!(&mut stack_str, "-;");
                continue;
            }
            match symbol_map.get(&(addr & 0xFF)) {
                Some(symbol) => unsafe {
                    if symbol.class_name[0] != b'\0' as i8 {
                        let _ = write!(
                            &mut stack_str,
                            "{}::",
                            CStr::from_ptr(symbol.class_name.as_ptr()).to_str().unwrap()
                        );
                    }
                    let _ = write!(
                        &mut stack_str,
                        "{};",
                        CStr::from_ptr(symbol.method_name.as_ptr())
                            .to_str()
                            .unwrap()
                    );
                },
                None => {
                    let _ = write!(&mut stack_str, "-;");
                }
            }
        }
        if !stack_str.is_empty() {
            stack_str.pop();
        }
        Some(stack_str)
    }
}

#[derive(Default)]
struct PollCtx {
    resolver: StackResolver,
    cache_native: HashMap<u64, String>,
    cache_py: HashMap<u64, String>,
    malloc_info: Arc<Mutex<HashMap<MallocKey, (u64, String)>>>,
    last_inuse: Duration,
    allocs: u64,
    frees: u64,
}

fn send_profile_data(
    trace: &stack_trace_key_t,
    cpu: i32,
    event_type: i32,
    size: u64,
    trace_str: &str,
) {
    let guard = PROFILE_SENDER.read().unwrap();
    let Some(sender) = guard.as_ref() else {
        return;
    };

    let profile = metric::Profile {
        sample_rate: 0,
        timestamp: trace.timestamp + unsafe { get_sys_boot_time_ns() },
        event_type,
        stime: unsafe { get_process_starttime(trace.tgid as i32) },
        pid: trace.tgid,
        tid: trace.pid,
        thread_name: unsafe {
            CStr::from_ptr(trace.comm.as_ptr() as *const i8)
                .to_str()
                .unwrap()
                .to_owned()
        },
        process_name: unsafe {
            CStr::from_ptr(trace.comm.as_ptr() as *const i8)
                .to_str()
                .unwrap()
                .to_owned()
        },
        u_stack_id: trace.dwarfstack as u32,
        k_stack_id: trace.kernstack as u32,
        cpu: cpu as u32,
        count: size as u32,
        data: trace_str.as_bytes().into(),
        ..Default::default()
    };
    let _ = sender.send(Profile(profile));
}

unsafe extern "C" fn cuda_memory_sample(ctx: *mut c_void, cpu: i32, data: *mut c_void, _: u32) {
    // assert_eq!(size, mem::size_of::<CudaMemoryInfo>() as u32);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let ctx = &mut *(ctx as *mut PollCtx);
    let info = &*(data as *mut stack_trace_key_t);
    let mut info_guard = ctx.malloc_info.lock().unwrap();
    let key = MallocKey(info.tgid, info.mem_addr);
    if info.mem_size > 0 {
        let empty_string = String::new();

        let native_stack = if info.dwarfstack != 0 {
            &*ctx.cache_native.entry(info.dwarfstack).or_insert_with(|| {
                ctx.resolver
                    .generate_native_stack(info.tgid, info.dwarfstack)
                    .unwrap_or(format!("missing stack id {}", info.dwarfstack))
            })
        } else {
            &empty_string
        };
        let py_stack = if info.intpstack != 0 {
            &*ctx.cache_py.entry(info.intpstack).or_insert_with(|| {
                ctx.resolver
                    .generate_python_stack(info.intpstack)
                    .unwrap_or(format!("missing stack id {}", info.intpstack))
            })
        } else {
            &empty_string
        };
        let mut trace_str = String::with_capacity(native_stack.len() + py_stack.len() + 32);
        merge_stacks_in(&mut trace_str, py_stack, native_stack);

        send_profile_data(
            &info,
            cpu,
            metric::ProfileEventType::EbpfMemAlloc.into(),
            info.mem_size,
            &trace_str,
        );

        info_guard.insert(key, (info.mem_size, trace_str));
        ctx.allocs += 1;
    } else {
        if info_guard.remove(&key).is_none() {
            println!("no malloc entry match {key:?}");
        }
        ctx.frees += 1;
    }
    let free_interval = Duration::from_secs(30);
    if now - ctx.last_inuse >= free_interval {
        ctx.last_inuse = now;
        for alloc in info_guard.values() {
            send_profile_data(
                &info,
                cpu,
                metric::ProfileEventType::EbpfMemInUse.into(),
                alloc.0,
                &alloc.1,
            );
        }
        println!(
            "alloc/s: {} free/s: {}",
            ctx.allocs / free_interval.as_secs(),
            ctx.frees / free_interval.as_secs()
        );
        ctx.allocs = 0;
        ctx.frees = 0;
    }
}

unsafe extern "C" fn cuda_memory_lost(_: *mut c_void, _: i32, _: u64) {
    println!("lost!");
}
