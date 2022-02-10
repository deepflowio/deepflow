use std::{
    process::exit,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use bytesize::ByteSize;
use log::{error, info, warn};

use super::process::{get_memory_rss, get_process_num, get_thread_num};
use crate::common::{NORMAL_EXIT_WITH_RESTART, TRIDENT_PROCESS_LIMIT, TRIDENT_THREAD_LIMIT};

const CHECK_INTERVAL: Duration = Duration::from_secs(1);

pub struct Guard {
    limit: Arc<Limit>,
    thread: Mutex<Option<JoinHandle<()>>>,
    running: Arc<(Mutex<bool>, Condvar)>,
}

struct Limit {
    process: AtomicU32,
    thread: AtomicU32,
    memory: AtomicU64,
}

impl Guard {
    pub fn new() -> Self {
        Self {
            limit: Arc::new(Limit {
                process: AtomicU32::new(TRIDENT_PROCESS_LIMIT),
                thread: AtomicU32::new(TRIDENT_THREAD_LIMIT),
                memory: AtomicU64::new(0),
            }),
            thread: Mutex::new(None),
            running: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    pub fn start(&self) {
        {
            let (started, _) = &*self.running;
            let mut started = started.lock().unwrap();
            if *started {
                return;
            }
            *started = true;
        }

        let limit = self.limit.clone();
        let running = self.running.clone();
        let thread = thread::spawn(move || {
            loop {
                let memory_limit = limit.memory.load(Ordering::SeqCst);
                if memory_limit != 0 {
                    match get_memory_rss() {
                        Ok(memory_usage) => {
                            if memory_usage >= memory_limit {
                                warn!(
                                    "memory usage over memory limit, current={}, memory_limit={}, trident restart...", 
                                    ByteSize::b(memory_usage).to_string_as(true), ByteSize::b(memory_limit).to_string_as(true)
                                );
                                thread::sleep(Duration::from_secs(1));
                                exit(-1);
                            }
                        }
                        Err(e) => {
                            warn!("{}", e);
                        }
                    }
                }

                match get_process_num() {
                    Ok(process_num) => {
                        let process_limit = limit.process.load(Ordering::SeqCst);
                        if process_num > process_limit {
                            warn!(
                                "the number of process exceeds the limit({} > {})",
                                process_num, process_limit
                            );
                            if process_num > process_limit * 2 {
                                error!("the number of process exceeds the limit by 2 times, trident restart...");
                                thread::sleep(Duration::from_secs(1));
                                exit(NORMAL_EXIT_WITH_RESTART);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("{}", e);
                    }
                }

                match get_thread_num() {
                    Ok(thread_num) => {
                        let thread_limit = limit.thread.load(Ordering::SeqCst);
                        if thread_num > thread_limit {
                            warn!(
                                "the number of thread exceeds the limit({} > {})",
                                thread_num, thread_limit
                            );
                            if thread_num > thread_limit * 2 {
                                error!("the number of thread exceeds the limit by 2 times, trident restart...");
                                thread::sleep(Duration::from_secs(1));
                                exit(NORMAL_EXIT_WITH_RESTART);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("{}", e);
                    }
                }

                let (running, timer) = &*running;
                let mut running = running.lock().unwrap();
                if !*running {
                    break;
                }
                running = timer.wait_timeout(running, CHECK_INTERVAL).unwrap().0;
                if !*running {
                    break;
                }
            }
            info!("guard exited");
        });

        self.thread.lock().unwrap().replace(thread);
        info!("guard started");
    }

    pub fn stop(&self) {
        let (stopped, timer) = &*self.running;
        {
            let mut stopped = stopped.lock().unwrap();
            if !*stopped {
                return;
            }
            *stopped = false;
        }
        timer.notify_one();

        if let Some(thread) = self.thread.lock().unwrap().take() {
            let _ = thread.join();
        }
    }

    pub fn set_memory_limit(&self, memory_limit: u64) {
        self.limit.memory.store(memory_limit, Ordering::SeqCst);
    }

    pub fn set_process_limit(&self, process_limit: u32) {
        self.limit.process.store(process_limit, Ordering::SeqCst);
    }

    pub fn set_thread_limit(&self, thread_limit: u32) {
        self.limit.process.store(thread_limit, Ordering::SeqCst);
    }
}
