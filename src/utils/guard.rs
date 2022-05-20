use std::{
    process::exit,
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};

use arc_swap::access::Access;
use bytesize::ByteSize;
use log::{error, info, warn};

use super::process::{get_memory_rss, get_process_num, get_thread_num};
use crate::common::NORMAL_EXIT_WITH_RESTART;
use crate::config::handler::EnvironmentAccess;
use crate::exception::ExceptionHandler;
use crate::proto::trident::Exception;

const CHECK_INTERVAL: Duration = Duration::from_secs(1);

pub struct Guard {
    config: EnvironmentAccess,
    thread: Mutex<Option<JoinHandle<()>>>,
    running: Arc<(Mutex<bool>, Condvar)>,
    exception_handler: ExceptionHandler,
}

impl Guard {
    pub fn new(config: EnvironmentAccess, exception_handler: ExceptionHandler) -> Self {
        Self {
            config,
            thread: Mutex::new(None),
            running: Arc::new((Mutex::new(false), Condvar::new())),
            exception_handler,
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

        let limit = self.config.clone();
        let running = self.running.clone();
        let exception_handler = self.exception_handler.clone();
        let thread = thread::spawn(move || {
            loop {
                let memory_limit = limit.load().max_memory;
                if memory_limit != 0 {
                    match get_memory_rss() {
                        Ok(memory_usage) => {
                            if memory_usage >= memory_limit {
                                warn!(
                                    "memory usage over memory limit, current={}, memory_limit={}, metaflow-agent restart...", 
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
                        let process_limit = limit.load().process_threshold;
                        if process_num > process_limit {
                            warn!(
                                "the number of process exceeds the limit({} > {})",
                                process_num, process_limit
                            );
                            if process_num > process_limit * 2 {
                                error!("the number of process exceeds the limit by 2 times, metaflow-agent restart...");
                                thread::sleep(Duration::from_secs(1));
                                exit(NORMAL_EXIT_WITH_RESTART);
                            }
                            exception_handler.set(Exception::ProcessThresholdExceeded);
                        }
                    }
                    Err(e) => {
                        warn!("{}", e);
                    }
                }

                match get_thread_num() {
                    Ok(thread_num) => {
                        let thread_limit = limit.load().thread_threshold;
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
                            exception_handler.set(Exception::ThreadThresholdExceeded);
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
}
