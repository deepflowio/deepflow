use std::ffi::CStr;
use std::fmt::Write as _;
use std::io::Write as _;
use std::mem;

pub const STACK_FRAMES_PER_RUN: usize = 16;
pub const STACK_PROG_MAX_RUN: usize = 5;
pub const MAX_STACK_DEPTH: usize = STACK_PROG_MAX_RUN * STACK_FRAMES_PER_RUN;

#[repr(C)]
pub struct StackTrace {
    pub len: u64,
    pub addrs: [u64; MAX_STACK_DEPTH],
}

const PYEVAL_FNAME: &'static str = "_PyEval_EvalFrameDefault";

#[no_mangle]
pub unsafe extern "C" fn merge_stacks(
    trace_str: *mut i8,
    len: usize,
    i_trace: *const i8,
    u_trace: *const i8,
) {
    let Ok(i_trace) = CStr::from_ptr(i_trace).to_str() else {
        return;
    };
    let Ok(u_trace) = CStr::from_ptr(u_trace).to_str() else {
        return;
    };
    trace_str.write_bytes(0, len);
    let mut trace_str = Vec::from_raw_parts(trace_str as *mut u8, 0, len);

    let n_py_frames = i_trace.split(";").count() - 1; // <module> does not count
    let n_eval_frames = u_trace
        .split(";")
        .filter(|c_func| *c_func == PYEVAL_FNAME)
        .count();

    if n_eval_frames == 0 {
        // native stack not correctly unwinded, just put it on top of python frames
        let _ = write!(
            &mut trace_str,
            "{};[lost] incomplete python c stack;{}",
            i_trace, u_trace
        );
    } else if n_py_frames == n_eval_frames {
        // no native stack
        let _ = write!(&mut trace_str, "{}", i_trace);
    } else if n_py_frames == n_eval_frames - 1 {
        // python calls native, just put everything after the last _PyEval on top of python frames (including the semicolon)
        let loc = u_trace.rfind(PYEVAL_FNAME).unwrap() + PYEVAL_FNAME.len();
        let _ = write!(&mut trace_str, "{}{}", i_trace, &u_trace[loc..]);
    } else {
        let _ = write!(
            &mut trace_str,
            "{};[lost] incomplete python c stack;{}",
            i_trace, u_trace
        );
    }

    mem::forget(trace_str);
}

pub fn merge_stacks_in(trace_str: &mut String, i_trace: &str, u_trace: &str) {
    let n_py_frames = i_trace.split(";").count() - 1; // <module> does not count
    let n_eval_frames = u_trace
        .split(";")
        .filter(|c_func| *c_func == PYEVAL_FNAME)
        .count();

    if n_eval_frames == 0 {
        // native stack not correctly unwinded, just put it on top of python frames
        let _ = write!(
            trace_str,
            "{};[lost] incomplete python c stack;{}",
            i_trace, u_trace
        );
    } else if n_py_frames == n_eval_frames {
        // no native stack
        let _ = write!(trace_str, "{}", i_trace);
    } else if n_py_frames == n_eval_frames - 1 {
        // python calls native, just put everything after the last _PyEval on top of python frames (including the semicolon)
        let loc = u_trace.rfind(PYEVAL_FNAME).unwrap() + PYEVAL_FNAME.len();
        let _ = write!(trace_str, "{}{}", i_trace, &u_trace[loc..]);
    } else {
        let _ = write!(
            trace_str,
            "{};[lost] incomplete python c stack;{}",
            i_trace, u_trace
        );
    }
}
