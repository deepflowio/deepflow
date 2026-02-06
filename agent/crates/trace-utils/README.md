# Steps to generate `src/trace_utils.h`

- Call `cbindgen -c cbindgen.toml -o src/trace_utils.h` under crate root. The config expands the enterprise ABI, so no extra flags are needed.
