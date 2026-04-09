# AGENTS.md

- Always refer to files by repo-root relative path. Prefer `@path/to/file` notation when it improves clarity.
- This repository does not have a single top-level build or test entrypoint. Run commands in the owning module directory.

## Project Structure
- `@agent` is the Rust workspace for `deepflow-agent`. Shared Rust crates live in `@agent/crates` and `@agent/plugins`, and eBPF/C sources live in `@agent/src/ebpf`.
- Prefer `@agent/crates` for new Rust code.
- `@server` is the main Go server module. The main subsystems are `@server/controller`, `@server/ingester`, `@server/querier`, and shared code under `@server/libs`.
- `@cli` is the Go CLI module for `deepflow-ctl`.
- `@message` contains shared protobuf definitions and message packages used by Go components.
- `@docs`, `@manifests`, and `@automation_test` contain product docs, deployment assets, and automation test assets.
- Go code is split across multiple modules. In addition to `@server`, `@cli`, and `@message`, there are nested `go.mod` files under `@server/**`. Confirm the owning module before changing dependencies or running `go` commands.

## Source Of Truth And Generated Files
- Treat files under `@message` as the source of truth for shared protobuf definitions. Do not hand-edit copied proto files or generated `*.pb.go` files under `@server/libs/**/pb`, `@server/vendor/**`, or `@cli/vendor/**` unless the source definition was updated first.
- `@agent/crates/trace-utils/src/trace_utils.h` is generated according to instructions in `@agent/crates/trace-utils/README.md`.
- `@server/Makefile` generates and refreshes checked-in artifacts, including files under `@server/libs/hmap/**`, `@server/libs/kubernetes/watcher.gen.go`, and multiple protobuf outputs. If you change a generator input, regenerate the output instead of editing the generated file by hand.
- `@server` and `@cli` build through vendored dependencies plus local patch files. Prefer the relevant `make` targets when protobufs, dependencies, or generated code are involved.
- Do not manually edit vendored code under `@server/vendor` or `@cli/vendor`. Recreate it through the provided module Makefile targets.

## Docs
- Start with `@README.md` for the repo overview. Use `@README-CN.md` or `@README-JP.md` when language-specific top-level docs are more appropriate.
- Use `@agent/build.md` for agent build prerequisites and environment assumptions.
- Component-specific behavior is documented in local READMEs such as `@agent/README.md`, `@server/README.md`, `@message/README.md`, and files under `@docs/**`.
- Deployment and packaging examples live under `@manifests/**`.
- If you change an operator-facing workflow, config, or generation path, update the nearest component README or doc page in the same task when appropriate.

## Code Style

### General
- Keep changes scoped to the component you are modifying. Avoid broad cleanup that is unrelated to the task.
- Prefer changing the real input to a generator instead of patching generated outputs.
- When a task crosses protobuf, Go, and Rust boundaries, update the source of truth first, regenerate downstream artifacts second, and validate third.

### C
- Follow the surrounding file's formatting, naming, and macro style.
- In `@agent/src/ebpf`, inspect adjacent headers and Makefiles before introducing new build assumptions or generated artifacts.

### Go
- Use `gofmt` on changed Go files. If a generator also runs formatting tools, still verify the checked-in output.
- `@server` and `@cli` declare Go 1.24 toolchains, while `@message` still declares Go 1.18. Do not silently raise cross-module language assumptions.
- When changing Go dependencies, use the owning module's `go` or `make` workflow so `go.mod`, `go.sum`, vendor contents, and local patches stay consistent.

### Rust
- Format code with rustfmt.
- While still satisfying rustfmt, prefer code shapes that minimize indentation.
- Prefer captured formatting arguments such as `format!("{argument}")` over positional forms such as `format!("{}", argument)`.
- `@agent` uses the `stable` Rust toolchain via `@agent/rust-toolchain`.
- Prefer placing new Rust code in `@agent/crates`.
- Dependencies in any `Cargo.toml` must be sorted in alphabet order.
- `use` declaration order is `std`, external crate, this `crate`, and `super`. Declarations should be grouped and sorted in alphabet order.

## Validation
- Run the narrowest relevant checks for the component you changed.
- For Rust agent changes, run commands from `@agent`. Typical checks are `cargo fmt`, targeted `cargo test`, or `cargo build`.
- For server changes, run commands from `@server`. Prefer `make test`, `make server`, or `make querier` because these targets also prepare vendor and generated prerequisites.
- For shared server library changes, run commands from `@server/libs`; `make test` is the standard entrypoint there.
- For CLI changes, run commands from `@cli`; `make cli` is the standard build path and refreshes vendored and generated inputs first.
- If you modify protobufs, templates, or other shared inputs, rerun the relevant generation or build flow for every affected component, not only the directory you edited.

## Git Notes
- Format code before committing.
- If there are any changes to `@server/agent_config/template.yaml`, execute `python3 @server/agent_config/gendoc.py` in the script's directory, commit `@server/agent_config/README.md` and `@server/agent_config/README-CH.md` as well.
- Use file `@commit-template` as template for commit messages.
- The commit template uses conventional prefixes such as `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, and `chore`.
