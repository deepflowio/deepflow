#if 0
SEC("uprobe/python_save_thread_state_address")
int uprobe_python_save_thread_state_address(struct pt_regs *ctx) {
	__u64 zero = 0;
	python_thread_state_map__update(&zero, &zero);
	bpf_debug("PyEval_SaveThread");
	return 0;
}

SEC("uprobe/pyeval_evalframedefault")
int uprobe_pyeval_evalframedefault(struct pt_regs *ctx) {
	__u64 zero = 0;
	python_thread_state_map__update(&zero, &zero);
	bpf_debug("_PyEval_EvalFrameDefault");
	return 0;
}
#endif
