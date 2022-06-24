SEC("uprobe/http2_serverConn_processHeaders")
int uprobe_http2_serverConn_processHeaders(struct pt_regs *ctx) {
	bpf_debug("uprobe_http2_serverConn_processHeaders\n");
	return 0;
}

SEC("uprobe/http2_serverConn_writeHeaders")
int uprobe_http2_serverConn_writeHeaders(struct pt_regs *ctx) {
	bpf_debug("uprobe_http2_serverConn_writeHeaders\n");
	return 0;
}
