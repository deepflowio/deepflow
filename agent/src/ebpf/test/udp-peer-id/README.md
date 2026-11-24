# UDP 多 Peer Socket ID 隔离样例

## 测试目标

本样例验证同一个 UDP 服务端 FD 与两个客户端 peer 通信时：

1. 两个 peer 获得不同的 `socket_id`；
2. 同一 peer 的请求和响应使用相同的 `socket_id`；
3. 每个 peer 的 `cap_seq` 独立从 0 开始，依次为 `0,1`；
4. 请求、响应交错时不会让一个 peer 消耗另一个 peer 的序号。

通信顺序如下：

```text
127.0.0.2:<port-A> -- A 请求 -->
                                  127.0.0.1:53053（同一个服务端 FD）
127.0.0.3:<port-B> -- B 请求 -->

127.0.0.3:<port-B> <-- B 响应 --
127.0.0.2:<port-A> <-- A 响应 --
```

报文使用最小 DNS 请求和响应格式。Socket Tracer sample 已将 `53053` 加入 DNS 端口，
并在加载前显式开启：

```rust
set_udp_peer_id_enabled(true);
```

本 v6.6 回迁版本不包含 UDP 本地 IP 补偿，因此服务端绑定具体地址 `127.0.0.1`，
避免通配地址缺失导致隔离回退。

## 1. 编译

在编译容器中执行：

```bash
docker exec -w /work/agent/src/ebpf deepflow-core make socket-tracer
docker exec -w /work/agent/src/ebpf/test/udp-peer-id \
  deepflow-core make clean all
```

## 2. 启动 Socket Tracer

在宿主机终端一执行：

```bash
cd /home/jiping/deepflow-core/agent/src/ebpf
sudo RUST_LOG=info \
  ./samples/rust/socket-tracer/target/release/socket_tracer \
  2>&1 | tee /tmp/socket-tracer-udp-peer.log
```

等待 Socket Tracer 进入 `TRACER_RUNNING`。日志中应出现：

```text
UDP peer socket ID isolation enabled for sample testing
```

## 3. 运行服务端和客户端

在宿主机终端二执行：

```bash
cd /home/jiping/deepflow-core/agent/src/ebpf/test/udp-peer-id
./udp_peer_server 127.0.0.1 53053 &
server_pid=$!
sleep 1
./udp_peer_client 127.0.0.1 53053
wait "$server_pid"
```

服务端始终打印同一个 FD，并按 A、B 接收，按 B、A 回复。

## 4. 校验 Socket Tracer 输出

停止 Socket Tracer，使日志完整落盘，然后执行：

```bash
python3 verify_socket_tracer.py /tmp/socket-tracer-udp-peer.log
```

成功输出示例：

```text
[OK] UDP peer socket ID isolation
  peer=127.0.0.2 fd=3 socket_id=<peer-A-id> cap_seq=0,1
  peer=127.0.0.3 fd=3 socket_id=<peer-B-id> cap_seq=0,1
```

如果功能未开启，两个 peer 会共享同一个物理 `socket_id`，校验脚本将返回失败。

## 5. 只验证通信程序

不启动 Socket Tracer 也可先验证样例通信：

```bash
./udp_peer_server 127.0.0.1 53053 &
server_pid=$!
sleep 1
./udp_peer_client 127.0.0.1 53053
wait "$server_pid"
```

该步骤只能验证请求、响应通信成功，不能证明 peer `socket_id/cap_seq` 已隔离。

## 6. 第二条 sendmmsg 消息的分段 iovec 回归

`test_sendmmsg_iov.py` 需要 Linux 和 Python 3.6+，通过 libc `sendmmsg` 在同一 socket、
同一目标上批量发送真实 DNS A + AAAA 请求。它验证单段、2/4/8 段、首项及中间项为空、
第一条消息分段，以及第二条消息超过 8 项时只采集前 8 项的边界。
本机需要能够绑定 `127.0.0.1:53053`，测试客户端绑定具体地址 `127.0.0.2`。

先启动开启 DNS 端口 53053 的采集程序，等待 `TRACER_RUNNING`，再生成流量和预期记录：

```bash
python3 test_sendmmsg_iov.py /tmp/iov-expectations.json --limit 8
```

仅运行上述命令会核对接收端的完整报文。要核对 eBPF 实际采集内容，需在独立测试副本的
Rust sample UDP callback 中输出以下记录；现有 `UDP_PEER` 日志不包含完整载荷，不能替代：

```rust
let event = &*sd; // 在现有 unsafe UDP callback 块内
let payload = std::slice::from_raw_parts(event.cap_data as *const u8, event.cap_len as usize);
let hex = payload.iter().map(|b| format!("{:02x}", b)).collect::<String>();
println!("UDP_IOV pid={} fd={} direction={} socket_id={} cap_seq={} cap_len={} syscall_len={} hex={}",
    event.process_id, event.fd,
    if event.direction == SOCK_DIR_SND { "out" } else { "in" },
    event.socket_id, event.cap_seq, event.cap_len, event.syscall_len, hex);
```

停止采集程序、确保日志落盘后，核对每条发送事件的完整载荷或预期截断前缀、采集长度、
syscall 长度、同一 peer 的稳定 ID，以及每批两条消息的相邻序号：

```bash
python3 test_sendmmsg_iov.py /tmp/iov-expectations.json --tracer-log /tmp/iov-tracer.log
```

分别设置 `set_udp_peer_id_enabled(false)` 和 `true` 重跑，使用各自的预期文件和日志。
开启隔离时，校验命令追加 `--peer-id-enabled`，还会检查全部发送事件的 peer 序号从 0 开始、
无重复或缺失（默认 8 项时为 20 条事件、序号 0–19）。关闭隔离时仅检查每批内部的相邻序号，
不要求跨批物理序号连续。

验证更大的候选值时，将生成流量的 `--limit` 设置为实际编译值，例如 12 或 16。
大于 8 时，脚本追加不超过候选值的 12/16/18 段测试，以及候选上限处的中间空项和
第一条消息分为 4 段的测试；超限场景使用候选值加 1 项。
12 项运行 14 个场景、28 条发送事件；16 项运行 16 个场景、32 条发送事件。
必须确认 sample 成功加载预期字节码变体，避免将自动回退后的运行误判为候选值通过。

本轮实际构建、测试日志和结果见
[附加 iovec 上限测试报告](../../docs/udp-extra-iov-limit-test-report-20261124.md)。
5.10 上的更大候选值、完整程序加载边界及 verifier 统计，见
[Linux 5.10 取值测试报告](../../docs/udp-extra-iov-limit-linux-5.10-test-report-20261124.md)。
