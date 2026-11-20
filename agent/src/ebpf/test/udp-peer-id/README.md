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
