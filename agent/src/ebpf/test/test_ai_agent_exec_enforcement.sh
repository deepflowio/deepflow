#!/usr/bin/env bash
set -euo pipefail

# Lightweight manual harness for AI Agent exec enforcement verification.
# It intentionally does not start or reconfigure deepflow-agent; effective policy
# must be delivered by DeepFlow server/controller agent-group configuration.

SYSFS_ROOT="${SYSFS_ROOT:-/sys}"
LSM_FILE="${SYSFS_ROOT%/}/kernel/security/lsm"
BLOCKED_CMD="${BLOCKED_CMD:-/usr/bin/uname}"
SERVER_NODE="${SERVER_NODE:-10.50.120.81}"
AGENT_NODE="${AGENT_NODE:-10.50.120.21}"
NAMESPACE="${NAMESPACE:-deepflow}"
AGENT_DS="${AGENT_DS:-deepflow-agent-r4-dcn-ctrl}"

if [[ ! -r "$LSM_FILE" ]]; then
	echo "SKIP: cannot read $LSM_FILE"
	exit 0
fi

if ! tr ',' '\n' <"$LSM_FILE" | grep -qx bpf; then
	echo "SKIP: BPF LSM is not active in $LSM_FILE"
	exit 0
fi

if [[ ! -x "$BLOCKED_CMD" ]]; then
	echo "SKIP: blocked command $BLOCKED_CMD is not executable on this host"
	exit 0
fi

echo "OK: BPF LSM active and $BLOCKED_CMD exists."
cat <<EOF

Manual K8s verification checklist:

1. Configure the rule through DeepFlow server/controller agent-group config,
   not only through the Kubernetes ConfigMap:
     inputs.proc.ai_agent.enforcement.enabled: true
     inputs.proc.ai_agent.enforcement.mode: block
     exact rule path: $BLOCKED_CMD

2. Refresh controller vtap cache, then check the target DaemonSet:
     ssh root@$SERVER_NODE 'kubectl -n $NAMESPACE get ds $AGENT_DS -o wide'

3. Confirm agent logs show both capability and LSM attach success:
     ssh root@$AGENT_NODE \\
       'sudo crictl ps --name deepflow-agent && sudo crictl logs <container-id> 2>&1 | grep -Ei "KernelCapability|bpf_lsm|attach lsm" | tail -50'

4. Trigger an AI endpoint hit from the same process that later executes
   $BLOCKED_CMD. Expected result in block mode:
     PermissionError errno=1

5. If event persistence is being validated, deploy a server/schema version that
   contains event.proc_block_event before querying ClickHouse.
EOF
