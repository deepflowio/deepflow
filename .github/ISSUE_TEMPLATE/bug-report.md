---
name: Bug Report
about: Template for bug reports
labels: kind/bug
---

# Expected Behavior

# Actual Behavior

# Steps to Reproduce the Problem

1.
2.
3.

# Additional Info

-  deepflow version:

   **Output of `kubectl exec -it -n deepflow deploy/deepflow-server -- deepflow-server -v`:**
  
   **Output of `kubectl exec -it -n deepflow ds/deepflow-agent -- deepflow-agent -v`:**

```
(paste your output here)
```

- deepflow agent list:

  **Output of `deepflow-ctl agent list`:**
```
(paste your output here)
```

- Kubernetes CNI:

```
(paste your Kubernetes CNI)
```

- operation-system/kernel version:
  
  **Output of `awk -F '=' '/PRETTY_NAME/ { print $2 }' /etc/os-release`:**
  
  **Output of `uname -r`:**
```
(paste your output here)
```

<!-- Any other additional information -->
