#include <asm-generic/errno-base.h>

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

const volatile __u32 target_pid = 0;

SEC("lsm/file_open")
int BPF_PROG(guard_file_open, struct file *file, int ret) {
    if (ret != 0) return ret;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == target_pid) return 0;

    char path[128];
    if (bpf_d_path(&file->f_path, path, sizeof(path)) < 0) return 0;

    if (path[0] != '/' || path[1] != 'p' || path[2] != 'r' ||
        path[3] != 'o' || path[4] != 'c' || path[5] != '/') {
        return 0;
        }

    __u32 parsed_pid = 0;
    int i = 6;
#pragma unroll
    for (int j = 0; j < 10; j++) {
        if (path[i] >= '0' && path[i] <= '9') {
            parsed_pid = parsed_pid * 10 + (path[i] - '0');
            i++;
        } else {
            break;
        }
    }

    if (parsed_pid != target_pid) return 0;
    if (path[i] != '/') return 0;

    if (path[i+1] == 'm' && path[i+2] == 'e' && path[i+3] == 'm' && path[i+4] == '\0') {
        return -EPERM;
    }
    if (path[i+1] == 'm' && path[i+2] == 'a' && path[i+3] == 'p' && path[i+4] == 's' && path[i+5] == '\0') {
        return -EPERM;
    }

    return 0;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(guard_ptrace, struct task_struct *child, unsigned int mode, int ret) {
    if (ret != 0) return ret;

    __u32 child_pid = BPF_CORE_READ(child, pid);
    __u32 tracer_pid = bpf_get_current_pid_tgid() >> 32;

    if (child_pid == target_pid && tracer_pid != target_pid) {
        return -EPERM;
    }

    return 0;
}