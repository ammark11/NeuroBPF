# other_syscall_traces.py

from bcc import BPF
import ctypes as ct
import time

# Define output data structure
class Data(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_ulonglong),
        ("pid", ct.c_uint32),
        ("uid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("syscall", ct.c_char * 16),
    ]

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u64 timestamp;
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char syscall[16];
};

BPF_PERF_OUTPUT(events);

int trace_syscalls(struct pt_regs *ctx) {
    struct data_t data = {};
    data.timestamp = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_strncpy(data.syscall, "SYSCALL_NAME", sizeof(data.syscall));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# List of syscalls to trace
syscalls = [
    "__x64_sys_read",
    "__x64_sys_write",
    "__x64_sys_connect",
    # Add more syscalls as needed
]

# Initialize BPF
b = BPF(text=bpf_text)

# Attach kprobes for each syscall
for syscall in syscalls:
    fn_name = "trace_syscalls"
    b.attach_kprobe(event=syscall, fn_name=fn_name)

# Open output file
output_file = open("other_syscalls_events.log", "w")

# Define callback
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    log_line = f"{event.timestamp},{event.pid},{event.uid},{event.comm.decode('utf-8', 'replace')},{event.syscall.decode('utf-8', 'replace')}\n"
    output_file.write(log_line)
    output_file.flush()

# Open perf buffer
b["events"].open_perf_buffer(print_event)

print("Tracing other syscalls... Press Ctrl+C to exit.")

# Polling loop
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Detaching...")
    output_file.close()
