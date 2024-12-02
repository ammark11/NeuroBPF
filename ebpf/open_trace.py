# open_trace.py

from bcc import BPF
import ctypes as ct
import time

# Define output data structure
class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("uid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("filename", ct.c_char * 256),
        ("flags", ct.c_int),
    ]

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    int flags;
};

BPF_PERF_OUTPUT(events);

int trace_openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags, umode_t mode) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user(&data.filename, sizeof(data.filename), filename);
    data.flags = flags;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="__x64_sys_openat", fn_name="trace_openat")

# Open output file
output_file = open("openat_events.log", "w")

# Define callback
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    log_line = f"{int(time.time())},{event.pid},{event.uid},{event.comm.decode('utf-8', 'replace')},{event.filename.decode('utf-8', 'replace')},{event.flags}\n"
    output_file.write(log_line)
    output_file.flush()

# Open perf buffer
b["events"].open_perf_buffer(print_event)

print("Tracing openat syscalls... Press Ctrl+C to exit.")

# Polling loop
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Detaching...")
    output_file.close()
