# data_preprocessing.py

import pandas as pd
import numpy as np
import os

# Load execve events
execve_df = pd.read_csv('../ebpf/execve_events.log', header=None, names=['timestamp', 'pid', 'uid', 'comm', 'filename'])
execve_df['event'] = 'execve'

# Load openat events
openat_df = pd.read_csv('../ebpf/openat_events.log', header=None, names=['timestamp', 'pid', 'uid', 'comm', 'filename', 'flags'])
openat_df['event'] = 'openat'

# Load other syscall events
other_syscalls_df = pd.read_csv('../ebpf/other_syscalls_events.log', header=None, names=['timestamp', 'pid', 'uid', 'comm', 'syscall'])
other_syscalls_df['event'] = other_syscalls_df['syscall']

# Combine all events
data = pd.concat([execve_df, openat_df, other_syscalls_df], ignore_index=True)

# Convert timestamps to datetime
data['timestamp'] = pd.to_datetime(data['timestamp'], unit='s')

# Feature Engineering
# Count events per process
event_counts = data.groupby(['pid', 'event']).size().unstack(fill_value=0).reset_index()

# Labeling
# For the purpose of this example, we'll randomly assign labels
# In practice, you should label based on known malicious or benign processes
event_counts['label'] = np.random.choice([0, 1], size=len(event_counts))  # 0: Normal, 1: Malicious

# Save preprocessed data
event_counts.to_csv('../data/preprocessed_data.csv', index=False)
