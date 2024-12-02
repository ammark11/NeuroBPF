# NeuroBPF
 Malware Detection using Machine Learning with eBPF for Linux

## Setup Instructions

### Prerequisites

- Linux system with kernel version >= 4.9
- Python 3.x
- Root privileges for running eBPF scripts

### Install Dependencies

```bash
sudo apt-get update
sudo apt-get install -y python3-pip linux-headers-$(uname -r) build-essential
sudo apt-get install -y bpfcc-tools libbpfcc-dev linux-tools-common linux-tools-$(uname -r)

pip3 install -r requirements.txt


Usage
Step 1: Data Collection with eBPF
Navigate to the ebpf/ directory and run the eBPF scripts with root privileges.


cd ebpf
sudo python3 execve_trace.py &
sudo python3 open_trace.py &
sudo python3 other_syscall_traces.py &
The scripts will generate log files (*.log) in the same directory.

Step 2: Data Preprocessing
Navigate to the ml/ directory and preprocess the collected data.


cd ../ml
python3 data_preprocessing.py
Step 3: Model Training
Train the machine learning model using the preprocessed data.

python3 train_model.py
Step 4: Model Evaluation
Evaluate the trained model and view the results.


python3 evaluate_model.py
Step 5: Making Predictions
Use the trained model to make predictions on new data.


python3 predict.py