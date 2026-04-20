# Parallel GPU-Accelerated Network Intrusion Prevention System (NIPS)

A performance driven, hybrid AI-driven Network Intrusion Prevention System able to detect and mitigate volumetric network attacks (like SYN floods and DDoS) at line-rate. 

System latency hovers in the microsecond range by bypassing the standard Linux networking stack using **eBPF/XDP** and routing packets directly to userspace via **AF_XDP**. Threat classification is accelerated across multiple cores and offloaded to a GPU using a hybrid **TensorRT (CNN-LSTM)** and **XGBoost** pipeline.

# Architecture
* **Layer 2 Hardware Offloading:** eBPF/XDP drops blacklisted IPs directly at the NIC level before they reach the kernel.
* **Userspace Packet Processing:** AF_XDP and DPDK distribute packet flows across 12 CPU cores via lockless ring buffers.
* **Hybrid AI Engine:** A C++ inference engine extracts flow embeddings using a TensorRT-optimized CNN-LSTM, classified by XGBoost to determine malicious intent.
* **Dynamic Honeypot Routing:** Suspicious packets are rewritten and redirected to an isolated honeypot namespace for observation.

# Prerequisites & Dependencies

1. **OS:** Linux (Ubuntu 22.04 or Pop!_OS) with Kernel >= 5.15
2. **Compiler:** `clang`, `llvm`, `gcc`, `make`
3. **Libraries:** `libbpf`, `libxdp`, `dpdk`
4. **NVIDIA Stack:**
   * CUDA Toolkit 12.0+
   * TensorRT 8.6.1.6 (Extract to project root)
   * cuDNN 8.9.7 (Extract to project root)
5. **AI Libraries:** XGBoost C API (`libxgboost.so`)
6. python libraries and virtual environment
#  Installation & Compilation

  1. git clone [https://github.com/omarnader456/parallel_gpu_nips.git](https://github.com/omarnader456/parallel_gpu_nips.git)
   cd parallel_gpu_nips
 2. Run the Python labeling and extraction scripts (dataset_labeling.py, model_train_extract.py) to generate the required .engine and .model files.
 3. Place cnn_lstm.engine and the XGBoost model in the xdpstack/ingress/ directory.
 4. compile the c++ engine cd xdpstack/ingress
make
 5. allocate 2gb hugepages for dpdk sudo sysctl -w vm.nr_hugepages=1024 and verify with grep HugePages_Total /proc/meminfo  
6. ensure leftover sockets and memory maps are cleared sudo rm -rf /var/run/dpdk/*
7. build the network topology
  * clear old virtual interfaces
  * sudo ip link del veth_nips 2>/dev/null
  * sudo ip link del honeypot 2>/dev/null
  * sudo ip netns del attacker 2>/dev/null
  * create honeypot and honeypot tap (honeypot tap needed to make tcpdump visible)
  * sudo ip link add honeypot type veth peer name honeypot_tap
  * sudo ip link set dev honeypot up
  * sudo ip link set dev honeypot_tap up
  * attacker namespace and 12 queues
  * sudo ip netns add attacker
  * sudo ip link add veth_nips numtxqueues 12 numrxqueues 12 type veth peer name veth_attacker numtxqueues 12 numrxqueues 12
  * nips host configuration
  * sudo ip link set dev veth_nips up
  * sudo ip link set dev veth_nips promisc on
  * sudo ip addr add 10.0.0.1/24 dev veth_nips
  * sudo ip addr add fd00::1/64 dev veth_nips
  * attacker container configuration
  * sudo ip link set veth_attacker netns attacker
  * sudo ip netns exec attacker ip link set dev veth_attacker up
  * sudo ip netns exec attacker ip addr add 10.0.0.2/24 dev veth_attacker
  * sudo ip netns exec attacker ip addr add fd00::2/64 dev veth_attacker
  * disable checksum offloading
  * sudo ethtool -K veth_nips tx off rx off
  * sudo ip netns exec attacker ethtool -K veth_attacker tx off rx off
 71. make sure mac address of your honeypot same as the one in kernel and if not then update kernel
 * cat /sys/class/net/honeypot/address
 8. compile and run
  * cd ~/nips/xdpstack/ingress
  * make clean && make
  * sudo ./xdp_user2 --in-memory -- -i veth_nips -S
 9. start honeypot monitoring
  * sudo tcpdump -i honeypot_tap -n -e
 1. testing
 * benign test
 * sudo ip netns exec attacker ping -c 3 10.0.0.1
  * Success Criteria: 3 packets transmitted, 3 received, 0% packet loss.
 * test 2
 *  sudo -v to allow bash script with loop
 * sudo ip netns exec attacker bash -c 'for i in {1..50}; do echo "payload" > /dev/udp/fd00::1/53; done'
 * Success Criteria: Traffic not tagged because each packet treated as a seperate flow because bash assigns a different source port to each packet
 * test 3
 * eBPF Kernel Rate Limiting (IPv6)
 * sudo ip netns exec attacker ping -6 -f fd00::1
 * Success Criteria: 18 - 20 pkts received, then  rest of the packets dropped. rx_npkts stay at 0 because the packets are dealt with at the kernel level.
 * test 4
 * Hybrid AI Inference & BPF Redirection
 * sudo ip netns exec attacker hping3 -S -p 80 --flood 10.0.0.1
 * success criteria 1: main terminal prints >>> HYBRID AI DETECTED MALICIOUS IPv4 FLOW -> BLOCKING IP <<<
 * success criteria 2: overflow with packets showing  mac 3a:15:f4:67:a5:bc  
