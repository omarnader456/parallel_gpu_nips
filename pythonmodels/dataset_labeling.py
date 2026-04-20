import pandas as pd
import numpy as np
import gc
from scapy.all import PcapReader, IP, TCP, UDP

def get_malicious_5tuples(csv_paths):
    
    malicious_set = set()
    total_attacks = 0

    for csv_path in csv_paths:
        print(f"loading labels from {csv_path}")
        df = pd.read_csv(csv_path, skipinitialspace=True, low_memory=False)
        df.columns = df.columns.str.strip()
        
        attacks = df[df['Label'] != 'BENIGN']
        total_attacks += len(attacks)
        
        for _, row in attacks.iterrows():
            src_ip = str(row['Source IP'])
            dst_ip = str(row['Destination IP'])
            src_port = int(row['Source Port'])
            dst_port = int(row['Destination Port'])
            proto = int(row['Protocol'])
            
            malicious_set.add((src_ip, src_port, dst_ip, dst_port, proto))
            malicious_set.add((dst_ip, dst_port, src_ip, src_port, proto))
            
        del df
        del attacks
        gc.collect()
        
    print(f"\n {total_attacks} malicious flow records across all csvs.")
    return malicious_set

def extract_entire_pcap(pcap_path, malicious_set, seq_len=10):
    flows = {}
    labels = {}
    print(f"\nbeginning full extraction of {pcap_path}")
    
    with PcapReader(pcap_path) as pcap:
        for i, pkt in enumerate(pcap):
            if i % 1000000 == 0 and i > 0:
                print(f"processed {i:,} packets current tracked flows: {len(flows):,}")
                
            if IP in pkt:
                ip_layer = pkt[IP]
                proto = ip_layer.proto
                
                if proto not in [6, 17]:
                    continue
                    
                src = ip_layer.src
                dst = ip_layer.dst
                tot_len = ip_layer.len
                ihl_bytes = ip_layer.ihl * 4
                
                src_port, dst_port, flags = 0, 0, 0
                
                if TCP in pkt:
                    tcp_layer = pkt[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    flags = int(tcp_layer.flags)
                elif UDP in pkt:
                    udp_layer = pkt[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                    flags = 0
                
                flow_tuple = (src, src_port, dst, dst_port, proto)
                flow_key = tuple(sorted([src, dst, str(src_port), str(dst_port), str(proto)]))
                
                if flow_key not in flows:
                    flows[flow_key] = []
                    if flow_tuple in malicious_set:
                        labels[flow_key] = 1
                    else:
                        labels[flow_key] = 0
                
                if len(flows[flow_key]) < seq_len:
                    features = [tot_len, proto, src_port, dst_port, ihl_bytes, flags]
                    flows[flow_key].append(features)

    print("\nPCAP reading complete. Padding sequences into arrays")
    X_data = []
    y_data = []
    
    for f_key, packet_list in flows.items():
        padded_sequence = np.zeros((seq_len, 6), dtype=np.float32)
        actual_len = len(packet_list)
        padded_sequence[:actual_len, :] = np.array(packet_list, dtype=np.float32)
        
        X_data.append(padded_sequence)
        y_data.append(labels[f_key])
        
    return np.array(X_data), np.array(y_data)

if __name__ == "__main__":
    CSV_FILES = [
        "Friday-WorkingHours-Morning.pcap_ISCX.csv",           
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"     
    ]
    
    PCAP_FILE = "Friday-WorkingHours.pcap" 
    
    malicious_tuples = get_malicious_5tuples(CSV_FILES)
    
    X, y = extract_entire_pcap(PCAP_FILE, malicious_tuples, seq_len=10)
    
    malicious_count = np.sum(y == 1)
    benign_count = np.sum(y == 0)
    print(f"\nfinal dataset stats")
    print(f"total flows extracted: {len(y):,}")
    print(f"malicious flows:    {malicious_count:,}")
    print(f"benign flows:       {benign_count:,}")
    
    print("\nsaving dataset to disk (X_friday.npy, y_friday.npy)")
    np.save("X_friday.npy", X)
    np.save("y_friday.npy", y)
    print("saving complete")