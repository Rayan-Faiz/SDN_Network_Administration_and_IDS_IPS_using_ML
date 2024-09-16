import paramiko
import scp
import pyshark
import csv
import time
from collections import defaultdict
import numpy as np

# Define your SSH and tcpdump parameters
remote_host = '192.168.1.42'
remote_user = 'mininet'
remote_password = 'mininet'
remote_pcap_file = '/home/mininet/capture.pcap'
local_pcap_file = 'capture.pcap'
packet_count = 100

# Function to execute a remote command over SSH
def execute_ssh_command(ssh, command):
    stdin, stdout, stderr = ssh.exec_command(command)
    stdout.channel.recv_exit_status()  # Wait for the command to finish
    return stdout.read().decode(), stderr.read().decode()

# SSH into the remote machine and run tcpdump
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(remote_host, username=remote_user, password=remote_password)

# Run tcpdump command on the remote machine with sudo
tcpdump_command = f'echo {remote_password} | sudo -S tcpdump -i any -c {packet_count} -w {remote_pcap_file}'
output, errors = execute_ssh_command(ssh, tcpdump_command)

# Check if the file exists on the remote machine
output, errors = execute_ssh_command(ssh, f'ls {remote_pcap_file}')
file_exists = len(errors) == 0

if not file_exists:
    print("Error: The pcap file was not created.")
    ssh.close()
    exit(1)

# Use SCP to transfer the file to the local machine
scp_client = scp.SCPClient(ssh.get_transport())
scp_client.get(remote_pcap_file, local_pcap_file)

# Delete the remote pcap file
execute_ssh_command(ssh, f'rm {remote_pcap_file}')

# Close the SCP and SSH connections
scp_client.close()
ssh.close()

# Load the pcap file using pyshark
cap = pyshark.FileCapture(local_pcap_file)

# Define the CSV file path
csv_file = 'capture_features.csv'

# Data structures to hold flow statistics
flows = defaultdict(lambda: {
    'fwd_pkts': [], 'bwd_pkts': [], 'fwd_times': [], 'bwd_times': [],
    'fwd_pkt_sizes': [], 'bwd_pkt_sizes': [],
    'fwd_flags': defaultdict(int), 'bwd_flags': defaultdict(int),
    'flow_bytes': 0, 'flow_pkts': 0
})

def get_flow_key(pkt):
    try:
        ip_layer = pkt.ip
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        if proto == '6' and hasattr(pkt, 'tcp'):  # TCP
            transport_layer = pkt.tcp
            src_port = transport_layer.srcport
            dst_port = transport_layer.dstport
        elif proto == '17' and hasattr(pkt, 'udp'):  # UDP
            transport_layer = pkt.udp
            src_port = transport_layer.srcport
            dst_port = transport_layer.dstport
        else:
            return None  # Ignore non-TCP/UDP packets

        return (src_ip, src_port, dst_ip, dst_port, proto)
    except AttributeError:
        return None  # Ignore packets without an IP layer

# Process each packet in the capture
for packet in cap:
    flow_key = get_flow_key(packet)
    if flow_key is None:
        continue

    timestamp = float(packet.sniff_timestamp)
    pkt_size = int(packet.length)

    if flow_key[0] == packet.ip.src:  # Forward direction
        flows[flow_key]['fwd_pkts'].append(packet)
        flows[flow_key]['fwd_times'].append(timestamp)
        flows[flow_key]['fwd_pkt_sizes'].append(pkt_size)
        
        # Ensure TCP layer exists before accessing TCP flags
        if hasattr(packet, 'tcp'):
            tcp_flags = packet.tcp
            if hasattr(tcp_flags, 'psh_flag') and tcp_flags.psh_flag == '1':
                flows[flow_key]['fwd_flags']['PSH'] += 1
            if hasattr(tcp_flags, 'urg_flag') and tcp_flags.urg_flag == '1':
                flows[flow_key]['fwd_flags']['URG'] += 1
            if hasattr(tcp_flags, 'fin_flag') and tcp_flags.fin_flag == '1':
                flows[flow_key]['fwd_flags']['FIN'] += 1
            if hasattr(tcp_flags, 'syn_flag') and tcp_flags.syn_flag == '1':
                flows[flow_key]['fwd_flags']['SYN'] += 1
            if hasattr(tcp_flags, 'rst_flag') and tcp_flags.rst_flag == '1':
                flows[flow_key]['fwd_flags']['RST'] += 1
            if hasattr(tcp_flags, 'ack_flag') and tcp_flags.ack_flag == '1':
                flows[flow_key]['fwd_flags']['ACK'] += 1
            if hasattr(tcp_flags, 'urg_flag') and tcp_flags.urg_flag == '1':
                flows[flow_key]['fwd_flags']['URG'] += 1
    else:  # Backward direction
        flows[flow_key]['bwd_pkts'].append(packet)
        flows[flow_key]['bwd_times'].append(timestamp)
        flows[flow_key]['bwd_pkt_sizes'].append(pkt_size)

        # Ensure TCP layer exists before accessing TCP flags
        if hasattr(packet, 'tcp'):
            tcp_flags = packet.tcp
            if hasattr(tcp_flags, 'psh_flag') and tcp_flags.psh_flag == '1':
                flows[flow_key]['bwd_flags']['PSH'] += 1
            if hasattr(tcp_flags, 'urg_flag') and tcp_flags.urg_flag == '1':
                flows[flow_key]['bwd_flags']['URG'] += 1
            if hasattr(tcp_flags, 'fin_flag') and tcp_flags.fin_flag == '1':
                flows[flow_key]['bwd_flags']['FIN'] += 1
            if hasattr(tcp_flags, 'syn_flag') and tcp_flags.syn_flag == '1':
                flows[flow_key]['bwd_flags']['SYN'] += 1
            if hasattr(tcp_flags, 'rst_flag') and tcp_flags.rst_flag == '1':
                flows[flow_key]['bwd_flags']['RST'] += 1
            if hasattr(tcp_flags, 'ack_flag') and tcp_flags.ack_flag == '1':
                flows[flow_key]['bwd_flags']['ACK'] += 1
            if hasattr(tcp_flags, 'urg_flag') and tcp_flags.urg_flag == '1':
                flows[flow_key]['bwd_flags']['URG'] += 1

# Calculate flow-based features
with open(csv_file, mode='w', newline='') as file:
    csv_writer = csv.writer(file)
    # Write header
    csv_writer.writerow([
        'Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
        'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
        'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 
        'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 
        'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 
        'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Len', 'Bwd Header Len', 
        'Fwd Pkts/s', 'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var', 
        'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count', 
        'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg', 
        'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts', 
        'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts', 'Init Fwd Win Byts', 'Init Bwd Win Byts', 
        'Fwd Act Data Pkts', 'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 
        'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
    ])

    for flow_id, stats in flows.items():
        # Forward IAT
        fwd_iats = np.diff(stats['fwd_times']) if len(stats['fwd_times']) > 1 else [0]
        fwd_iat_tot = np.sum(fwd_iats)
        fwd_iat_mean = np.mean(fwd_iats) if len(fwd_iats) > 0 else 0
        fwd_iat_std = np.std(fwd_iats) if len(fwd_iats) > 0 else 0
        fwd_iat_max = np.max(fwd_iats) if len(fwd_iats) > 0 else 0
        fwd_iat_min = np.min(fwd_iats) if len(fwd_iats) > 0 else 0

        # Backward IAT
        bwd_iats = np.diff(stats['bwd_times']) if len(stats['bwd_times']) > 1 else [0]
        bwd_iat_tot = np.sum(bwd_iats)
        bwd_iat_mean = np.mean(bwd_iats) if len(bwd_iats) > 0 else 0
        bwd_iat_std = np.std(bwd_iats) if len(bwd_iats) > 0 else 0
        bwd_iat_max = np.max(bwd_iats) if len(bwd_iats) > 0 else 0
        bwd_iat_min = np.min(bwd_iats) if len(bwd_iats) > 0 else 0

        # Packet lengths
        all_pkt_sizes = stats['fwd_pkt_sizes'] + stats['bwd_pkt_sizes']
        pkt_len_min = np.min(all_pkt_sizes) if all_pkt_sizes else 0
        pkt_len_max = np.max(all_pkt_sizes) if all_pkt_sizes else 0
        pkt_len_mean = np.mean(all_pkt_sizes) if all_pkt_sizes else 0
        pkt_len_std = np.std(all_pkt_sizes) if all_pkt_sizes else 0
        pkt_len_var = np.var(all_pkt_sizes) if all_pkt_sizes else 0

        # Flags
        fin_flag_cnt = stats['fwd_flags']['FIN'] + stats['bwd_flags']['FIN']
        syn_flag_cnt = stats['fwd_flags']['SYN'] + stats['bwd_flags']['SYN']
        rst_flag_cnt = stats['fwd_flags']['RST'] + stats['bwd_flags']['RST']
        psh_flag_cnt = stats['fwd_flags']['PSH'] + stats['bwd_flags']['PSH']
        ack_flag_cnt = stats['fwd_flags']['ACK'] + stats['bwd_flags']['ACK']
        urg_flag_cnt = stats['fwd_flags']['URG'] + stats['bwd_flags']['URG']
        cwe_flag_cnt = stats['fwd_flags']['CWE'] + stats['bwd_flags']['CWE']
        ece_flag_cnt = stats['fwd_flags']['ECE'] + stats['bwd_flags']['ECE']

        # Subflows (assuming no fragmentation)
        subflow_fwd_pkts = len(stats['fwd_pkts'])
        subflow_fwd_byts = sum(stats['fwd_pkt_sizes'])
        subflow_bwd_pkts = len(stats['bwd_pkts'])
        subflow_bwd_byts = sum(stats['bwd_pkt_sizes'])

        # Convert time delta to seconds
        flow_duration = (stats['fwd_pkts'][-1].sniff_time - stats['fwd_pkts'][0].sniff_time).total_seconds() if stats['fwd_pkts'] else 0

        # Write flow statistics
        csv_writer.writerow([
            flow_id, stats['fwd_pkts'][0].ip.src if stats['fwd_pkts'] else '', stats['fwd_pkts'][0].tcp.srcport if stats['fwd_pkts'] and hasattr(stats['fwd_pkts'][0], 'tcp') else '',
            stats['fwd_pkts'][0].ip.dst if stats['fwd_pkts'] else '', stats['fwd_pkts'][0].tcp.dstport if stats['fwd_pkts'] and hasattr(stats['fwd_pkts'][0], 'tcp') else '',
            stats['fwd_pkts'][0].ip.proto if stats['fwd_pkts'] else '', flow_duration,
            len(stats['fwd_pkts']), len(stats['bwd_pkts']), sum(stats['fwd_pkt_sizes']), sum(stats['bwd_pkt_sizes']),
            np.max(stats['fwd_pkt_sizes']) if stats['fwd_pkt_sizes'] else 0,
            np.min(stats['fwd_pkt_sizes']) if stats['fwd_pkt_sizes'] else 0,
            np.mean(stats['fwd_pkt_sizes']) if stats['fwd_pkt_sizes'] else 0,
            np.std(stats['fwd_pkt_sizes']) if stats['fwd_pkt_sizes'] else 0,
            np.max(stats['bwd_pkt_sizes']) if stats['bwd_pkt_sizes'] else 0,
            np.min(stats['bwd_pkt_sizes']) if stats['bwd_pkt_sizes'] else 0,
            np.mean(stats['bwd_pkt_sizes']) if stats['bwd_pkt_sizes'] else 0,
            np.std(stats['bwd_pkt_sizes']) if stats['bwd_pkt_sizes'] else 0,
            subflow_fwd_byts / flow_duration if flow_duration > 0 else 0,
            (len(stats['fwd_pkts']) + len(stats['bwd_pkts'])) / flow_duration if flow_duration > 0 else 0,
            fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min,
            bwd_iat_tot, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min,
            stats['fwd_flags']['PSH'], stats['bwd_flags']['PSH'], stats['fwd_flags']['URG'], stats['bwd_flags']['URG'],
            sum(stats['fwd_pkt_sizes']), sum(stats['bwd_pkt_sizes']),
            len(stats['fwd_pkts']) / flow_duration if flow_duration > 0 else 0,
            len(stats['bwd_pkts']) / flow_duration if flow_duration > 0 else 0,
            pkt_len_min, pkt_len_max, pkt_len_mean, pkt_len_std, pkt_len_var,
            fin_flag_cnt, syn_flag_cnt, rst_flag_cnt, psh_flag_cnt, ack_flag_cnt, 
            urg_flag_cnt, cwe_flag_cnt, ece_flag_cnt,
            subflow_fwd_pkts, subflow_fwd_byts, subflow_bwd_pkts, subflow_bwd_byts
        ])

print(f'Flow features have been extracted to CSV: {csv_file}')
