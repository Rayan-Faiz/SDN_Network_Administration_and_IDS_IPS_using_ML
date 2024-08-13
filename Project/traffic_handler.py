import paramiko
import scp
import pyshark
import csv
import time

# Define your SSH and tcpdump parameters
remote_host = '172.16.158.137'
remote_user = 'mininet'
remote_password = 'mininet'
remote_pcap_file = '/home/mininet/capture.pcap'  # Use a directory with write permissions
local_pcap_file = 'capture.pcap'
#capture_interface = 'eth0'
packet_count = 500

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
tcpdump_command = f'sudo tcpdump -i any -c {packet_count} -w {remote_pcap_file}'
output, errors = execute_ssh_command(ssh, tcpdump_command)

# Print the output and errors for debugging
print(f"Output: {output}")
print(f"Errors: {errors}")

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
csv_file = 'capture.csv'

# Get all field names dynamically
fieldnames = set()
for packet in cap:
    for layer in packet.layers:
        for field in layer.field_names:
            fieldnames.add(field)

# Open the CSV file for writing
with open(csv_file, mode='w', newline='') as file:
    csv_writer = csv.writer(file)
    
    # Write the header row
    csv_writer.writerow(['No.', 'Time'] + sorted(fieldnames))
    
    # Write packet data
    for i, packet in enumerate(cap):
        row = [i + 1, packet.sniff_time]
        packet_fields = {field: '' for field in fieldnames}
        
        for layer in packet.layers:
            for field in layer.field_names:
                packet_fields[field] = getattr(layer, field, '')

        row.extend([packet_fields[field] for field in sorted(fieldnames)])
        csv_writer.writerow(row)

print(f'PCAP file has been converted to CSV: {csv_file}')

