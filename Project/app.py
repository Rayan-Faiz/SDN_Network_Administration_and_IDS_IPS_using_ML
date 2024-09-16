from flask import Flask, jsonify, request, render_template
import requests
import pandas as pd
from io import StringIO

# Replace with the IP address of the machine running the Ryu controller
RYU_CONTROLLER_URL = "http://0.0.0.0:5000"

app = Flask(__name__, static_folder='static', template_folder='static')

# Rendering routes
@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/mac_management')
def mac_management():
    return app.send_static_file('mac_management.html')

@app.route('/ip_management')
def ip_management():
    return app.send_static_file('ip_management.html')

@app.route('/csv_upload')
def csv_upload():
    return app.send_static_file('csv_upload.html')

@app.route('/performance_page')
def performance_page():
    return app.send_static_file('performance.html')

# MAC management endpoints
@app.route('/block_mac', methods=['POST'])
def block_mac():
    data = request.get_json()
    response = requests.post(f"{RYU_CONTROLLER_URL}/block_mac", json=data)
    return jsonify(response.json())

@app.route('/unblock_mac', methods=['POST'])
def unblock_mac():
    data = request.get_json()
    response = requests.post(f"{RYU_CONTROLLER_URL}/unblock_mac", json=data)
    return jsonify(response.json())

@app.route('/blocked_macs', methods=['GET'])
def blocked_macs():
    response = requests.get(f"{RYU_CONTROLLER_URL}/blocked_macs")
    return jsonify(response.json())

# IP management endpoints
@app.route('/block_ip', methods=['POST'])
def block_ip():
    data = request.get_json()
    response = requests.post(f"{RYU_CONTROLLER_URL}/block_ip", json=data)
    return jsonify(response.json())

@app.route('/unblock_ip', methods=['POST'])
def unblock_ip():
    data = request.get_json()
    response = requests.post(f"{RYU_CONTROLLER_URL}/unblock_ip", json=data)
    return jsonify(response.json())

@app.route('/blocked_ips', methods=['GET'])
def blocked_ips():
    response = requests.get(f"{RYU_CONTROLLER_URL}/blocked_ips")
    return jsonify(response.json())

# CSV upload endpoint
@app.route('/block_csv', methods=['POST'])
def block_csv():
    # Check if the request contains a file
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    
    # Check if a file is selected
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # Read the CSV file into a DataFrame
    df = pd.read_csv(file)
    
    # Remove rows where 'Label' is 0 or 'Normal'
    df_filtered = df[(df['Label'] != 0) & (df['Label'] != 'Normal')]
    
    # Convert the filtered DataFrame back to CSV format
    filtered_csv_content = df_filtered.to_csv(index=False)
    
    # Send the filtered CSV to the Ryu controller
    response = requests.post(f"{RYU_CONTROLLER_URL}/block_csv", files={'file': ('filtered.csv', filtered_csv_content)})
    
    return jsonify(response.json())

# Flow tables listing endpoint
@app.route('/flow_tables_page')
def flow_tables_page():
    # Fetch flow tables from the Ryu controller
    response = requests.get(f"{RYU_CONTROLLER_URL}/flow_tables")
    flow_data = response.json()

    # Render the template with flow table data
    return render_template('flow_tables.html', flow_data=flow_data)

# Performance check endpoint
@app.route('/performance')
def performance():
    # Fetch performance data from the Ryu controller
    response = requests.get(f"{RYU_CONTROLLER_URL}/performance")
    performance_data = response.json()
    return jsonify(performance_data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
