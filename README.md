# SDN Network Traffic Management & Attack Detection and Prevention using Ryu and SVM

## Project Overview
This project simulates a Software-Defined Network (SDN) using Mininet and Ryu, combined with an attack detection system using a Support Vector Machine (SVM) model. The system dynamically manages network traffic and detects security threats based on real-time network flows.

## Key Components
- Mininet: Used to create a virtual network topology.
- Ryu SDN Controller: Manages network traffic and applies flow rules dynamically.
- SVM Model: Trained to detect network attacks (e.g., DDoS, brute force attacks).
- Custom Traffic Flow Capture: A script to capture network traffic and extract flow features.
- Web Application: Flask-based interface for interacting with the network.
- Network Topology Script: Available in the GitHub repository to simulate the network.
- InSDN Dataset: Used for training the attack detection model, sourced from IEEE Access.

## Features
- Dynamic Network Topology: Custom topology created using Mininet, with hosts and switches.
- Traffic Flow Management: Managed dynamically through the Ryu SDN controller.
- Attack Detection: The trained SVM model classifies and blocks malicious traffic in real time.
- Custom Traffic Capture: A Python script captures network traffic flows for machine learning analysis.
- Web Interface: Provides real-time control and monitoring of the SDN network.
- High Availability: The system can handle multiple controllers for redundancy.

## Network Topology
The network topology consists of:
- A central switch acting as a router.
- Three additional switches, each connected to two hosts.
- The entire network is controlled by the Ryu controller for dynamic flow management.

## Prerequisites

### Software Requirements
- Mininet: Mininet Installation Guide
- Ryu Controller: Ryu Installation Guide
- Python 3.x
- Flask: Web framework for the control interface.
- tcpdump: For traffic capture.
- Scikit-learn and PyTorch: Required for training the SVM model.

## Dataset
The InSDN Dataset from IEEE Access is used to train the SVM model. This dataset contains labeled traffic flows, with both normal and attack data, including DDoS and brute force attacks.

## Installation and Setup

### Step 1: Clone the Project
```
git clone https://github.com/Rayan-Faiz/Network_Administration.git
cd Network_Administration
```

### Step 2: Install Dependencies
Install the necessary dependencies:
```
pip install -r requirements.txt
```

### Step 3: Set up the Mininet Topology
Run the custom Mininet topology script:
```
sudo python3 network.py
```

### Step 4: Run the Ryu Controller
Start the Ryu SDN controller:
```
ryu-manager Project/ryu_controller.py
```

### Step 5: Start the Flask Web Application
Run the Flask app to manage the network:
```
python Project/app.py
```
Access it at http://localhost:5000.

### Step 6: Capture Traffic
Use the custom traffic capture script to collect network flows:
```
python Project/flow_capture.py
```

### Step 7: Train the SVM Model
To train the SVM model, modify the data path inside the training script to point to the InSDN Dataset:

## Inside SVM_Training.py
```
data_path = "path/to/InSDN_Dataset.csv"
```
Then run the training script:
```
python Machine_Learning_Detection_System/SVM_Training.py
```
This will train the model and save it for real-time classification.

## Usage
- Network Management: Use the web interface to block or unblock hosts and manage network traffic.
- Real-Time Attack Detection: The Ryu controller classifies traffic using the trained SVM model and blocks malicious flows.
- Traffic Capture: Capture network traffic using the custom traffic capture script and analyze it using the SVM model.

## Results
After training on the InSDN Dataset, the updated SVM model achieved:
- Training accuracy: 99.02%
- Testing accuracy: 98.87%
These results make the model effective in detecting DDoS, brute force attacks, etc.. in an SDN environment.

## Future Enhancements
- Enhance the SVM model's performance by experimenting with deep learning techniques.
- Add more real-time monitoring and alerting features to the web interface.
- Scale the solution to more complex topologies for testing robustness.
- Investigate other machine learning models for improved attack detection.

## Contributors
Rayan-Faiz - GitHub

## License
This project is licensed under the MIT License.

