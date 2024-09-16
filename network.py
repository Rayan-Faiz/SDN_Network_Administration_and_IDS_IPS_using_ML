from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.nodelib import NAT
from mininet.log import setLogLevel, info
import os
import sys

def network():
	net = Mininet(controller=RemoteController, link=TCLink, switch=OVSSwitch, waitConnected=True)

	# Add conttroller
	info('*** Adding controller\n')
	c0 = net.addController('c0', controller=RemoteController, ip='192.168.1.42', port=6633)
	# c1 = net.addController('c1', controller=RemoteController, ip='177.20.10.8', port=6632)

	# Add switches
	info('*** Adding switches\n')
	s0 = net.addSwitch('s0', protocols='OpenFlow13')
	s1 = net.addSwitch('s1', protocols='OpenFlow13')
	s2 = net.addSwitch('s2', protocols='OpenFlow13')
	s3 = net.addSwitch('s3', protocols='OpenFlow13')

	# Add hosts
	info('*** Adding hosts\n')
	h1 = net.addHost('h1', ip='172.16.158.231/24')
	h2 = net.addHost('h2', ip='172.16.158.232/24')
	h3 = net.addHost('h3', ip='172.16.158.233/24')
	h4 = net.addHost('h4', ip='172.16.158.234/24')
	h5 = net.addHost('h5', ip='172.16.158.235/24')
	h6 = net.addHost('h6', ip='172.16.158.236/24')

	# Create links between switches
	info('*** Creating links\n')

	net.addLink(h1, s1)
	net.addLink(h2, s1)
	net.addLink(h3, s2)
	net.addLink(h4, s2)
	net.addLink(h5, s3)
	net.addLink(h6, s3)

	net.addLink(s1, s0)
	net.addLink(s2, s0)
	net.addLink(s3, s0)

	# Add NAT connectivity
	net.addNAT(ip='172.16.158.230/24', inNamespace=False).configDefault()
	#net.addLink(s0, nat0)

	# Start network
	info('*** Starting network\n')
	net.start()

	# Enable IP forwarding on s0 and assign @IP to interfaces
	s0.cmd('sysctl -w net.ipv4.ip_forward=1')
	s0.cmd('ifconfig s0-eth1 172.16.158.254/24')
	s0.cmd('ifconfig s0-eth2 172.16.158.254/24')
	s0.cmd('ifconfig s0-eth3 172.16.158.254/24')

	# Set default routes on hosts
	h1.cmd('ip route add default via 172.16.158.254')
	h2.cmd('ip route add default via 172.16.158.254')
	h3.cmd('ip route add default via 172.16.158.254')
	h4.cmd('ip route add default via 172.16.158.254')
	h5.cmd('ip route add default via 172.16.158.254')
	h6.cmd('ip route add default via 172.16.158.254')

	# Run CLI
	info('*** Running CLI\n')
	CLI(net)

	# Stop network
	info('*** Stopping network\n')
	net.stop()
	os.system('mn -c')

if __name__ == '__main__':
	setLogLevel('info')
	network()
