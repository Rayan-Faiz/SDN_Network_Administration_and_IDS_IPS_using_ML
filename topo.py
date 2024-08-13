from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch, OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def custom_topology():
	net = Mininet(controller=RemoteController, switch=OVSSwitch)

	# Add conttroller
	info('*** Adding controller\n')
	c0 = net.addController('c0', controller=RemoteController, ip='172.16.158.138', port=6633)

	# Add switches
	info('*** Adding switches\n')
	s0 = net.addSwitch('s0', protocols='OpenFlow13')
	s1 = net.addSwitch('s1', protocols='OpenFlow13')
	s2 = net.addSwitch('s2', protocols='OpenFlow13')
	s3 = net.addSwitch('s3', protocols='OpenFlow13')

	# Add hosts
	info('*** Adding hosts\n')
	h1 = net.addHost('h1', ip='10.0.1.1/24')
	h2 = net.addHost('h2', ip='10.0.1.2/24')
	h3 = net.addHost('h3', ip='10.0.2.3/24')
	h4 = net.addHost('h4', ip='10.0.2.4/24')
	h5 = net.addHost('h5', ip='10.0.3.5/24')
	h6 = net.addHost('h6', ip='10.0.3.6/24')

	# Create links between switches
	info('*** Creating links\n')
	net.addLink(s0, s1)
	net.addLink(s0, s2)
	net.addLink(s0, s3)

	# Create links between switches and hosts
	net.addLink(s1, h1)
	net.addLink(s1, h2)
	net.addLink(s2, h3)
	net.addLink(s2, h4)
	net.addLink(s3, h5)
	net.addLink(s3, h6)

	# Start network
	info('*** Starting network\n')
	net.start()

	# Enable IP forwarding on s0 and assign @IP to interfaces
	s0 = net.get('s0')
	s0.cmd('sysctl -w net.ipv4.ip_forward=1')
	s0.cmd('ifconfig s0-eth1 10.0.1.254/24')
	s0.cmd('ifconfig s0-eth2 10.0.2.254/24')
	s0.cmd('ifconfig s0-rth3 10.0.3.254/24')

	# Set default routes on hosts
	h1.cmd('ip route add default via 10.0.1.1')
	h2.cmd('ip route add default via 10.0.1.2')
	h3.cmd('ip route add default via 10.0.2.3')
	h4.cmd('ip route add default via 10.0.2.4')
	h5.cmd('ip route add default via 10.0.3.5')
	h6.cmd('ip route add default via 10.0.3.6')

	# Show switch and DPIDs
	info('*** Showing DPIDs\n')
	for switch in net.switches:
		print(f'Switch {switch.name} DPID: {switch.dpid}')

	# Run CLI
	info('*** Running CLI\n')
	CLI(net)

	# Stop network
	info('*** Stopping network\n')
	net.stop()

if __name__ == '__main__':
	setLogLevel('info')
	custom_topology()

