from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from flask import Flask, jsonify, request, send_from_directory
import psutil
import threading
import csv
import time
import json
from io import StringIO

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.blocked_macs = set()
        self.blocked_ips = set()
        self.datapaths = {}
        self.switches = {}
        self.hosts = {}
        self.links = []

        # Start Flask API in a separate thread
        self.app = Flask(__name__, static_folder='static')
        
        self.app.add_url_rule('/block_mac', 'block_mac', self.block_host, methods=['POST'])
        self.app.add_url_rule('/unblock_mac', 'unblock_mac', self.unblock_host, methods=['POST'])
        self.app.add_url_rule('/block_ip', 'block_ip', self.block_ip, methods=['POST'])
        self.app.add_url_rule('/unblock_ip', 'unblock_ip', self.unblock_ip, methods=['POST'])
        self.app.add_url_rule('/blocked_macs', 'blocked_macs', self.list_blocked_macs, methods=['GET'])
        self.app.add_url_rule('/blocked_ips', 'blocked_ips', self.list_blocked_ips, methods=['GET'])
        self.app.add_url_rule('/block_csv', 'block_csv', self.block_csv, methods=['POST'])
        self.app.add_url_rule('/flow_tables', 'flow_tables', self.get_flow_tables, methods=['GET'])
        self.app.add_url_rule('/performance', 'performance', self.get_performance, methods=['GET'])

        threading.Thread(target=self.app.run, kwargs={'host': '0.0.0.0', 'port': 5000}).start()

    def get_performance(self):
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_info = psutil.virtual_memory()
        disk_info = psutil.disk_usage('/')

        performance_data = {
            'cpu_usage': cpu_usage,
            'memory_total': memory_info.total,
            'memory_used': memory_info.used,
            'memory_free': memory_info.free,
            'disk_total': disk_info.total,
            'disk_used': disk_info.used,
            'disk_free': disk_info.free
        }
        return jsonify(performance_data)

    def block_host(self):
        data = request.get_json()
        host_mac = data.get('mac')
        if host_mac:
            self.blocked_macs.add(host_mac)
            self.logger.info("Blocking host with MAC: %s", host_mac)
            # Install blocking flows on all datapaths
            for datapath in self.datapaths.values():
                self.block_flows(datapath, host_mac)
            return jsonify({'status': 'success', 'mac': host_mac}), 200
        return jsonify({'status': 'error', 'message': 'MAC address not provided'}), 400

    def unblock_host(self):
        data = request.get_json()
        host_mac = data.get('mac')
        if host_mac and host_mac in self.blocked_macs:
            self.blocked_macs.remove(host_mac)
            self.logger.info("Unblocking host with MAC: %s", host_mac)
            # Remove blocking flows on all datapaths
            for datapath in self.datapaths.values():
                self.unblock_flows(datapath, host_mac)
            return jsonify({'status': 'success', 'mac': host_mac}), 200
        return jsonify({'status': 'error', 'message': 'MAC address not found or not blocked'}), 400

    def block_ip(self):
        data = request.get_json()
        ip_address = data.get('ip')
        if ip_address:
            self.blocked_ips.add(ip_address)
            self.logger.info("Blocking IP: %s", ip_address)
            # Install blocking flows on all datapaths
            for datapath in self.datapaths.values():
                self.block_ip_flows(datapath, ip_address)
            return jsonify({'status': 'success', 'ip': ip_address}), 200
        return jsonify({'status': 'error', 'message': 'IP address not provided'}), 400

    def unblock_ip(self):
        data = request.get_json()
        ip_address = data.get('ip')
        if ip_address and ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
            self.logger.info("Unblocking IP: %s", ip_address)
            # Remove blocking flows on all datapaths
            for datapath in self.datapaths.values():
                self.unblock_ip_flows(datapath, ip_address)
            return jsonify({'status': 'success', 'ip': ip_address}), 200
        return jsonify({'status': 'error', 'message': 'IP address not found or not blocked'}), 400

    def list_blocked_macs(self):
        return jsonify({'blocked_macs': list(self.blocked_macs)}), 200

    def list_blocked_ips(self):
        return jsonify({'blocked_ips': list(self.blocked_ips)}), 200

    def get_flow_tables(self):
        self.flow_stats = {}  # Clear previous stats
        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser
            req = parser.OFPFlowStatsRequest(datapath)
            datapath.send_msg(req)
        
        time.sleep(1)  # Wait for responses, adjust if necessary

        return jsonify(self.flow_stats), 200

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        self.flow_stats.setdefault(dpid, [])
        for stat in ev.msg.body:
            flow = {
                'priority': stat.priority,
                'match': stat.match.to_jsondict(),
                'actions': [action.to_jsondict() for action in stat.instructions],
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count
            }
            self.flow_stats[dpid].append(flow)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_feature_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        self.logger.info("Switch connected: %016x", datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('Register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == CONFIG_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('Unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
                
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # Learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # Check if the source or destination MAC is blocked
        if src in self.blocked_macs or dst in self.blocked_macs:
            self.logger.info("Blocked MAC address, dropping packet")
            return

        # Check if the packet is IPv4 and if the source or destination IP is blocked
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt and (ip_pkt.src in self.blocked_ips or ip_pkt.dst in self.blocked_ips):
            self.logger.info("Blocked IP address, dropping packet")
            return

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=0,
                hard_timeout=0
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=0,
                hard_timeout=0
            )
        datapath.send_msg(mod)
        self.logger.info("Added flow: priority=%d, match=%s, actions=%s", priority, match, actions)

    def block_flows(self, datapath, mac):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Block all packets from the blocked MAC address
        match = parser.OFPMatch(eth_src=mac)
        actions = []
        self.add_flow(datapath, 100, match, actions)
        
        # Block all packets to the blocked MAC address
        match = parser.OFPMatch(eth_dst=mac)
        actions = []
        self.add_flow(datapath, 100, match, actions)

    def unblock_flows(self, datapath, mac):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Remove all flows from and to the MAC address
        match = parser.OFPMatch(eth_src=mac)
        mod = parser.OFPFlowMod(
            datapath=datapath, 
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )
        datapath.send_msg(mod)
        
        match = parser.OFPMatch(eth_dst=mac)
        mod = parser.OFPFlowMod(
            datapath=datapath, 
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )
        datapath.send_msg(mod)

    def block_ip_flows(self, datapath, ip):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Block all packets from the blocked IP address
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip)
        actions = []
        self.add_flow(datapath, 100, match, actions)
        
        # Block all packets to the blocked IP address
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip)
        actions = []
        self.add_flow(datapath, 100, match, actions)

    def unblock_ip_flows(self, datapath, ip):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Remove all flows from and to the IP address
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip)
        mod = parser.OFPFlowMod(
            datapath=datapath, 
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )
        datapath.send_msg(mod)
        
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip)
        mod = parser.OFPFlowMod(
            datapath=datapath, 
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )
        datapath.send_msg(mod)

    def block_csv(self):
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No file part'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'status': 'error', 'message': 'No selected file'}), 400

        if file and file.filename.endswith('.csv'):
            csv_content = file.read().decode('utf-8')
            self.process_csv_content(csv_content)
            return jsonify({'status': 'success'}), 200

        return jsonify({'status': 'error', 'message': 'Invalid file type'}), 400

    def process_csv_content(self, csv_content):
        csv_file = StringIO(csv_content)
        reader = csv.DictReader(csv_file)

        for row in reader:
            src_ip = row.get('Src IP')
            dst_ip = row.get('Dst IP')
            src_port = row.get('Src Port')
            dst_port = row.get('Dst Port')
            protocol = row.get('Protocol')
            label = row.get('Label')

            # Block communication
            for datapath in self.datapaths.values():
                self.block_communication(datapath, src_ip, dst_ip, src_port, dst_port, protocol)

    def block_communication(self, datapath, src_ip, dst_ip, src_port, dst_port, protocol):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = []

        # Build the match object
        match_fields = {}

        if protocol == '0':
            # When protocol is 0, match only on source and destination IP
            if src_ip:
                match_fields['ipv4_src'] = src_ip
            if dst_ip:
                match_fields['ipv4_dst'] = dst_ip
        else:
            # For other protocols, include protocol-specific fields
            if src_ip:
                match_fields['ipv4_src'] = src_ip
            if dst_ip:
                match_fields['ipv4_dst'] = dst_ip
            if protocol:
                ip_proto = int(protocol)
                match_fields['ip_proto'] = ip_proto

                if ip_proto == 6:  # TCP
                    if src_port:
                        match_fields['tcp_src'] = int(src_port)
                    if dst_port:
                        match_fields['tcp_dst'] = int(dst_port)
                elif ip_proto == 17:  # UDP
                    if src_port:
                        match_fields['udp_src'] = int(src_port)
                    if dst_port:
                        match_fields['udp_dst'] = int(dst_port)
                elif ip_proto == 1:  # ICMP
                    if src_port:  # ICMP type
                        match_fields['icmp_type'] = int(src_port)
                    if dst_port:  # ICMP code
                        match_fields['icmp_code'] = int(dst_port)

        # Ensure eth_type is set for IPv4
        match = parser.OFPMatch(**match_fields, eth_type=ether_types.ETH_TYPE_IP)

        self.add_flow(datapath, 100, match, actions)
