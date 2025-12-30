# Part 2 of UWCSE's Mininet-SDN project2
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet

log = core.getLogger()

# Convenience mappings of hostnames to ips
IPS = {
    "h10": "10.0.1.10",
    "h20": "10.0.2.20",
    "h30": "10.0.3.30",
    "serv1": "10.0.4.10",
    "hnotrust": "172.16.10.100",
}

# Convenience mappings of hostnames to subnets
SUBNETS = {
    "h10": "10.0.1.0/24",
    "h20": "10.0.2.0/24",
    "h30": "10.0.3.0/24",
    "serv1": "10.0.4.0/24",
    "hnotrust": "172.16.10.0/24",
}

# Router configuration
ROUTER_MAC = EthAddr("00:00:00:00:00:01")

# Gateway IPs for each subnet (interface on the core switch)
GATEWAYS = {
    IPAddr("10.0.1.1"): 1,
    IPAddr("10.0.2.1"): 2,
    IPAddr("10.0.3.1"): 3,
    IPAddr("10.0.4.1"): 4,
    IPAddr("172.16.10.1"): 5
}

class Part4Controller(object):
    """
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        print(connection.dpid)
        self.connection = connection

        # ARP Table: IPAddr -> (EthAddr, Port)
        self.arp_table = {}

        connection.addListeners(self)

        if connection.dpid == 1:
            self.s1_setup()
        elif connection.dpid == 2:
            self.s2_setup()
        elif connection.dpid == 3:
            self.s3_setup()
        elif connection.dpid == 21:
            self.cores21_setup()
        elif connection.dpid == 31:
            self.dcs31_setup()
        else:
            print("UNKNOWN SWITCH")

    def _flood_all(self):
        """Helper to flood on L2 switches"""
        msg = of.ofp_flow_mod()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    def s1_setup(self):
        self._flood_all()

    def s2_setup(self):
        self._flood_all()

    def s3_setup(self):
        self._flood_all()

    def dcs31_setup(self):
        self._flood_all()

    def cores21_setup(self):
        # --- 1. Security Rules (High Priority: 20) ---
        
        # Rule 1: Drop ICMP from hnotrust
        msg = of.ofp_flow_mod()
        msg.priority = 20
        msg.match.dl_type = 0x0800 # IPv4
        msg.match.nw_proto = 1     # ICMP
        msg.match.nw_src = IPS["hnotrust"]
        self.connection.send(msg) # No action = Drop

        # Rule 2: Drop IP traffic from hnotrust to serv1
        msg = of.ofp_flow_mod()
        msg.priority = 20
        msg.match.dl_type = 0x0800 # IPv4
        msg.match.nw_src = IPS["hnotrust"]
        msg.match.nw_dst = IPS["serv1"]
        self.connection.send(msg) # No action = Drop

        # --- 2. Controller Traps (Normal Priority: 10) ---
        # Send ARP and IP packets to controller for routing logic
        
        # Trap ARP
        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.match.dl_type = 0x0806 # ARP
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        self.connection.send(msg)

        # Trap IPv4
        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.match.dl_type = 0x0800 # IPv4
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        self.connection.send(msg)

    def send_arp_request(self, ip_needed, out_port, source_ip):
        """
        Helper to send an ARP Request from the Router to a specific IP
        """
        r = arp()
        r.opcode = arp.REQUEST
        r.hwdst = EthAddr("ff:ff:ff:ff:ff:ff")
        r.protodst = ip_needed
        r.hwsrc = ROUTER_MAC
        r.protosrc = source_ip
        
        e = ethernet(type=ethernet.ARP_TYPE, src=ROUTER_MAC, dst=r.hwdst)
        e.payload = r
        
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def _handle_PacketIn(self, event):
        """
        Handle packets sent to the controller
        """
        packet = event.parsed
        if not packet:
            log.warning("Ignoring incomplete packet")
            return
        
        # Only handle cores21 logic here
        if self.connection.dpid != 21:
            return

        packet_in = event.ofp
        
        # --- 1. Dynamic Learning ---
        # Learn the source: IP -> (MAC, Port)
        src_ip = None
        if packet.type == ethernet.IP_TYPE:
            src_ip = packet.payload.srcip
        elif packet.type == ethernet.ARP_TYPE:
            src_ip = packet.payload.protosrc
        
        if src_ip is not None:
            # Update ARP Table
            self.arp_table[src_ip] = (packet.src, event.port)

        # --- 2. Handle ARP Requests for Gateway ---
        if packet.type == ethernet.ARP_TYPE:
            arp_payload = packet.payload
            # If this is an ARP request looking for one of my Gateway IPs
            if arp_payload.opcode == arp.REQUEST and arp_payload.protodst in GATEWAYS:
                # Construct ARP Reply
                reply = arp()
                reply.opcode = arp.REPLY
                reply.hwdst = arp_payload.hwsrc
                reply.protodst = arp_payload.protosrc
                reply.hwsrc = ROUTER_MAC
                reply.protosrc = arp_payload.protodst # The Gateway IP
                
                ether = ethernet()
                ether.type = ethernet.ARP_TYPE
                ether.dst = arp_payload.hwsrc
                ether.src = ROUTER_MAC
                ether.payload = reply
                
                # Send reply back out the port it came from
                msg = of.ofp_packet_out()
                msg.data = ether.pack()
                msg.actions.append(of.ofp_action_output(port=event.port))
                self.connection.send(msg)
                return

        # --- 3. Handle IP Routing ---
        if packet.type == ethernet.IP_TYPE:
            dst_ip = packet.payload.dstip
            
            # Check if we know the destination
            if dst_ip in self.arp_table:
                dst_mac, dst_port = self.arp_table[dst_ip]
                
                # A. Install Flow Rule for future packets
                msg = of.ofp_flow_mod()
                msg.priority = 15 
                msg.match.dl_type = 0x0800
                msg.match.nw_dst = dst_ip
                
                # Set Src MAC to Router MAC, Dst MAC to Next Hop
                msg.actions.append(of.ofp_action_dl_addr.set_src(ROUTER_MAC))
                msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
                msg.actions.append(of.ofp_action_output(port=dst_port))
                self.connection.send(msg)
                
                # B. Forward the current packet immediately
                packet.src = ROUTER_MAC
                packet.dst = dst_mac
                
                msg_out = of.ofp_packet_out()
                msg_out.data = packet.pack()
                msg_out.actions.append(of.ofp_action_output(port=dst_port))
                self.connection.send(msg_out)
            else:
                # Destination unknown. 
                # Send ARP Request to learn the destination.
                
                # Find which subnet/port this IP belongs to
                out_port = None
                gw_ip = None
                
                # Simple check assuming /24 subnets as per assignment
                for gateway_ip, port in GATEWAYS.items():
                    # FIX: Avoid "Host part not zero" error by not using string CIDR
                    # Check if dst_ip is in the same /24 subnet as the gateway_ip
                    # We compare the first 3 octets (masked with 0xFFFFFF00)
                    if (dst_ip.toUnsigned() & 0xFFFFFF00) == (gateway_ip.toUnsigned() & 0xFFFFFF00):
                         out_port = port
                         gw_ip = gateway_ip
                         break
                
                if out_port is not None:
                    # Send ARP Request from Router
                    self.send_arp_request(dst_ip, out_port, gw_ip)
                
                # Packet dropped, waiting for ARP resolution
                pass

def launch():
    """
    Starts the component
    """
    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Part4Controller(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)