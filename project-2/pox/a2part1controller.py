# Part 1 of UWCSE's Mininet-SDN project2
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

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

class Part3Controller(object):
    """
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        print(connection.dpid)
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)
        # use the dpid to figure out what switch is being created
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
            exit(1)

    def _flood_all(self):
        """
        Helper function to flood all traffic on a switch.
        Used for s1, s2, s3, and dcs31.
        """
        msg = of.ofp_flow_mod()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    def s1_setup(self):
        # s1 act as a normal switch (flood)
        self._flood_all()

    def s2_setup(self):
        # s2 act as a normal switch (flood)
        self._flood_all()

    def s3_setup(self):
        # s3 act as a normal switch (flood)
        self._flood_all()

    def dcs31_setup(self):
        # dcs31 act as a normal switch (flood)
        self._flood_all()

    def cores21_setup(self):
        # put core switch rules here
        
        # --- 安全规则 (Security Rules / ACLs) ---
        # 优先级必须高于转发规则 (Priority > 10)
        
        # Rule 1: 禁止 hnotrust 向任何内部主机发送 ICMP
        # Match: EtherType=IP, Protocol=ICMP, Src=hnotrust
        msg = of.ofp_flow_mod()
        msg.priority = 20
        msg.match.dl_type = 0x0800 # IPv4
        msg.match.nw_proto = 1     # ICMP
        msg.match.nw_src = IPS["hnotrust"]
        # Action: None (Drop)
        self.connection.send(msg)

        # Rule 2: 禁止 hnotrust 向 serv1 发送任何 IP 流量
        # Match: EtherType=IP, Src=hnotrust, Dst=serv1
        msg = of.ofp_flow_mod()
        msg.priority = 20
        msg.match.dl_type = 0x0800 # IPv4
        msg.match.nw_src = IPS["hnotrust"]
        msg.match.nw_dst = IPS["serv1"]
        # Action: None (Drop)
        self.connection.send(msg)


        # --- 转发规则 (Forwarding Rules) ---
        # 优先级设为 10
        # 假设 cores21 的端口连接如下 (标准 Mininet 拓扑顺序):
        # Port 1 -> s1 (Subnet 10.0.1.0/24)
        # Port 2 -> s2 (Subnet 10.0.2.0/24)
        # Port 3 -> s3 (Subnet 10.0.3.0/24)
        # Port 4 -> dcs31 (Subnet 10.0.4.0/24)
        # Port 5 -> hnotrust (Subnet 172.16.10.0/24)

        # To Subnet h10 (via s1)
        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = SUBNETS["h10"]
        msg.actions.append(of.ofp_action_output(port=1))
        self.connection.send(msg)

        # To Subnet h20 (via s2)
        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = SUBNETS["h20"]
        msg.actions.append(of.ofp_action_output(port=2))
        self.connection.send(msg)

        # To Subnet h30 (via s3)
        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = SUBNETS["h30"]
        msg.actions.append(of.ofp_action_output(port=3))
        self.connection.send(msg)

        # To Subnet serv1 (via dcs31)
        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = SUBNETS["serv1"]
        msg.actions.append(of.ofp_action_output(port=4))
        self.connection.send(msg)

        # To Subnet hnotrust
        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = SUBNETS["hnotrust"]
        msg.actions.append(of.ofp_action_output(port=5))
        self.connection.send(msg)


    # used in part 4 to handle individual ARP packets
    # not needed for part 3 (USE RULES!)
    # causes the switch to output packet_in on out_port
    def resend_packet(self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        self.connection.send(msg)

    def _handle_PacketIn(self, event):
        """
        Packets not handled by the router rules will be
        forwarded to this method to be handled by the controller
        """

        packet = event.parsed  # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.
        print(
            "Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump()
        )


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Part3Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)