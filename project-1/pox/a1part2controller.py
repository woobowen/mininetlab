# Part 2 of UWCSE's Project 3
#
# based on Lab 4 from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()


class Firewall(object):
    """
    A Firewall object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # --- 修改开始: 添加流表规则 (Switch Rules) ---
        
        # 规则 1: 允许并泛洪 ARP 流量
        # dl_type = 0x0806 (ARP)
        msg_arp = of.ofp_flow_mod()
        msg_arp.match.dl_type = 0x0806 
        msg_arp.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        self.connection.send(msg_arp)

        # 规则 2: 允许并泛洪 ICMP 流量
        # dl_type = 0x0800 (IPv4), nw_proto = 1 (ICMP)
        # 注意: 需要设置较高的优先级，以免被下面的"丢弃所有IPv4"规则覆盖
        msg_icmp = of.ofp_flow_mod()
        msg_icmp.match.dl_type = 0x0800 
        msg_icmp.match.nw_proto = 1
        msg_icmp.priority = 20 # 优先级设为 20
        msg_icmp.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        self.connection.send(msg_icmp)

        # 规则 3: 丢弃其他所有 IPv4 流量
        # dl_type = 0x0800 (IPv4)
        # 动作列表为空 (No actions) 即表示丢弃 (Drop)
        msg_drop = of.ofp_flow_mod()
        msg_drop.match.dl_type = 0x0800
        msg_drop.priority = 10 # 优先级设为 10 (低于 ICMP)
        self.connection.send(msg_drop)

        # --- 修改结束 ---

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
        print("Unhandled packet :" + str(packet.dump()))


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Firewall(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)