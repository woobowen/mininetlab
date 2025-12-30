#!/usr/bin/python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.cli import CLI


class part1_topo(Topo):
    def build(self):
        # 修改说明: 根据作业 Part1 要求，添加1个交换机和4个主机，并连接成星型拓扑
        
        # 1. 添加交换机 s1
        s1 = self.addSwitch('s1')

        # 2. 添加主机 h1, h2, h3, h4
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        # 3. 添加链路：将所有主机连接到交换机 s1
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)


topos = {"part1": part1_topo}

if __name__ == "__main__":
    t = part1_topo()
    net = Mininet(topo=t)
    net.start()
    CLI(net)
    net.stop()