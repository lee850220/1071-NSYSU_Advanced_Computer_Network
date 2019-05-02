from mininet.topo import Topo
from mininet.link import Link
from mininet.net import Mininet

class MyToPo(Topo):

    def __init__(self):

        # init
        Topo.__init__(self)

        # add hosts and switches
        host1 = self.addHost('h1', ip='10.0.0.1')
        host2 = self.addHost('h2', ip='10.0.5.1')

        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        switch3 = self.addSwitch('s3')
        switch4 = self.addSwitch('s4')
        switch5 = self.addSwitch('s5')

        # add links
        self.addLink(host1, switch1, 1, 1)
        self.addLink(switch1, switch2, 2, 1)
        self.addLink(switch2, switch3, 2, 1)
        self.addLink(switch3, switch4, 2, 1)
        self.addLink(switch4, switch5, 2, 2)
        self.addLink(switch5, host2, 1, 1)

        # set ip
        #setIP('10.0.0.100', intf='s1-eth1')
        #get('s1').setIP('10.0.0.101', intf='s1-eth2')
        #.setIP('10.0.0.100', intf='s2-eth1')
        #.setIP('10.0.0.101', intf='s2-eth2')

topos = {'mytopo_5': (lambda: MyToPo())}
