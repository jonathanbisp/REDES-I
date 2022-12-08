#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call


def myNetwork():

    net = Mininet(topo=None, build=False, ipBase="10.0.0.0/8", autoSetMacs=False)

    info("*** Adding controller\n")

    info("*** Add switches\n")

    s1 = net.addSwitch("s1", cls=OVSKernelSwitch)

    s2 = net.addSwitch("s2", cls=OVSKernelSwitch)

    s3 = net.addSwitch("s3", cls=OVSKernelSwitch)

    s4 = net.addSwitch("s4", cls=OVSKernelSwitch)

    s5 = net.addSwitch("s5", cls=OVSKernelSwitch)

    s6 = net.addSwitch("s6", cls=OVSKernelSwitch)

    info("*** Add hosts\n")

    vendas1 = net.addHost(
        "vendas1",
        cls=Host,
        ip="10.100.80.1/8",
        mac="00:00:00:00:00:71",
        defaultRoute=None,
    )

    visitante1 = net.addHost(
        "visitante1",
        cls=Host,
        ip="10.100.254.1/8",
        mac="00:00:00:00:00:01",
        defaultRoute=None,
    )

    visitante2 = net.addHost(
        "visitante2",
        cls=Host,
        ip="10.100.254.2/8",
        mac="00:00:00:00:00:02",
        defaultRoute=None,
    )

    recepcao1 = net.addHost(
        "recepcao1",
        cls=Host,
        ip="10.100.90.1/8",
        mac="00:00:00:00:00:11",
        defaultRoute=None,
    )

    rh1 = net.addHost(
        "rh1", cls=Host, ip="10.100.70.1/8", mac="00:00:00:00:00:21", defaultRoute=None
    )

    diretoria1 = net.addHost(
        "diretoria1",
        cls=Host,
        ip="10.100.60.1/8",
        mac="00:00:00:00:00:31",
        defaultRoute=None,
    )

    finan1 = net.addHost(
        "finan1",
        cls=Host,
        ip="10.100.50.1/8",
        mac="00:00:00:00:00:41",
        defaultRoute=None,
    )

    ti1 = net.addHost(
        "ti1", cls=Host, ip="10.100.2.1/8", mac="00:00:00:00:00:51", defaultRoute=None
    )

    internet1 = net.addHost(
        "internet1",
        cls=Host,
        ip="10.100.1.1/8",
        mac="00:00:00:00:00:61",
        defaultRoute=None,
    )

    info("*** Add links\n")

    net.addLink(s2, vendas1)

    net.addLink(s3, visitante1)

    net.addLink(s3, visitante2)

    net.addLink(s3, recepcao1)

    net.addLink(s5, rh1)

    net.addLink(s5, diretoria1)

    net.addLink(s5, finan1)

    net.addLink(s6, ti1)

    net.addLink(s6, internet1)

    net.addLink(s1, s2)

    net.addLink(s2, s3)

    net.addLink(s1, s4)

    net.addLink(s4, s5)

    net.addLink(s4, s6)

    info("*** Starting network\n")

    net.build()

    info("*** Starting controllers\n")

    for controller in net.controllers:
        controller.start()

    info("*** Starting switches\n")

    net.get("s1").start([])

    net.get("s2").start([])

    net.get("s3").start([])

    net.get("s4").start([])

    net.get("s5").start([])

    net.get("s6").start([])

    info("*** Post configure switches and hosts\n")

    CLI(net)

    net.stop()


if __name__ == "__main__":

    setLogLevel("info")

    myNetwork()
