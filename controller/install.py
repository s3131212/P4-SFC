#!/usr/bin/env python3
from sfc.proxy import install_proxy
from sfc.firewall import install_firewall
from sfc.qos import install_qos


if __name__ == '__main__':        
    install_proxy('./build/sfc_proxy.p4.p4info.txt', './build/sfc_proxy.json')
    install_firewall('./build/sfc_firewall.p4.p4info.txt', './build/sfc_firewall.json')
    install_qos('./build/sfc_qos.p4.p4info.txt', './build/sfc_qos.json')
    
    
