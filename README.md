# Implementing a Simple SFC using p4

This is a simple SFC implemented on P4.

## Project Structure
- `template`: They are templates for both internal switch and edge switches.
- `utils`: This also comes from [p4tutorial](https://github.com/p4lang/tutorials). It provides many useful library and scripts to manipulate p4runtime.
- `vm-ubuntu-20.04`: This is our experiment environment. Use `vagrant up` to setup the virtual machine, still comes from [p4tutorial](https://github.com/p4lang/tutorials).
- `controllers`: This is where we put our controllers in.

## Usage

1. Compile p4 programs and launch mininet.
```bash
make sfc
```
2. Install rules on p4 switches
```bash
./controller/install.py
```
3. Check connection
  - Method 1: using ping (ICMP)
```bash
mininet> h1 ping h2
mininet> h2 ping h1
```
  - Method 2: using TCP
```bash
# It will open terminal for host 1 and host 2
mininet> xterm h1 h2

# You can modify the iface to listen on different NIC
h2> ./receive.py eth0

# 10.0.2.2 is the destination ip address (see topo/topology.json)
h1> ./send.py 10.0.2.2
```
4. Cleanup
```bash
# 1. Type Ctrl+d

# 2. Clean up the resources
make clean
```

## Testing Connection
The simplest way to test connection between switches and hosts is to user our `send.py` and `receive.py`. 
1. First, you have to send up where to listen the packet. The benefits of listening on ports of switches are to see if a packet did be send to some port.
```bash
# 1. Testing connection between host
mininet> xterm h1 h2

# The only interface on host is eth0
h2> ./receive.py eth0

# 2. Test connection between host and switch
mininet> xterm h1 s4

# The interface of switch is [switch name]-[port number]
s4> ./receive.py s4-eth3
```
2. Second, just use `send.py` to send packet.
```
h1> ./send.py 10.0.2.2
```

