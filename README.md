# Implementing a Control Plane using P4Runtime

This is a simple SFC implemented on P4.

## Project Structure
- `reference`: The reference p4 programs and controllers.
  - `p4`: We reference several programs from [p4tutorial](https://github.com/p4lang/tutorials). 
  - `controllers`: This folder contains several experiemental controllers implemented before. They are not runnable, just for reference.
- `runtime`: It documents the setting of each switch. You can install it manually using the CLI provided. However, formally we use our controller to insert p4info and set rules.
- `sfc`: This folder contains our p4 application in hierarchy.
- `template`: They are templates for both internal switch and edge switches.
- `utils`: This also comes from [p4tutorial](https://github.com/p4lang/tutorials). It provides many useful library and scripts to manipulate p4runtime.
- `vm-ubuntu-20.04`: This is our experiment environment. Use `vagrant up` to setup the virtual machine, still comes from [p4tutorial](https://github.com/p4lang/tutorials).
- `controlles`: This is where we put our controllers in.

## Usage

1. Compile p4 programs and launch mininet.
```bash
make sfc
```
2. Install rules on p4 switches
```bash
./sfc_controller.py
```
3. Check connection
  - Method 1: using ping (ICMP)
```bash
mininet> h1 ping h2
```
  - Method 2: using TCP
```bash
# It will open terminal for host 1 and host 2
mininet> xterm h1 h2

# You can modify the iface to listen on different NIC
h2> ./tools/receive.py

h1> ./tools/send.py 10.0.2.2
```
4. Cleanup
```bash
# 1. Type Ctrl+d

# 2. Clean up the resources
make clean
```

