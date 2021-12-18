# Creating the VM

Start creating a brand new VM by running `vagrant up` in this
directory (install vagrant on your system if needed).  It can take one
to several hours, depending upon the speed of your computer and
Internet connection.

Steps taken to prepare a VM _after_ running `vagrant up` on the host
OS.  Some of these could probably be automated with programs, and
changes to the `vagrant up` scripts that can do so are welcome.  I did
them manually to create a VM image simply to avoid the experimentation
and time required to automate them, since I do not expect to create a
new VM very often (a couple of times per year?).

+ Log in as user p4 (password p4)
+ Click "Upgrade" in the pop-up window asking if you want to upgrade
  the system, if asked.  This will download the latest Linux kernel
  version released for Ubuntu 20.04, and other updated packages.
+ Reboot the system.
+ This is optional, but if you want to save a little disk space, use
  `sudo apt purge <list of packages>` to remove older version of Linux
  kernel, if the upgrade installed a newer one.
+ `sudo apt clean`

+ Log in as user p4 (password p4)
+ Start menu -> Preferences -> LXQt settings -> Monitor settings
  + Change resolution from initial 800x600 to 1024x768.  Apply the changes.
  + Close monitor settings window
  + Note: For some reason I do not know, these settings seem to be
    undone, even if I use the "Save" button.  They are temporarily in
    effect if I shut down the system and log back in, but then in a few
    seconds it switches back to 800x600.  Strange.
+ Start menu -> Preferences -> LXQt settings -> Desktop
  + In "Wallpaper mode" popup menu, choose "Center on the screen".
  + Click Apply button
  + Close "Desktop preferences" window
+ Several of the icons on the desktop have an exclamation mark on
  them.  If you try double-clicking those icons, it pops up a window
  saying "This file 'Wireshark' seems to be a desktop entry.  What do
  you want to do with it?" with buttons for "Open", "Execute", and
  "Cancel".  Clicking "Open" causes the file to be opened using the
  Atom editor.  Clicking "Execute" executes the associated command.
  If you do a mouse middle click on one of these desktop icons, a
  popup menu appears where the second-to-bottom choice is "Trust this
  executable".  Selecting that causes the exclamation mark to go away,
  and future double-clicks of the icon execute the program without
  first popping up a window to choose between Open/Execute/Cancel.  I
  did that for each of these desktop icons:
  + Terminal
  + Wireshark
+ Log off

+ Log in as user vagrant (password vagrant)
+ Change monitor settings and wallpaper mode as described above for
  user p4.
+ Open a terminal.
  + Run the command `./clean.sh`, which removes about 6 to 7 GBytes of
    files created while building the projects.
+ Log off


# Notes on test results for the VM

## p4c testing results

Steps to run the p4c tests:

+ Log in as user vagrant (password vagrant)
+ In a new terminal, execute these commands:

```bash
# Compile p4c again from source, since the clean.sh step reduced disk
# space by deleting the p4c/build directory.
git clone https://github.com/jafingerhut/p4-guide
cd p4c
~/p4-guide/bin/build-p4c.sh

# Run the p4c tests
cd build
make -j2 check |& tee make-check-out.txt
```

As of 2021-09-07, the p4c compiler passes all but 61 of its included
tests.

The test named cpplint fails because Python2 is not installed on the
system.  Omitting Python2 is intentional for this VM.  The cpplint
test passes fine on other systems that have Python2 installed.

There are 60 tests whose names begin with 'ebpf' and 'ubpf' that fail.
They work fine in the continuous integration tests on the
https://github.com/p4lang/p4c project, because the VM used to run
those tests has additional software installed to enable it.  Perhaps
future versions of this VM will enable the ebpf and ubpf back ends to
pass these tests, also.  Contributions are welcome to the needed
changes in the VM build scripts to enable this.


## Send ping packets in the solution to `basic` exercise of `p4lang/tutorials` repository

With the branch of the p4lang/tutorials repository included with this
VM, the following tests pass.  More testing and/or bug fixes is
welcome here.

First log in as the user `p4` (password `p4`) and open a terminal
window.
```bash
$ cd tutorials/exercises/basic
$ cp solution/basic.p4 basic.p4
$ make run
```

If at the end of many lines of logging output you see a prompt
`mininet>`, you can try entering the command `h1 ping h2` to ping from
virtual host `h1` in the exercise to `h2`, and it should report a
successful ping every second.  It will not stop on its own.  You can
type Control-C to stop it and return to the `mininet>` prompt, and you
can type Control-D to exit from mininet and get back to the original
shell prompt.  To ensure that any processes started by the above steps
are terminated, you can run this command:
```bash
$ make stop
```


# Creating a single file image of the VM

For the particular case of creating the VM named 'P4 Tutorial
2021-09-07' on September 7, 2021, here were the host OS details, in
case it turns out that matters to the finished VM image for some
reason:

+ macOS 10.14.6
+ VirtualBox 6.1.26 r145957
+ Vagrant 2.2.16

In the VirtualBox GUI interface:

+ Choose menu item File -> Export Appliance ...
+ Select the VM named 'P4 Tutorial 2021-09-07' and click Continue button

+ Format
  + I used: Open Virtualization Format 1.0
  + Other available options were:
    + Open Virtualization Format 0.9
    + Open Virtualization Format 2.0
+ Target file
  + I used: /Users/andy/Documents/P4 Tutorial 2021-09-07.ova
+ Mac Address Policy
  + I used: Include only NAT network adapter MAC addresses
  + Other available options were:
    + Include all network adapter MAC addresses
    + Strip all network adapter MAC addresses
+ Additionally
  + Write Manifest file: checked
  + Include ISO image files: unchecked

Clicked "Continue" button.

Virtual system settings:

+ Name: P4 Tutorial 2021-09-07
+ Product: I left this blank
+ Product-URL: I left this blank
+ Vendor: P4.org - P4 Language Consortium
+ Vendor-URL: https://p4.org
+ Version: 2021-09-07
+ Description:

```
Open source P4 development tools built from latest source code as of 2021-Sep-07 and packaged into an Ubuntu 20.04 Desktop Linux VM for the AMD64 architecture.
```

+ License

```
Open source code available hosted at https://github.com/p4lang is released under the Apache 2.0 license.  Libraries it depends upon, such as Protobuf, Thrift, gRPC, Ubuntu Linux, etc. are released under their own licenses.
```

Clicked "Export" button.
