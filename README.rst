Requirements
============

1. Test task should be created and tested on Ubuntu 12.04 connected to the network. Additionally to standard Python distribution (2.6+) you need to install the following modules:

  - ``netinfo`` (for getting information about network interfaces and routes in the system)
  - ``scapy`` (for network packets manipulation)

2. Result should be provided as .py source file.
3. You have to use a ``subprocess`` or threads for sending packets in parallel with sniffing. Create test class which tests described below functionality by comparing number of packets which were supposed to be sent and the number of packets which were actually captured (use standard ``unittest`` module).

Task
====

Part 1
------
Create functionality which sends ping requests to *8.8.8.8* host out of the default network interface in the system (usually something like *ethX*, where *X* is a number) and verifies that the requests have been sent by capturing outgoing packets.

Part 2
------
Do the same for *lo* and *ethX* interfaces simultaneously (use standard ``threading`` module). Captured results should be  collected into dictionary which has the following structure::

  {'iface1': list_of_captured_packets, 'iface2': list_of_captured_packets, ...}

Modification of this dictionary should be thread-safe. Modify the test class by adding a test which checks that resulting dictionary contains both - *lo* and *ethX* interfaces as keys.

Part 3
------
Do the same but for all active network interfaces in your system. These interfaces should be detected in your code. Modify test class to support all active network interfaces in your system.

Part 4
------
Check that you've got ping replies on (and only on) the interface connected to the default gateway. Modify the test class to verify newly added functionality.
