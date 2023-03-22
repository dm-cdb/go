udpreplic simply forwards incoming udp packet to several destinations, changing the ip destination and/or port, but leaving original ip source.
The goal is to get rid of pmacct/nfacctd netflow collector, while keeping an internal flexibility to send netflow datagrams to whatever destination (currently Kentick collector).
Can be used for any udp service in need of simple replications (syslog etc.)

The config file is in json format with a deamon part and a service part. The service part is a list of destination IP/ports, and can be modified inline, while the process is running and without interruption or need of restart (provided the ip adresses and ports are in valid format).
By default the file should be located in current exec directory, or /etc/default.
