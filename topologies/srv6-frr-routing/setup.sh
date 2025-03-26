#!/bin/bash

docker exec -it clab-srv6-host11 /bin/bash -c "ip addr add 192.168.11.10/24 dev eth1"
docker exec -it clab-srv6-host12 /bin/bash -c "ip addr add 192.168.12.10/24 dev eth1"
docker exec -it clab-srv6-host21 /bin/bash -c "ip addr add 192.168.21.10/24 dev eth1"
docker exec -it clab-srv6-host22 /bin/bash -c "ip addr add 192.168.22.10/24 dev eth1"

docker exec -i clab-srv6-frr3 /usr/bin/vtysh << EOF
configure terminal
router bgp 65000 vrf Client1
 address-family ipv4 unicast
  rt vpn export 65000:101
 exit-address-family
 address-family ipv6 unicast
  rt vpn export 65000:101
 exit-address-family
exit
router bgp 65000 vrf Client2
 address-family ipv4 unicast
  rt vpn export 65000:101
 exit-address-family
 address-family ipv6 unicast
  rt vpn export 65000:101
 exit-address-family
exit
q
clear bgp *
EOF

docker exec -i clab-srv6-frr3 /usr/bin/vtysh << EOF
configure terminal
router bgp 65000 vrf Client1
 address-family ipv4 unicast
  rt vpn export 65000:101
 exit-address-family
 address-family ipv6 unicast
  rt vpn export 65000:101
 exit-address-family
exit
router bgp 65000 vrf Client2
 address-family ipv4 unicast
  rt vpn export 65000:102
 exit-address-family
 address-family ipv6 unicast
  rt vpn export 65000:102
 exit-address-family
exit
q
clear bgp *
EOF

