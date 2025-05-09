# icmp-TS
ICMP Timestamp Disclosure Tester

-----

Send an ICMP type 13 request to a target, CIDR range or input list of targets and evaluate the type 14 response if returned.
It is also possible that the destination specified in the response may disclose an RFC1918 (internal, private) IP address.

-----

pip install -r requirements.txt
