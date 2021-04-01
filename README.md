# SharkHunter: python pyshark pcap parser

This project takes in a pcap file and outputs information regarding malicious behavior.
Detectable behavior include FTP, SSH, LDAP, and SMB brute forcing, NMAP scanning, directory traversal, and SQL injections.

The program also outputs graphs detailing the density with respect to time of SYN requests, LDAP, SMB, and outgoing data. 
The graphs for Data, LDAP, and SMB Density take in user input for an IP address in order to display outbound connection rates.
