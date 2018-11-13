# BotDAD
Anomaly detection based on DNS traffic analysis


I    Install Instruction

1. Install Python 2.7.*
2. Install Pycharm Community Edition
3. Install Following Packages

  a) pip install ipaddr
  
  b) pip install dpkt
  
  c) pip install geoip2
  
  d) pip install matplotlib
 
 
II Dataset Preparation
 
 1. Filter all DNS traffic from Pcap file as tool analyses DNS packets only using command below :
 
    c:\Progra~1\Wireshark\tshark.exe  -r "input.pcap" -F pcap -Y dns -t ad -w "big.pcap"
 
 2. Convert a bigger pcapfile to 1 hour duration using the command below as fingerprint are calculated for one hour:
 
     c:\Progra~1\Wireshark\editcap.exe -F pcap -i 3600 "big.pcap"  "slice.pcap"
 
OR
 
 Download the sample file from link below:
 
 https://drive.google.com/file/d/14cRY6aEQz_xVsfySBb4Ik6mPYDLoIc88/view?usp=sharing
 
 
