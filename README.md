# BotDAD
Anomaly detection based on DNS traffic analysis

---------------------------------
I - Installation Instruction
---------------------------------

1. Install Python 2.7.9
2. Install Pycharm Community Edition (Optional)
3. Install Following Packages

      a) python -m pip install ipaddr
  
      b) python -m pip install dpkt
  
      c) python -m pip install geoip2
  
      d) python -m pip install matplotlib
      
      (Note: in case of error, upgrade pip to latest version using this command : python -m pip install -U pip)
      
      e)  python -m pip install win_inet_pton
 
---------------------------------
II- Dataset Preparation
---------------------------------
 
 1. Filter all DNS traffic from Pcap file as tool analyses DNS packets only using command below :
 
    c:\Progra~1\Wireshark\tshark.exe  -r "input.pcap" -F pcap -Y dns -t ad -w "big.pcap"
 
 2. Convert a bigger pcapfile to 1 hour duration using the command below as fingerprint are calculated for one hour:
 
     c:\Progra~1\Wireshark\editcap.exe -F pcap -i 3600 "big.pcap"  "slice.pcap"
 
          OR
 
 Download the sample file (20160421_150521.pcap) from link below:
 
 https://drive.google.com/file/d/14cRY6aEQz_xVsfySBb4Ik6mPYDLoIc88/view?usp=sharing
 
 
 ---------------------------------
 Running BotDAD
 ---------------------------------
 
 1. Download and extract the zip from the github repository to BotDAD Folder
 
 2.  <<botDAD_Path>>:>    C:\python27\Python.exe main.py
 
 3. Following files will be generated at the successful completion of the script
 
    a) In the same folder as the pcap file
      DNS Requests    : 20160421_150521.pcap_req.csv
      DNS Response    : 20160421_150521.pcap_res.csv
      PCap Parser Log : 20160421_150521.pcap_log.csv
      
     b) In the BotDAD folder
       
 
 
