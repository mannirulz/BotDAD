# BotDAD (Bot DNS Anomaly Detector)

Tool for Anomaly based Botnet detection using DNS traffic analysis 
(Tested on Windows 10 64 bit. Should work for Linux and other Windows versions)

---------------------------------
I - Installation Instruction 
---------------------------------

1. Install Python 2.7.9 (https://www.python.org/downloads/release/python-279/)
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
 
            OR
 
 Download sample file from Mendeley Dataset from link below:
 
 https://data.mendeley.com/datasets/zh3wnddzxy/1
 
 
 ---------------------------------
 Running BotDAD
 ---------------------------------
 
 1. Download and extract the zip from the github repository to BotDAD Folder
 
 2.  <<botDAD_Path>>:>    C:\python27\Python.exe main.py
     Kindly check the pathname in the main.py before proceeding 
 
     Following output should come after successful running
     
                  BotDAD Ver 0.2
                  ===============
                        Verbose : 1
                        Mode    : 3

                  =============== PCAP Processing Started at  2018-11-14 11:34:33.811000 ===========
                  Packets (#)		Time Taken
                          10 		0:00:00.002000
                         100 		0:00:00.003000
                    =============== PCAP Processing completed at 2018-11-14 11:36:36.260000 ==========

                  Total number of Packets Processed        : 1000000
                  Total number of DNS Query                : 440969
                  Total number of DNS Responses            : 559031
                  Total number of Unknown Response Records : 0
                  Total number of Failed Responses         : 50108
                  Total Time taken                         : 0:02:02.449000

                  Number of infected Hosts = 19

                  Number of Clean Hosts = 755

                  l - list 	 m - Save Map 	 p - plot 	d/D - Display/Save 	 h - saveHtml 	 x - saveCSV 	 F - Find Req                       URl	 f - Find Resolved IP	 q - quit
                  console>
        
 
 3. Type l for list of  hosts with maximum DNS queries
 
                   Hosts with over 100 distinct requests 
                  1.	172.31.157.166	4156
                  2.	172.31.250.252	667
                  3.	172.31.247.66	1492
                  4.	172.31.242.144	223
                  5.	172.31.157.212	285
 
 4. Type d to display DNS queries data
 
                   d
                  Enter Hostname :
                  172.31.251.155
                  ('172.31.251.155', 4292, 0, 2037, 0, 0, 0, 0, 0, 0, 0, 0)
                  Request:	34267	aqgmekpyyhxyrnly.eu	1	21/04/16 09:46:20
                  Request:	20800	fbkbpdqvtqrssyoxlcor.ru	1	21/04/16 09:48:02
                  Request:	55664	xqjggsdhhcp.sx	1	21/04/16 09:48:02
                  Request:	15193	wbdaojgucxaq.ms	1	21/04/16 09:49:15
                  Request:	2527	kvivhjwewvm.to	1	21/04/16 09:45:43
 
 5. Type p to plot DNS query timeline
 
                   p
                  Enter Hostname :
                  172.31.251.155
                  ('Hostname : ', '172.31.251.155')
                  (' Number of URLs :', 2037)
                  A plot of DNS query timeline will be displayed
                  
                  
 
6. Following files will be generated at the successful completion of the script
 
    a) In the same folder as the pcap file
    
                  DNS Requests    : 20160421_150521.pcap_req.csv

                  DNS Response    : 20160421_150521.pcap_res.csv

                  PCap Parser Log : 20160421_150521.pcap_log.csv
      
      
     b) In the Output folder
     
                 Hosts DNS fingerpeint : DNS_FP.csv

                 Anomaly detection     : DNS_FP_Anomaly.csv
     
       
 
 For BotDAD machine learning module please refer readme file from link below:
 
 https://github.com/mannirulz/BotDAD/blob/master/ML/Readme.MD
