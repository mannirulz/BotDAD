# Copyright (C) 2016   Manmeet Singh, Maninder Singh, Sanmeet kour
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#
#
# Display Parser for DNS Query , DNS Response and DNS Failed Lookups
#

# !python2

import datetime
import socket
import sys
import ipaddr
import time
import dpkt
import thread
from threading import Thread


# try:
#    import mysql.connector
# except:
#    print("MySQl Not found")

import struct
import getopt
from whitelist import checkWhiteList
from DnsAnalyser import Network
from DnsAnalyser import map_analyse_data
syntax = "PcapParse.py -v -c 10000 -m < mode_val e.g. 0,1,2> -f  <filename>"

# print messages 0- OFF , 1  -ON
VERBOSE = 1

# 0- Parse & display only
# 1- parse,display,store,
# 2 - parse & store don't display,
# 3 - CSV Write
# MODE = 0

# count of unknown responses /Previous , Query, Response


# CSV Wrapper
# TODO : batch row insert instead of single row write using  some cache mechanism
class CSVWrapper:

    def __init__(self, filename):
        # if pipeline : 0  csv files are not created. pipeline 1 : csv files are created
        self.pipeline = 0
        self.my_req_cache_list = []
        self.my_res_cache_list = []
        self.h = Network(filename)

        if self.pipeline:
            return
        else:
            self.req_outfile = open(filename + "_req.csv", "wb")
            self.res_outfile = open(filename + "_res.csv", "wb")
            self.log_outfile = open(filename + "_log.csv", "wb")

    def write_request(self, tid, reqIP, reqURL, nbrDomainToken, querytype, urlLength,dns_server_ip, timestamp):
        if self.pipeline:
            self.h.process_record(str(tid), str(reqIP), str(reqURL), str(nbrDomainToken), str(querytype), str(urlLength), str(timestamp), str(dns_server_ip))
            return

        if len(self.my_req_cache_list) != 3:
            self.my_req_cache_list.append(str(tid) + "," + str(reqIP) + "," + str(reqURL).encode('ascii', 'ignore') + "," + str(nbrDomainToken) + "," + str(querytype) + "," +  str(urlLength) + "," + str(timestamp) + "," + dns_server_ip + "\n")
        else:
            self.req_outfile.writelines(self.my_req_cache_list)
            self.my_req_cache_list[0:3] = []
            self.my_req_cache_list.append(str(tid) + "," + str(reqIP) + "," + str(reqURL) + "," + str(nbrDomainToken) + "," + str(querytype) + "," +  str(urlLength) + "," + str(timestamp) + "," + dns_server_ip + "\n")

    def write_response(self, tid, reqIP, reqURL, reqType, rescode, ttl, resolvedIp, receivedtimestamp):
        if self.pipeline:
            self.h.process_response(str(tid), str(reqIP), str(reqURL), str(rescode), str(ttl), str(resolvedIp), str(receivedtimestamp))
            return
        if len(self.my_res_cache_list) != 3:
            self.my_res_cache_list.append(str(tid) + "," + str(reqIP) + "," + str(reqURL) + "," + str(reqType) + "," + str(rescode) + "," + str(ttl) + "," + str(resolvedIp) + "," + str(receivedtimestamp)+ "\n" )
        else:
            self.res_outfile.writelines(self.my_res_cache_list)
            self.my_res_cache_list[0:3] = []
            self.my_res_cache_list.append(str(tid) + "," + str(reqIP) + "," + str(reqURL) + "," + str(reqType) + "," + str(rescode) + "," + str(ttl) + "," + str(resolvedIp) + "," + str(receivedtimestamp) + "\n")

    def write_log(self, sno, key, val):
        if self.pipeline:
            return
        self.log_outfile.write(sno + "," + key + "," + val + "\n")

    def close(self):
        if self.pipeline:
            self.h.find_anomaly()
            return
        self.req_outfile.close()
        self.res_outfile.close()
        self.log_outfile.close()


# MySQL Wrapper
class MySqlWrapper:

    def __init__(self):
        try:
            self.cnx = mysql.connector.connect(user='root', password='mysql', host='127.0.0.1', database='bot')
        except:
            print("MySQL Failed")

    def select(self, sql):
        try:
            cursor = self.cnx.cursor()
            cursor.execute(sql)
            results = cursor.fetchall()
            if cursor.rowcount < 1:
                return 0, 0
            else :
                return 1, results
        except:
            return 0, 0

    def insert(self, sql):
        try:
            cursor = self.cnx.cursor()
            cursor.execute(sql)
            self.cnx.commit()
            if cursor.rowcount < 1:
                cursor.close()
                return 0
            else:
                cursor.close()
                return 1
        except:
            cursor.close()
            return -1

    def update(self, sql):
        try:
            cursor = self.cnx.cursor()
            cursor.execute(sql)
            self.cnx.commit()
            # print cursor.rowcount
            if cursor.rowcount < 1:
                cursor.close()
                return 0
            else:
                cursor.close()
                return 1
        except:
            cursor.close()
            return -1


# class PcapParser:
# Pcap parser Class
class PcapParser:

    # Constructor
    def __init__(self, _count, _mode, _filename, _verbose):
        self.count = _count
        self.filename = _filename
        self.mode = _mode
        self.verbose = _verbose
        self.dnsUnknownResponseCount = 0
        self.dnsQueryCount = 0
        self.dnsResponseCount = 0
        self.dnsFailedCount = 0
        self.dnsPktCount = 0
        self.csv_obj = CSVWrapper(_filename)
        self.progress_index = 0
        self.f = open(self.filename, 'rb')
        self.pcap = dpkt.pcap.Reader(self.f)
        self.c_name = ""
        # default count of packets to parse
        self.MAX_PKT_COUNT = 1000
        self.start = datetime.datetime.now()

    # Insert or update existing query with response code and other fields
    def update_response(self,  tid, reqIP, reqURL, reqType, rescode, ttl, resolvedIp, receivedtimestamp):
        try:
            if reqIP == "172.31.1.6" or reqIP == "172.31.3.121":
                return 0
            if self.mode == 3:
                if checkWhiteList(reqURL) != 1:
                    self.csv_obj.write_response(tid, reqIP, reqURL, reqType, rescode, ttl, resolvedIp, receivedtimestamp)
                return 0
        except:
            print (self.dnsPktCount + "Error: updateResponse ")
            return 0
            # disconnect from server

    # check DNS packet or not
    def check_dns_traffic(self):
        # make sure we are dealing with IP traffic
        try:
            self.eth = dpkt.ethernet.Ethernet(self.buf)
        except:
            return 0
        if self.eth.type != 2048:
            return 0

        # make sure we are dealing with UDP protocol
        try:
            self.ip = self.eth.data
        except:
            return 0
        if self.ip.p != 17:
            return 0

        # filter on UDP assigned ports for DNS
        try:
            self.udp = self.ip.data
        except:
            return 0
        if self.udp.sport != 53 and self.udp.dport != 53:
            return 0
        return 1

    # wrapper to parse Request
    def parse_request(self):
        self.dnsQueryCount += 1
        # Default Gateway and dns server skip query
        if socket.inet_ntoa(self.ip.src) == '172.31.1.6' or socket.inet_ntoa(self.ip.src) == '172.31.3.121':
            return
        for self.query in self.dns.qd:

            # If URL in white list skip the packet
            # if MODE != 3:
            if checkWhiteList(self.query.name) == 1:
                if self.verbose == 1 and self.mode < 2:
                    print ("White list Presence : " + self.query.name)
                continue
            elif self.query.type != 0:  # DNS_A
                try:
                    # pt= query.name.split('.')
                    # ip_add = struct.unpack("!L", self.ip.src)[0]
                    if self.mode == 3:
                        self.csv_obj.write_request(self.dns.id, socket.inet_ntoa(self.ip.src),
                                                   self.query.name, self.query.name.count('.') + 1,
                                                   self.query.type, len(self.query.name),socket.inet_ntoa(self.ip.dst),
                                                   str(datetime.datetime.utcfromtimestamp(self.ts).strftime(
                                                       "%d/%m/%y %H:%M:%S")))
                    elif self.mode == 9:
                        print(self.ts, str(datetime.datetime.fromtimestamp(self.ts).strftime("%H:%M:%S")))
                    elif self.mode < 2:
                        print (self.dnsPktCount, '\t', self.dns.id, '\tQuery\t\t', socket.inet_ntoa(self.ip.src),
                               '  \t  ',
                               self.query.name, '\t', self.query.type, '\t', len(self.query.name), '\t',
                               self.query.name.count('.') + 1, '\t',
                               str(datetime.datetime.utcfromtimestamp(self.ts).strftime("%H:%M:%S")))
                    elif self.mode == 0 or self.mode == 1:
                        if self.checkRequest(self.dns.id, socket.inet_ntoa(self.ip.src), self.query.name,
                                        self.query.type) == 0:
                            self.insertNewRequest(self.dns.id, socket.inet_ntoa(self.ip.src), self.query.name,
                                             self.query.name.count('.') + 1, self.query.type, len(self.query.name), str(
                                    datetime.datetime.utcfromtimestamp(self.ts).strftime("%d/%m/%y %H:%M:%S")))
                        else:
                            if VERBOSE:
                                print (str(self.dnsPktCount) + "\t" + "exist")
                except:
                    continue
            else:
                print (self.dnsPktCount, '\t', 'Unhandled Request')

    # wrapper to parse Answer, NS and Authoratative response records
    def parse_response(self):
        if self.answer.type == dpkt.dns.DNS_A:  # DNS_A
            try:
                ipadd = struct.unpack("!L", self.answer.rdata)[0]  # resolved self.ip
                dstIP = struct.unpack("!L", self.ip.dst)[0]  # Destination self.ip
                if self.mode < 2:
                    print (self.dnsPktCount, '\t', self.dns.id, '\tResponse\t', self.answer.name, '->',
                           socket.inet_ntoa(self.answer.rdata), '\t', self.answer.ttl, '\t', self.answer.type, '\t',
                           socket.inet_ntoa(self.ip.dst), '\t',
                           str(datetime.datetime.utcfromtimestamp(self.ts).strftime("%H:%M:%S")))
                if self.mode > 0:
                    if self.c_name == "":
                        self.update_response(self.dns.id, socket.inet_ntoa(self.ip.dst), self.answer.name,
                                             self.answer.type, self.dns.rcode, self.answer.ttl,
                                             socket.inet_ntoa(self.answer.rdata), str(
                                datetime.datetime.utcfromtimestamp(self.ts).strftime("%d/%m/%y %H:%M:%S")))
                    else:
                        self.update_response(self.dns.id, socket.inet_ntoa(self.ip.dst), self.c_name, self.answer.type,
                                             self.dns.rcode, self.answer.ttl, socket.inet_ntoa(self.answer.rdata), str(
                                datetime.datetime.utcfromtimestamp(self.ts).strftime("%d/%m/%y %H:%M:%S")))
            except:
                if self.mode < 3:
                    print(self.dnsPktCount, '\t', "Unhandled Record Response type : " + str(self.answer.type))
        elif self.answer.type == dpkt.dns.DNS_CNAME:  # DNS_CNAME
            try:
                c_name = self.answer.name
                if self.mode < 2:
                    print (self.dnsPktCount, '\t', self.dns.id, '\tResponse\t', self.answer.name, '->',
                           self.answer.cname, '\t',
                           self.answer.ttl, '\t', self.answer.type, '\t',
                           socket.inet_ntoa(self.ip.dst), '\t',
                           str(datetime.datetime.utcfromtimestamp(self.ts).strftime("%H:%M:%S"))
                           )
            except:
                print (self.dnsPktCount, '\t', "Failed")
        elif self.answer.type == dpkt.dns.DNS_MX:  # DNS_MX
            try:
                ipadd = struct.unpack("!L", self.answer.rdata)[0]  # resolved self.ip
                dstIP = struct.unpack("!L", self.ip.dst)[0]  # Destination self.ip
                if self.mode < 2:
                    print (self.dnsPktCount, '\t', self.dns.id, '\tResponse\t', self.answer.name, '->',
                           socket.inet_ntoa(self.answer.rdata), '\t', self.answer.ttl, '\t', self.answer.type, '\t',
                           socket.inet_ntoa(self.ip.dst), '\t',
                           str(datetime.datetime.utcfromtimestamp(self.ts).strftime("%H:%M:%S")))
                if self.mode > 0:
                    if self.c_name == "":
                        self.updateResponse(self.csv_obj, self.dns.id, socket.inet_ntoa(self.ip.dst), self.answer.name,
                                       self.answer.type,
                                       self.dns.rcode, self.answer.ttl, socket.inet_ntoa(self.answer.rdata), str(
                                datetime.datetime.utcfromtimestamp(self.ts).strftime("%d/%m/%y %H:%M:%S")))
                    else:
                        self.updateResponse(self.csv_obj, self.dns.id, socket.inet_ntoa(self.ip.dst), self.cname,
                                       self.answer.type,
                                       self.dns.rcode, self.answer.ttl, socket.inet_ntoa(self.answer.rdata), str(
                                datetime.datetime.utcfromtimestamp(self.ts).strftime("%d/%m/%y %H:%M:%S")))

            except:
                if self.mode < 3:
                    print(self.dnsPktCount, '\t', "Unhandled Record Response type : " + str(self.answer.type))
        elif self.answer.type == dpkt.dns.DNS_NS:  # DNS_NS
            try:
                # ipadd = struct.unpack("!L", self.answer.rdata)[0]  # resolved self.ip
                dstIP = struct.unpack("!L", self.ip.dst)[0]  # Destination self.ip
                if self.mode < 2:
                    print (self.dnsPktCount, '\t', self.dns.id, '\tResponse\t', self.answer.name, '->',
                           self.answer.nsname, '\t', self.answer.ttl, '\t', self.answer.type, '\t',
                           socket.inet_ntoa(self.ip.dst), '\t',
                           str(datetime.datetime.utcfromtimestamp(self.ts).strftime("%H:%M:%S")))
                if self.mode > 0:
                    if self.c_name == "":
                        if self.answer.rlen == 4:
                            self.update_response(self.dns.id, socket.inet_ntoa(self.ip.dst), self.answer.name,
                                             self.answer.type,
                                             self.dns.rcode, self.answer.ttl, socket.inet_ntoa(self.answer.rdata), str(
                                datetime.datetime.utcfromtimestamp(self.ts).strftime("%d/%m/%y %H:%M:%S")))
                    else:
                        # Ignore NS Records for TLD as they are not returning any IP and causing Exception in inet_itoa
                        if self.answer.rlen == 4:
                            self.update_response(self.dns.id, socket.inet_ntoa(self.ip.dst), self.c_name, self.answer.type,
                                             self.dns.rcode, self.answer.ttl, socket.inet_ntoa(self.answer.rdata), str(
                                datetime.datetime.utcfromtimestamp(self.ts).strftime("%d/%m/%y %H:%M:%S")))

            except:
                if self.mode < 3:
                    print(self.dnsPktCount, '\t', "Unhandled Record Response type : " + str(self.answer.type))
        elif self.answer.type == dpkt.dns.DNS_AAAA:  # DNS_AAAA
            try:
                # dstIP = struct.unpack("!L", self.ip.dst)[0]   # Destination self.ip

                if self.mode < 2:
                    print(self.dnsPktCount, '\t', self.dns.id, '\tResponse\t', self.answer.name, '->',
                          str(ipaddr.IPv6Address(ipaddr.Bytes(self.answer.rdata))), '\t', self.answer.ttl, '\t',
                          self.answer.type, '\t',
                          socket.inet_ntoa(self.ip.dst), '\t',
                          str(datetime.datetime.utcfromtimestamp(self.ts).strftime(" %H:%M:%S")))

            except:
                print (self.dnsPktCount, '\t', self.dns.id, '\tResponse\t', "Failed Parsing DNS_AAAA ")
        # DNSSEC Unhandled , txt records ,SRV records,PTR
        elif self.answer.type == 12 or self.answer.type == 43 or self.answer.type == 46 or self.answer.type == 48 or \
                        self.answer.type == 16 or self.answer.type == 33 or self.answer.type == 6 or self.answer.type == 13:
            if self.mode < 2:
                print(self.dnsPktCount, '\t', self.dns.id, '\tResponse\t DNS SEC :Unhandled type  ', self.answer.type)

        else:
            if self.mode < 3:
                print(self.dnsPktCount, '\t', "Unhandled Record Response type : " + str(self.answer.type))

    # Begining of Pcap parsing
    def start_parse(self):

        print ("Verbose : " + str(self.verbose))
        print ("Mode : " + str(self.mode))

        self.csv_obj.write_log("1", "Processing Started at", str(self.start))
        print ("\n=============== Processing Started at  " + str(self.start) + " =============\n")

        self.progress_index = 10  # progress index =1,10,100,1000

        for self.ts, self.buf in self.pcap:
            if self.count <= self.dnsPktCount:
                break
            elif self.dnsPktCount == self.progress_index:
                print '%10d' %self.dnsPktCount, "\t\t" + str(datetime.datetime.now() - self.start)
                self.progress_index *= 10

            if 0 == self.check_dns_traffic():
                continue

            # make the dns object out of the udp data and
            # check for it being a RR (answer) and for opcode QUERY
            try:
                self.dns = dpkt.dns.DNS(self.udp.data)
            except:
                continue

            # parse the dns Request & responses
            self.dnsPktCount += 1

            if self.dns.qr == dpkt.dns.DNS_Q:
                self.parse_request()

            if self.dns.qr != dpkt.dns.DNS_R:
                # print (self.dns.qr)
                continue
            if self.dns.opcode != dpkt.dns.DNS_QUERY:
                print (self.dns.opcode)
                continue

            # Error in Response Code
            if self.dns.rcode != dpkt.dns.DNS_RCODE_NOERR:
                self.dnsResponseCount += 1
                if self.dns.rcode == dpkt.dns.DNS_RCODE_NXDOMAIN or self.dns.rcode == dpkt.dns.DNS_RCODE_REFUSED or \
                                self.dns.rcode == dpkt.dns.DNS_RCODE_SERVFAIL:
                    self.dnsFailedCount += 1
                    for answer in self.dns.qd:
                        try:
                            dstIP = struct.unpack("!L", self.ip.dst)[0]  # Destination self.ip
                            if self.mode > 0:
                                self.update_response(self.dns.id, socket.inet_ntoa(self.ip.dst), self.answer.name, self.answer.type, self.dns.rcode, 0, 0, str(datetime.datetime.utcfromtimestamp(self.ts).strftime("%d/%m/%y %H:%M:%S")))
                            if self.mode < 2:
                                print (self.dnsPktCount, '\t', self.dns.id, '\tFail/Refused\t', self.answer.name, self.dns.rcode,
                                       socket.inet_ntoa(self.ip.dst), '\t',
                                       str(datetime.datetime.utcfromtimestamp(self.ts).strftime("%H:%M:%S")))
                            continue
                        except:
                            continue
                else:
                    print (self.dnsPktCount, '\t', self.dns.id, ' unhandled dns.rcode:', self.dns.rcode)
                continue

            # New Types in DNS SEC not understood by the parser
            if len(self.dns.an) < 1:
                self.dnsResponseCount += 1
                if self.dns.rcode != dpkt.dns.DNS_RCODE_REFUSED:
                    # Todo: DNS SEC support
                    if self.mode < 2:
                        print(self.dnsPktCount, '\t', self.dns.id, "\tResponse \t Unhandled DNSSEC : opcode",
                              self.dns.opcode, "\t Rcode", self.dns.rcode)
                    continue
            try:
                # process and print responses based on record type
                c_name = ""
                self.dnsResponseCount += 1
                # for answer in dns.an:

                for self.answer in self.dns.an:
                    self.parse_response()
                for self.answer in self.dns.ns:
                    self.parse_response()
                for self.answer in self.dns.ar:
                    self.parse_response()

            except:
                # print (dnsPktCount,'\t',"Unhandled Query type : " + str(self.answer.type))
                print(self.dnsPktCount, '\t', "Unhandled Query type : ")
        self.f.close()

        print("\n=============== Processing completed at " + str(datetime.datetime.now()) + " ==========\n")
        print("Total number of Packets Processed : \t\t" + str(self.dnsPktCount))
        print("Total number of DNS Query : \t\t\t" + str(self.dnsQueryCount))
        print("Total number of DNS Responses: \t\t\t" + str(self.dnsResponseCount))
        print("Total number of Unknown Response Records : \t" + str(self.dnsUnknownResponseCount))
        print("Total number of Failed Responses: \t\t" + str(self.dnsFailedCount))
        print("Total Time taken : \t\t\t\t" + str(datetime.datetime.now() - self.start))

        self.csv_obj.write_log("2", "Processing completed at ", str(datetime.datetime.now()))
        self.csv_obj.write_log("3", "Total number of Packets Processed", str(self.dnsPktCount))
        self.csv_obj.write_log("4", "Total number of DNS Query", str(self.dnsQueryCount))
        self.csv_obj.write_log("5", "Total number of DNS Responses: ", str(self.dnsResponseCount))
        self.csv_obj.write_log("6", "Total number of Unknown Response Records", str(self.dnsUnknownResponseCount))
        self.csv_obj.write_log("7", "Total number of Failed Responses", str(self.dnsFailedCount))
        self.csv_obj.write_log("8", "Total Time taken", str(datetime.datetime.now() - self.start))

        # AnalyseData(self.filename + "_req.csv")
        self.csv_obj.close()
        #analyse_data(self.filename + "_req.csv")

        # from DnsMapper
        #csv_only = 0 ;
        #if csv_only == 0:
        #   return
        
        if self.csv_obj.pipeline == 0:
            t = Thread(target=map_analyse_data, args=(self.filename, 1))
            t.start()
            t.join()
            #thread.start_new_thread(map_analyse_data, (self.filename, 3))
            #thread.join()


def batch_parse():
    filename_list = ["20160423_235403.pcap","20160424_005404.pcap","20160424_015405.pcap","20160424_025406.pcap",
                     "20160424_035407.pcap","20160424_045408.pcap","20160424_055409.pcap","20160424_065410.pcap",
                     "20160424_075411.pcap","20160424_085412.pcap","20160424_095413.pcap","20160424_105414.pcap",
                     "20160424_115415.pcap","20160424_125416.pcap","20160424_135417.pcap","20160424_145418.pcap",
                     "20160424_155419.pcap","20160424_165420.pcap","20160424_175421.pcap","20160424_185422.pcap",
                     "20160424_195423.pcap","20160424_205424.pcap","20160424_215425.pcap","20160424_225426.pcap",
                     "20160424_235427.pcap","20160425_005428.pcap","20160425_015429.pcap","20160425_025430.pcap",
                     "20160425_035431.pcap","20160425_045432.pcap","20160425_055433.pcap","20160425_065434.pcap",
                     "20160425_075435.pcap","20160425_085436.pcap","20160425_095437.pcap","20160425_105438.pcap",
                     "20160425_115439.pcap","20160425_125440.pcap","20160425_135441.pcap","20160425_145442.pcap",
                     "20160425_155443.pcap","20160425_165444.pcap","20160425_175445.pcap","20160425_185446.pcap",
                     "20160425_195447.pcap","20160425_205448.pcap","20160425_215449.pcap","20160425_225450.pcap",
                     "20160426_231401.pcap","20160427_001402.pcap","20160427_011403.pcap","20160427_021404.pcap",
                     "20160427_031405.pcap","20160427_041406.pcap","20160427_051407.pcap","20160427_061408.pcap",
                     "20160427_071409.pcap","20160427_081410.pcap","20160427_091411.pcap","20160427_101412.pcap",
                     "20160427_111413.pcap","20160427_121414.pcap","20160427_131415.pcap","20160427_141416.pcap",
                     "20160427_151417.pcap","20160427_161418.pcap","20160427_171419.pcap","20160427_181420.pcap",
                     "20160427_191421.pcap","20160427_201422.pcap","20160427_211423.pcap","20160427_221424.pcap",
                     "20160427_231425.pcap","20160428_001426.pcap","20160428_011427.pcap","20160428_021428.pcap",
                     "20160428_031429.pcap","20160428_041430.pcap","20160428_051431.pcap","20160428_061432.pcap",
                     "20160428_071433.pcap","20160428_081434.pcap","20160428_091435.pcap","20160428_101436.pcap",
                     "20160428_111437.pcap","20160428_121438.pcap","20160428_131439.pcap","20160428_141440.pcap",
                     "20160428_151441.pcap","20160428_161442.pcap","20160428_171443.pcap","20160428_181444.pcap",
                     "20160428_191445.pcap","20160428_201446.pcap","20160428_211447.pcap","20160428_221448.pcap",
                     "20160428_231449.pcap","20160429_001450.pcap","20160429_011451.pcap","20160429_021452.pcap",
                     "20160429_031453.pcap","20160429_041454.pcap","20160429_051455.pcap","20160429_061456.pcap",
                     "20160429_071457.pcap","20160429_081458.pcap","20160429_091459.pcap","20160429_101500.pcap",
                     "20160429_111501.pcap","20160429_121502.pcap","20160429_131503.pcap","20160429_141504.pcap",
                     "20160429_151505.pcap","20160429_161506.pcap","20160429_171507.pcap","20160429_181508.pcap",
                     "20160429_191509.pcap","20160429_201510.pcap","20160429_211511.pcap","20160429_221512.pcap",
                     "20160429_231513.pcap","20160430_001514.pcap","20160430_011515.pcap","20160430_021516.pcap",
                     "20160430_031517.pcap","20160430_041518.pcap","20160430_051519.pcap","20160430_061520.pcap",
                     "20160430_071521.pcap","20160430_081522.pcap","20160430_091523.pcap","20160430_101524.pcap",
                     "20160430_111525.pcap","20160430_121526.pcap","20160430_131527.pcap","20160430_141528.pcap",
                     "20160430_151529.pcap","20160430_161530.pcap","20160430_171531.pcap","20160430_181532.pcap",
                     "20160430_191533.pcap","20160430_201534.pcap","20160430_211535.pcap","20160430_221536.pcap",
                     "20160430_231537.pcap","20160501_001538.pcap","20160501_011539.pcap","20160501_021540.pcap",
                     "20160501_031541.pcap","20160501_041542.pcap","20160501_051543.pcap","20160501_061544.pcap",
                     "20160501_071545.pcap","20160501_081546.pcap","20160501_091547.pcap","20160501_101548.pcap",
                     "20160501_111549.pcap","20160501_121550.pcap","20160501_131551.pcap","20160501_141552.pcap",
                     "20160501_151553.pcap","20160501_161554.pcap","20160501_171555.pcap","20160501_181556.pcap",
                     "20160501_191557.pcap","20160501_201558.pcap","20160501_211559.pcap","20160501_221600.pcap",
                     "20160506_231542.pcap","20160507_001543.pcap","20160507_011544.pcap","20160507_021545.pcap",
                     "20160507_031546.pcap","20160507_041547.pcap","20160507_051548.pcap","20160507_061549.pcap",
                     "20160507_071550.pcap","20160507_081551.pcap","20160507_091552.pcap","20160507_101553.pcap",
                     "20160507_111554.pcap","20160507_121555.pcap","20160507_131556.pcap","20160507_141557.pcap",
                     "20160507_151558.pcap","20160507_161559.pcap","20160507_171600.pcap","20160507_181601.pcap",
                     "20160507_191602.pcap","20160507_201603.pcap","20160507_211604.pcap","20160507_221605.pcap",
                     "20160507_231606.pcap","20160508_001607.pcap","20160508_011608.pcap","20160508_021609.pcap",
                     "20160508_031610.pcap","20160508_041611.pcap","20160508_051612.pcap","20160508_061613.pcap",
                     "20160508_071614.pcap","20160508_081615.pcap","20160508_091616.pcap","20160508_101617.pcap",
                     "20160508_111618.pcap","20160508_121619.pcap","20160508_131620.pcap","20160508_141621.pcap",
                     "20160508_151622.pcap","20160508_161623.pcap","20160508_171624.pcap","20160508_181625.pcap",
                     "20160508_191626.pcap","20160508_201627.pcap","20160508_211628.pcap","20160508_221629.pcap",
                     "20160508_231630.pcap","20160509_001631.pcap","20160509_011632.pcap","20160509_021633.pcap",
                     "20160509_031634.pcap","20160509_041635.pcap","20160509_051636.pcap","20160509_061637.pcap",
                     "20160509_071638.pcap","20160509_081639.pcap","20160509_091640.pcap","20160509_101641.pcap",
                     "20160509_111642.pcap","20160509_121643.pcap","20160509_131644.pcap","20160509_141645.pcap",
                     "20160509_151646.pcap","20160509_161647.pcap","20160509_171648.pcap","20160509_181649.pcap",
                     "20160509_191650.pcap","20160509_201651.pcap","20160509_211652.pcap","20160509_221653.pcap"]
    for items in filename_list:
        try:
            #obj_dns_parser = PcapParser(10000000, 3, '../../Traffic/' + items, 1)
            obj_dns_parser = PcapParser(10000000, 3, '../../sample_large.pcap', 1)
            obj_dns_parser.start_parse()
            return()


        except:
            print("File Not Found")
            #  return
            time.sleep(5)

    # obj_dns_parser = PcapParser(10000, 3, 'E:/Phd/python/scripts/DNS_AAAA.pcap', 1)


def main():
    print ("\n================================= DNS Parse v0.01 =============================\n")

    try:
        opts, args = getopt.getopt(sys.argv[1:], "vm:c:f:")
        # print (sys.argv)
    except:
        print(syntax)
        sys.exit(2)

    filename = ""
    # Count of packets to parse
    max_pkt_count = 1000
    mode = 4
    verbose = 0
    for opt, arg in opts:
        if opt == '-h':
            print(syntax)
            sys.exit()
        elif opt in "-f":
            filename = arg
            print ("Opening File : " + str(filename))
        elif opt in "-v":
            verbose = 1
        elif opt in "-m":
            mode = int(arg)
        elif opt in "-c":
            max_pkt_count = int(arg)
            print ("Maximum Packet count  : " + str(max_pkt_count))

        else:
            print(syntax)
            sys.exit()

    if filename == "":
        print(syntax)
        #sys.exit()

    obj_dns_parser = PcapParser(max_pkt_count, mode, filename, verbose)
    #obj_dns_parser = PcapParser(1000, 3, '../sample/sample.pcap', 1)


    obj_dns_parser.start_parse()

if __name__ == "__main__":
    batch_parse()
