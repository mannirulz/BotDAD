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
# Fingerprint Parser  and Anomaly Detection for Host's DNS Fingerprint
#


import datetime
import socket
import sys
import ipaddr
import time
import dpkt
import thread
import csv
import struct
import getopt
import os


class Anomaly:
    def __init__(self, filename):
        self.filename = filename
        self.counter = 1
        self.outfile = open("DNS_FP_OUT.csv", "w")

    def parse_file(self):
        req_infile = open(self.filename, "r")
        # req_infile = open("sample\\request.csv", "r")
        req_reader = csv.reader(req_infile, delimiter=',')

        count = 1
        tmpstr = ""

        for res in req_reader:
            try:
                if count == 1:
                    tmpstr += "UUID,"
                    for items in res:
                        tmpstr += items + ","
                    tmpstr += "Result,ResCode"
                    self.outfile.writelines(tmpstr + "\n")
                    count += 1
                    continue
                if count == 1500000:
                    break
                self.read_record(res)
                count += 1

            except:
                print "Error reading CSV record " + str(count) , sys.exc_info()
                continue
        self.outfile.close()

    def read_record(self, res):
        try:
            tmp_result = 1
            tmp_str = ""
            if int(res[2]) > 10000:
                tmp_result *= 3
            if int(res[3]) > 1500:
                tmp_result *= 5
            if int(res[4]) > 10000:
                tmp_result *= 7
            if int(res[5]) > 500:
                tmp_result *= 11
            if int(res[6]) > 1000:
                tmp_result *= 13
            if int(res[10]) > 500:
                tmp_result *= 17
            if int(res[11]) > 50:
                tmp_result *= 19
            if int(res[12]) > 500:
                tmp_result *= 23
            if int(res[13]) > 15:
                tmp_result *= 29
            if int(res[20]) > 50:
                tmp_result *= 31
            tmp_str += str(self.counter) + ","

            for items in res:
                tmp_str += items + ","

            if tmp_result == 1:
                tmp_str += "Clean," + str(tmp_result)
                # print tmp_str
            else:
                tmp_str += "Bot," + str(tmp_result)
            self.counter += 1
                # print tmp_str
            self.outfile.writelines(tmp_str + "\n")
        except:
            print "Error"


obj = Anomaly("DNS_FP.csv")
obj.parse_file()
