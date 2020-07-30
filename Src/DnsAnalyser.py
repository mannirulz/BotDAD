
# Copyright (C) 2016   Manmeet Singh (mSingh), Maninder Singh(MSingh), Sanmeet kour(SKour)
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
# CSVParser : Parse CSV file and generates graphs
#

# !python3

import sys
import socket
import datetime
import subprocess
import struct
import time
import os.path
from IPInfo import IPDetails
import csv
import matplotlib.pyplot as plt
import numpy as np
plt.rcdefaults()

# print messages 0- OFF , 1  -ON
VERBOSE = 1


class DnsResponseRecord:
    def __init__(self, *args, **kwargs):
        self.res_code = -1
        self.ttl = -1
        self.res_timestamp = -1
        self.resolved_ip = ""

    def insert(self,res_code, ttl, resolved_ip, ts):
        self.res_code = res_code
        self.ttl = ttl
        self.res_timestamp = ts
        self.resolved_ip = resolved_ip

    def display(self):
        print("Response:" + '\t' + str(self.res_code) + '\t' + str(self.ttl) + '\t' + self.resolved_ip + '\t' + str(self.res_timestamp))


# DNS Request/Response Class to collect timestamp for each DNS request
class DnsQuery:
    def __init__(self, *args, **kwargs):
        self.txn_id = ""
        self.req_url = args[0]
        self.req_type = -1
        self.req_timestamp = ""
        self.dns_server_ip = ""
        self.response = []

    def add_request(self, token, req_type, timestamp, dns_server_ip):
        self.txn_id = token
        self.req_type = req_type
        self.req_timestamp = timestamp
        self.dns_server_ip = dns_server_ip

    def update_response(self, res_code, ttl, resolved_ip, ts):
        obj = DnsResponseRecord()
        obj.insert(res_code, ttl, resolved_ip, ts)
        self.response.append(obj)

    def display(self):
        # print("URL : ", self.url)
        print ("Request:" + "\t" + self.txn_id + "\t" + self.req_url + "\t" + str(self.req_type) +
               "\t" + self.req_timestamp)
        for item in self.response:
            item.display()
        print ("\n")


class DnsQueryList:
    def __init__(self, *args, **kwargs):
        self.list = {}
        self.url = args[0]

    def add_request(self, token, request_type, timestamp, dns_server_ip):
        if token in self.list:
            obj = self.list[token]
            obj.add_request(token, request_type, timestamp, dns_server_ip)
        else:
            obj = DnsQuery(self.url)
            self.list[token] = obj
            obj.add_request(token, request_type, timestamp, dns_server_ip)

    def update_response(self, token, res_code, ttl, resolved_ip, ts):
        if token in self.list:
            obj = self.list[token]
            obj.update_response(res_code, ttl, resolved_ip, ts)

    def display(self):
        for items in self.list:
            obj = self.list[items]
            obj.display()


# Unique Host in the network which requests DNS Service
class Host:
    def __init__(self, *args, **kwargs):
        self.hostname = args[0]
        self.domain = {}
        self.req_count = 0
        self.plot_data = {}
        self.nbr_of_requests = 0
        self.nbr_of_distinct_requests = 0
        self.avg_req_per_min = 0
        self.max_req_per_min = 0
        self.failed_req_count = 0
        self.ratio_req_response = 0
        self.nbr_of_countries = 0
        self.req_type = 0
        self.sum_url_len = 0
        self.sum_nbr_domain_token = 0
        self.plot_data = {}

    def add_request(self, token, url, nbr_of_tokens, request_type, url_len,  timestamp, dns_server_ip):
        self.req_count += 1
        if url in self.domain:
            obj = self.domain[url]
            obj.add_request(token, request_type, timestamp, dns_server_ip)
        else:
            self.nbr_of_distinct_requests += 1
            obj = DnsQueryList(url)
            self.domain[url] = obj
            obj.add_request(token, request_type, timestamp, dns_server_ip)
        # obj.display()

    def update_response(self, token, url, res_code, ttl, resolved_ip, timestamp):
        if url in self.domain:
            # if res_code == "3":
            #    self.failed_req_count += 1
            obj = self.domain[url]
            obj.update_response(token, res_code, ttl, resolved_ip, timestamp)
        # else:
        # Discard Response if request doesn't exist

    def display(self):
        print(self.hostname, self.req_count,
              self.nbr_of_requests, self.nbr_of_distinct_requests, self.avg_req_per_min,
              self.max_req_per_min, self.failed_req_count, self.ratio_req_response,
              self.nbr_of_countries, self.req_type, self.sum_url_len, self.sum_nbr_domain_token )
        for url in self.domain:
            obj = self.domain[url]
            obj.display()

    def plot(self, filename):
        print("Hostname : ", self.hostname)
        print(" Number of URLs :", len(self.domain))

        for obj_domain in self.domain:
            obj_list = self.domain[obj_domain]
            for obj_query in obj_list.list:
                obj_req = obj_list.list[obj_query]
                mints = obj_req.req_timestamp[9:14]
                if mints in self.plot_data:
                    self.plot_data[mints] += 1
                else:
                    self.plot_data[mints] = 1
        new_key = []
        new_values = []
        i = 0

        for key, values in sorted(self.plot_data.items()):
            new_key.append(key)
            new_values.append(values)
            # print(key,values)
            i += 1

        fig = plt.figure()
        plt.bar(range(len(new_key)), new_values, align='center')
        plt.xticks(range(len(new_key)), new_key,rotation='75',size='xx-small')
        plt.ylabel('# of DNS Request')
        plt.xlabel("Time Line")
        plt.title("DNS Traffic  for " + self.hostname)

        plt.show()
        #plt.savefig(filename + "_" + self.hostname + "_req_time.png", dpi=fig.dpi)
        plt.close()


# Network Class consisting of Hosts
class Network:
    def __init__(self, *args, **kwargs):
        self.hosts = {}
        self.filename = args[0]
        self.UFID = 1

    # Process records in CSV File
    def process_record(self, token, hostname, url, nbr_of_tokens, request_type, url_len,  timestamp, dns_server_ip):
        if hostname in self.hosts:
            obj = self.hosts[hostname]
            obj.add_request(token, url, nbr_of_tokens, request_type, url_len,  timestamp, dns_server_ip)
        else:
            obj = Host(hostname)
            self.hosts[hostname] = obj
            obj.add_request(token, url, nbr_of_tokens, request_type, url_len,  timestamp, dns_server_ip)

    def process_response(self, token, hostname, url, res_code, ttl, resolved_ip, timestamp):
        if hostname in self.hosts:
            obj = self.hosts[hostname]
            obj.update_response(token, url, res_code, ttl, resolved_ip, timestamp)
        # else
        # If Request doesn't exist, discard response

    # Display top n hosts
    def display_count(self, count):
        # obj = Host("127.0.0.1")
        i = 1
        for m_hosts in self.hosts:
            print (i, ". ", m_hosts)
            obj = self.hosts[m_hosts]
            obj.display()
            i += 1
            if count == i:
                break

    # Display all requests by hostname
    def display_host(self, hostname):
        if hostname in self.hosts:
            obj = self.hosts[hostname]
            obj.display()
        else:
            print("Hostname not found !!")

    # Save all requests by hostname
    def save_host(self, hostname):
        tmp_str = ""
        if hostname in self.hosts:
            obj = self.hosts[hostname]
            for m_urls in obj.domain:
                token_list = obj.domain[m_urls]
                for token in token_list.list:
                    request = token_list.list[token]
                    tmp_str += request.txn_id + "," + request.req_url + "," + request.req_timestamp \
                               + "," + request.req_type
                    for res in request.response:
                        if res.resolved_ip != "0":
                            tmp_str += res.res_code + "," + res.ttl + "," + res.res_timestamp + "," + res.resolved_ip
                    tmp_str += "\n"

            xml_outfile = open("host_" + hostname + ".csv", "w")
            xml_outfile.write(tmp_str)
            xml_outfile.close()

        else:
            print("Hostname not found !!")


    # Display all requests by hostname
    def save_map(self, hostname, tmp_str):
        if hostname in self.hosts:
            obj = self.hosts[hostname]
            for m_urls in obj.domain:
                token_list = obj.domain[m_urls]
                for token in token_list.list:
                    request = token_list.list[token]
                    for res in request.response:
                        if res.resolved_ip != "0":
                            tmp_str += request.req_url + "," + res.resolved_ip + "\n"

            xml_outfile = open(hostname + "_map.csv", "w")
            xml_outfile.write(tmp_str)
            xml_outfile.close()
        else:
            for m_hosts in self.hosts:
                obj = self.hosts[m_hosts]
                for m_urls in obj.domain:
                    token_list = obj.domain[m_urls]
                    for token in token_list.list:
                        request = token_list.list[token]
                        for res in request.response:
                            if res.resolved_ip != "0":
                                tmp_str += request.req_url + "," + res.resolved_ip + "\n"

            xml_outfile = open(self.filename + "_map.csv", "w")
            xml_outfile.write(tmp_str)
            xml_outfile.close()

    def display(self):
        for hostname in self.hosts:
            obj = self.hosts[hostname]
            obj.display()

    # plot using Hostname
    def plot(self, hostname):
        if hostname in self.hosts:
            obj = self.hosts[hostname]
            obj.plot(self.filename)
        else:
            print("Hostname not found !!")

    # Returns seconds given a timestamp
    def get_sec(self, time_str):
        h, m, s = time_str.split(':')
        return int(h) * 3600 + int(m) * 60 + int(s)

    # Return Top Level Domain of a FQDN
    def get_tld(self, url):
        ptr = url.split('.')
        if len(ptr) > 0:
            return ptr[len(ptr) - 1]

    # Return Second Level Domain of a FQDN
    def get_sld(self, url):
        ptr = url.split('.')
        if len(ptr) > 1:
            return ptr[len(ptr) - 2]

    # Get UFID Unique Footprint ID
    def getUFID(self):
        if os.path.exists("UFID.txt"):
            f = open('UFID.txt', 'r')
            tmp_str = f.read()
            self.UFID = int(tmp_str)
            f.close()
        else:
            f = open('UFID.txt', 'w')
            f.write("1")
            f.close()

    def updateUFID(self,ufid):
        f = open('UFID.txt', 'w')
        f.write(str(ufid))
        f.close()



    # Find number of requests, number of responses, number of response record, Number of resolved URL
    def find_anomaly(self):
        self.getUFID()
        host_cnt = self.UFID
        tmp_str = ""
        tmp_str2 = 'S.No, Hostname, Req_cnt, Dist_Req_Cnt, high_req_cnt_single_domain, avg_req_per_min, ' \
                   'high_req_per_min, cnt_query_a, cnt_query_mx, cnt_query_ns, cnt_query_ptr, dist_tld, ' \
                   'dist_sld, dist_dns_server, res_cnt,dist_city_cnt, dist_subdivision_cnt, dist_country_cnt,' \
                   ' res_rec_cnt, res_success_cnt, res_failed, avg_ttl_value, high_ttl_value, res_ip_cnt\n'
        for m_hosts in self.hosts:
            req_cnt = 0
            dist_req_cnt = 0
            high_req_cnt_single_domain = 0
            first_req_time = 0
            last_req_time = 0
            avg_req_per_min = 0.0
            res_cnt = 0
            min_stats = {}
            high_req_per_min = 0
            cnt_query_a = 0
            cnt_query_mx = 0
            cnt_query_ns = 0
            cnt_query_ptr = 0
            list_tld = []
            dist_tld = 0
            list_sld = []
            dist_sld = 0
            dist_dns_server = 0

            dist_city_cnt = 0
            dist_subdivision_cnt = 0
            dist_country_cnt = 0

            res_rec_cnt = 0
            res_success_cnt = 0
            res_failed = 0
            avg_ttl_value = 0
            high_ttl_value = 0
            list_dns_server_ip = []
            list_res_ip = []
            list_country_name = []
            list_sub_name = []
            list_city_name = []
            res_ip_cnt = 0
            host_cnt += 1
            obj = self.hosts[m_hosts]
            for m_urls in obj.domain:
                tld = self.get_tld(m_urls)
                if tld not in list_tld:
                    list_tld.append(tld)
                sld = self.get_sld(m_urls)
                if sld not in list_sld:
                    list_sld.append(sld)

                dist_req_cnt += 1
                token_list = obj.domain[m_urls]
                if high_req_cnt_single_domain < len(token_list.list):
                    high_req_cnt_single_domain = len(token_list.list)

                for token in token_list.list:
                    req_cnt += 1
                    request = token_list.list[token]
                    if len(request.response) != 0:
                        res_cnt += 1
                    seconds = self.get_sec(request.req_timestamp[9:17])
                    if first_req_time == 0:
                        first_req_time = seconds
                    if seconds < first_req_time:
                        first_req_time = seconds
                    elif seconds > last_req_time:
                        last_req_time = seconds

                    if int(request.req_type) == 1:
                        cnt_query_a += 1
                    elif int(request.req_type) == 2:
                        cnt_query_ns += 1
                    elif int(request.req_type) == 15:
                        cnt_query_mx += 1
                    elif int(request.req_type) == 12:
                        cnt_query_ptr += 1

                    if request.dns_server_ip not in list_dns_server_ip:
                        list_dns_server_ip.append(request.dns_server_ip)

                    mints = request.req_timestamp[9:14]
                    if mints in min_stats:
                        min_stats[mints] += 1
                    else:
                        min_stats[mints] = 1

                    # DNS_RCODE_NXDOMAIN = 3
                    for res in request.response:
                        if int(res.res_code) == 0:
                            res_success_cnt += 1
                        if int(res.res_code) == 3:
                            res_failed += 1
                        res_rec_cnt += 1
                        if res.resolved_ip != 0:
                            if high_ttl_value < int(res.ttl):
                                high_ttl_value = int(res.ttl)
                            avg_ttl_value += int(res.ttl)
                            if res.resolved_ip not in list_res_ip:
                                list_res_ip.append(res.resolved_ip)
                                obj_ip = IPDetails(res.resolved_ip)
                                if obj_ip.country_name not in list_country_name:
                                    list_country_name.append(obj_ip.country_name)
                                if obj_ip.sub_name not in list_sub_name:
                                    list_sub_name.append(obj_ip.sub_name)
                                if obj_ip.city_name not in list_city_name:
                                    list_city_name.append(obj_ip.city_name)

            for items in min_stats:
                if min_stats[items] > high_req_per_min:
                    high_req_per_min = min_stats[items]

            res_ip_cnt = len(list_res_ip)
            if res_success_cnt != 0:
                avg_ttl_value /= res_success_cnt
            if (last_req_time - first_req_time) > 60:
                avg_req_per_min = req_cnt / ((last_req_time - first_req_time) / 60)
            else:
                avg_req_per_min = req_cnt
            dist_city_cnt = len(list_city_name)
            dist_subdivision_cnt = len(list_sub_name)
            dist_country_cnt = len(list_country_name)
            dist_dns_server = len(list_dns_server_ip)
            dist_sld = len(list_sld)
            dist_tld = len (list_tld)

            tmp_list = self.filename.split('/')
            uuid = tmp_list[len(tmp_list) - 1]

            tmp_str += str(host_cnt) + "," + m_hosts + "_" + uuid[4:8] + uuid[9:11] + ","
            tmp_str += str(req_cnt) + ","
            tmp_str += str(dist_req_cnt) + ","
            tmp_str += str(high_req_cnt_single_domain) + ","
            tmp_str += str(avg_req_per_min) + ","
            tmp_str += str(high_req_per_min) + ","
            tmp_str += str(cnt_query_a) + ","
            tmp_str += str(cnt_query_mx) + ","
            tmp_str += str(cnt_query_ns) + ","
            tmp_str += str(cnt_query_ptr) + ","
            tmp_str += str(dist_tld) + ","
            tmp_str += str(dist_sld) + ","

            tmp_str += str(dist_dns_server) + ","
            tmp_str += str(res_cnt) + ","
            tmp_str += str(dist_city_cnt) + ","
            tmp_str += str(dist_subdivision_cnt) + ","
            tmp_str += str(dist_country_cnt) + ","
            tmp_str += str(res_rec_cnt) + ","
            tmp_str += str(res_success_cnt) + ","
            tmp_str += str(res_failed) + ","
            tmp_str += str(avg_ttl_value) + ","
            tmp_str += str(high_ttl_value) + ","
            tmp_str += str(res_ip_cnt) + "\n"
        # print tmp_str
        # xml_outfile = open(self.filename + "_DNS_FP.csv", "w+")

        self.updateUFID(host_cnt)
        if os.path.exists("DNS_FP.csv"):
            xml_outfile = open("DNS_FP.csv", "a")
        else:
            xml_outfile = open("DNS_FP.csv", "w")
            tmp_str = tmp_str2 + tmp_str

        xml_outfile.write(tmp_str)
        xml_outfile.close()

    # Find hosts that requested for URl with the Resolved Ip as received in resolved_Ip
    def find_resolved_ip(self, resolved_ip):
        for m_hosts in self.hosts:
            obj = self.hosts[m_hosts]
            next_host = False
            for m_urls in obj.domain:
                token_list = obj.domain[m_urls]
                for token in token_list.list:
                    request = token_list.list[token]
                    for res in request.response:
                        if res.resolved_ip == resolved_ip:
                            print m_hosts
                            next_host = True
                            break
                    if next_host:
                        break
                if next_host:
                    break
            if next_host:
                continue

    # Find hosts that requested  the same URL
    def find_req_url(self, req_url):
        for m_hosts in self.hosts:
            obj = self.hosts[m_hosts]
            next_host = False
            for m_urls in obj.domain:
                if m_urls == req_url:
                    print m_hosts
                    next_host = True
                    break
            if next_host:
                continue

    # Print summary of all hosts with greater than 300 requests
    def summary(self):
        print("Total Number of Hosts :" + str(len(self.hosts)))
        print("Number of Hosts with over 300 Different Requests:")
        i = 1
        for m_hosts in self.hosts:
            obj = self.hosts[m_hosts]
            #for m_urls in obj.domain:
                #token_list = obj.domain[m_urls]
            if len(obj.domain) > 300:
                print (m_hosts + "\t" + str(len(obj.domain)))

    def save_html(self):
        tmp_str = "<html><body><table border='1px'><thead><tr><th colspan='5'>DNS Summary</th></tr></thead>"
        print("Saving Requests:" + str(len(self.hosts)))
        host_cnt = 0
        for m_hosts in self.hosts:
            host_cnt += 1
            tmp_str += "<tr><td>" + str(host_cnt) + "</td><td colspan='4'>" + m_hosts + "</td></tr>"
            obj = self.hosts[m_hosts]
            url_cnt = 0
            for m_urls in obj.domain:
                url_cnt += 1
                tmp_str += "<tr><td></td><td>" + str(url_cnt) + "</td><td colspan='4'>" + m_urls + "</td></tr>"
                token_list = obj.domain[m_urls]

                token_cnt = 0

                for token in token_list.list:
                    token_cnt += 1
                    request = token_list.list[token]
                    tmp_str += "<tr><td></td><td></td><td>" + str(token_cnt) + "</td><td >" + request.txn_id + "</td><td >" + request.req_type + "</td><td >"\
                               + request.req_timestamp + "</td></tr>"

                    res_cnt = 0
                    for res in request.response:
                        res_cnt += 1
                        tmp_str += "<tr><td></td><td></td><td></td><td>" + str(res_cnt) + "</td><td >" + res.res_code + "</td><td >" + res.ttl + "</td><td >" \
                                   + res.resolved_ip + "</td><td >" + res.res_timestamp + "</td></tr>"



        tmp_str += "</table></body></html>"
        xml_outfile = open(self.filename + ".html", "w")
        xml_outfile.write(tmp_str)
        xml_outfile.close()

    # Save all requests in csv
    def save_csv(self):
        i = 1
        tmp_str = "Hostname,count,nbr_requests,nbr_unique_req,avg_req_min,max_req_min,failed_cnt,ratio," \
                  "nbr_countries,req_type,sum_url,sum_token\n"
        for m_hosts in self.hosts:
            tmp_str += m_hosts + ","
            obj = self.hosts[m_hosts]
            tmp_str += str(obj.req_count) + ","
            tmp_str += str(obj.nbr_of_requests) + ","
            tmp_str += str(obj.nbr_of_distinct_requests) + ","
            tmp_str += str(obj.avg_req_per_min) + ","
            tmp_str += str(obj.max_req_per_min) + ","
            tmp_str += str(obj.failed_req_count) + ","
            tmp_str += str(obj.ratio_req_response) + ","
            tmp_str += str(obj.nbr_of_countries) + ","
            tmp_str += str(obj.req_type) + ","
            tmp_str += str(obj.sum_url_len) + ","
            tmp_str += str(obj.sum_nbr_domain_token) + "\n"

        xml_outfile = open(self.filename + ".csv", "w")
        xml_outfile.write(tmp_str)
        xml_outfile.close()

    # Get all hosts with requests greater than threshold
    def get_top_hosts(self, thresh_hold, result):
        for m_hosts in self.hosts:
            obj = self.hosts[m_hosts]
            if len(obj.domain) > thresh_hold:
                result.append(m_hosts)


def console(h):
    syntax = "a - Anomaly \tl - list \t m - Save Map \t " \
             "p - plot \td/D - Display/Save \t s - summary " \
             "\t h - saveHtml \t x - saveCSV \t F - Find Req URl\t " \
             "f - Find Resolved IP\t q - quit"

    print(syntax)
    print("console>")
    choice = "l"
    while choice != "q":
        choice = raw_input()
        if choice == "l":
            result = []
            h.get_top_hosts(100, result)
            i = 1
            print("Hosts with over 100 distinct requests ")
            for m_host in result:
                print(str(i) + ".\t" + m_host + "\t" + str(h.hosts[m_host].req_count))
                i += 1
        elif choice == "s":
            h.find_anomaly()
        elif choice == "a":
            h.find_anomaly()
        elif choice == "p":
            print("Enter Hostname :")
            hostname = raw_input()
            h.plot(hostname)
        elif choice == "f":
            print("Enter Resolved IP :")
            resolved_ip = raw_input()
            h.find_resolved_ip(resolved_ip)
        elif choice == "F":
            print("Enter Request URL :")
            req_url = raw_input()
            h.find_req_url(req_url)
        elif choice == "d":
            print("Enter Hostname :")
            hostname = raw_input()
            h.display_host(hostname)
        elif choice == "D":
            print("Enter Hostname :")
            hostname = raw_input()
            h.save_host(hostname)
        elif choice == "m":
            print("Enter Hostname :")
            hostname = raw_input()
            tmp_str = ""
            h.save_map(hostname, tmp_str)
            print(tmp_str)
        elif choice == "q":
            continue
        elif choice == "x":
            h.save_csv()
        elif choice == "h":
            h.save_html()
        else:
            print("Invalid Choice !!")
        print(syntax)
        print("console>")

    print ("Console Terminated.")


def back_track():
    #1 Read DNS_FP_ID
    print "Enter Device Fingerprint: "
    fp_id = raw_input()

    #2 Extract Hostname and timestamp
    token= fp_id.split("_")
    print token[0],token[1]


    #3 Map pcap.csv filename
    print "2016" + token[1][0:4] + "_" + token[1][4:6] + ".pcap.csv"

    #4 parse csv

    #5 Show Host Details





# Rome was not build in a day
def rwnbiad(filename, option):

    h = Network(filename)

    req_infile = open(filename + "_req.csv", "r")
    # req_infile = open("sample\\request.csv", "r")
    req_reader = csv.reader(req_infile, delimiter=',')

    for res in req_reader:
        try:
            h.process_record(str(res[0]), str(res[1]), str(res[2]), str(res[3]), str(res[4]), str(res[5]), str(res[6]), str(res[7]))
        except:
            continue


    res_infile = open(filename + "_res.csv", "r")
    # res_infile = open("sample\\response.csv", "r")
    res_reader = csv.reader(res_infile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)

    for res in res_reader:
        try:
            h.process_response(str(res[0]), str(res[1]), str(res[2]), str(res[4]), str(res[5]), str(res[6]), str(res[7]))
        except:
            continue

    #   TODO: Automate the process after feedback from MSingh
    if option == 1:
        console(h)
    elif option == 2:
        h.find_anomaly()


# option 1 : console , 2 : Save FP
def map_analyse_data(filename, option):
    dns_analyser_start = datetime.datetime.now()
    print("===============DNS Analyzer Started at  " + str(dns_analyser_start) + ":" + filename + "===============")
    if option == 3:
        back_track()
    else:
        rwnbiad(filename, option)
    # get_stats(filename)
    print("===============DNS Analyzer Completed at  " + str(datetime.datetime.now()) + "==============")

# Main
# map_analyse_data("sample\\sample.pcap_req.csv")


if __name__ == '__main__':
    # map_analyse_data("../../traffic/20160423_235403.pcap", 2)
    map_analyse_data("",3)