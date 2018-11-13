
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
# Find_Flux : Parse CSV file and generates flux data
#

# !python3

import csv
try:
    from gephistreamer import graph
    from gephistreamer import streamer
    stream = streamer.Streamer(streamer.GephiWS())
except:
    print("Error: Gephi Failed to load.")


class List:

    def __init__(self, *args, **kwargs):
        self.url = args[0]
        self.list = {}


class Flux:

    def __init__(self):
        self.url = {}
        self.ip = {}

    def process_record(self, url, ip):
        if url in self.url:
            if ip not in self.url[url].list:
                self.url[url].list[ip] = ip
        else:
            obj = List(url)
            obj.list[ip] = ip
            self.url[url] = obj

        if ip in self.ip:
            if url not in self.ip[ip].list:
                self.ip[ip].list[url] = url
        else:
            obj = List(ip)
            obj.list[url] = url
            self.ip[ip] = obj

    def check_domain_list(self, list_str):
        index = 0
        old_tld = ""
        old_sld = ""
        for item in list_str:
            if index == 0:
                pt = item.split('.')
                old_tld = pt[len(pt) - 1]
                old_sld = pt[len(pt) - 2]
                index += 1
            else:
                pt = item.split('.')
                if old_tld == pt[len(pt) - 1] and old_sld == pt[len(pt) - 2]:
                    old_tld = pt[len(pt) - 1]
                    old_sld = pt[len(pt) - 2]
                    index += 1
                    continue
                else:
                    return False
        return True

    # checks whether ip belongs to same network ID or not
    def check_ip_list(self, list_str):
        tmp_list = {}
        for item in list_str:
            pt = item.split('.')
            one_ld = pt[0]
            two_ld = pt[1]
            three_ld = pt[2]
            tmp_str = one_ld + "." + two_ld + "." + three_ld
            if tmp_str in tmp_list:
                obj = tmp_list[tmp_str]
                obj.append(pt[3])
            else:
                list_four = []
                list_four.append(pt[3])
                tmp_list[tmp_str] = list_four

        for items in tmp_list:
            prev = "-1"
            match = 0
            for sub_items in tmp_list[items]:
                if int(prev) == int(sub_items) - 1:
                    match += 1
                else:
                    match = 0
                prev = sub_items
                if match == 2:
                    return True
        return False

    def display_url_wise(self):
        for url in self.url:
            if len(self.url[url].list) < 5:
                continue
            else:
                tmp_list = []
                for ip in self.url[url].list:
                    tmp_list.append(ip)

                if not self.check_ip_list(tmp_list):
                    print (url, len(self.url[url].list))
                    for items in tmp_list:
                        print(items)

    def display_ip_wise(self):
        for ip in self.ip:
            if len(self.ip[ip].list) < 5:
                continue
            else:
                tmp_list = []
                for url in self.ip[ip].list:
                    tmp_list.append(url)
                if not self.check_domain_list(tmp_list):
                    print (ip, len(self.ip[ip].list))
                    for items in tmp_list:
                        print(items)

    def visualize_ip_flux(self):
        i = 0
        for ip in self.ip:
            i += 1
            # Subject to minimum of 20 URL
            if len(self.ip[ip].list) < 10:
                continue
            else:
                tmp_list = []
                for url in self.ip[ip].list:
                    tmp_list.append(url)
                if not self.check_domain_list(tmp_list):
                    node_a = graph.Node(ip)
                    stream.add_node(node_a)

                    for items in tmp_list:
                        node_b = graph.Node(items)
                        stream.add_node(node_b)
                        edge_ab = graph.Edge(node_a, node_b)
                        stream.add_edge(edge_ab)

    def visualize_url_flux(self):
        i = 0
        for url in self.url:
            i += 1
            # Subject to Minimum of 10 IP
            if len(self.url[url].list) < 10:
                continue
            else:
                tmp_list = []
                for ip in self.url[url].list:
                    tmp_list.append(ip)
                if not self.check_ip_list(tmp_list):
                    node_a = graph.Node(url)
                    stream.add_node(node_a)

                    for items in tmp_list:
                        node_b = graph.Node(items)
                        stream.add_node(node_b)
                        edge_ab = graph.Edge(node_a, node_b)
                        stream.add_edge(edge_ab)


req_infile = open("sample\\sample.pcap_map.csv", "r")
# req_infile = open("sample\\request.csv", "r")
req_reader = csv.reader(req_infile, delimiter=',')

h = Flux()
for res in req_reader:
    h.process_record(str(res[0]), str(res[1]))

# h.display_ip_wise()
# h.display_url_wise()

h.visualize_ip_flux()
# h.visualize_url_flux()