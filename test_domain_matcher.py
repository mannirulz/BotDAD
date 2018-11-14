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

# !python2

# test bed for IP address stuff


import ipaddr

# checks whether ip belongs to same network ID or not
def check_ip_list( list_str):
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

list_str = []

list_str.append("111.221.77.143")
list_str.append("111.221.77.144")
list_str.append("111.221.77.147")
list_str.append("111.221.77.154")
list_str.append("111.221.77.157")
list_str.append("111.221.77.158")
list_str.append("111.221.77.160")
list_str.append("111.221.77.161")
list_str.append("111.221.77.162")
list_str.append("111.221.77.168")
list_str.append("111.221.77.173")
list_str.append("157.55.130.150")
list_str.append("157.55.130.151")
list_str.append("157.55.130.155")
list_str.append("157.55.130.161")
list_str.append("157.55.130.162")
list_str.append("157.55.130.171")
list_str.append("157.55.235.143")
list_str.append("157.55.235.144")
list_str.append("157.55.235.152")
list_str.append("157.55.235.154")
list_str.append("157.55.235.158")
list_str.append("157.55.235.159")
list_str.append("157.55.235.160")
list_str.append("157.55.235.173")
list_str.append("157.55.235.174")
list_str.append("157.55.56.140")
list_str.append("157.55.56.146")
list_str.append("157.55.56.147")
list_str.append("157.55.56.153")
list_str.append("157.55.56.158")
list_str.append("157.55.56.168")
list_str.append("157.55.56.174")
list_str.append("157.55.56.176")
list_str.append("157.56.52.12")
list_str.append("157.56.52.15")
list_str.append("157.56.52.17")
list_str.append("157.56.52.23")
list_str.append("157.56.52.29")
list_str.append("157.56.52.31")
list_str.append("157.56.52.32")
list_str.append("157.56.52.35")
list_str.append("157.56.52.37")
list_str.append("64.4.23.143")
list_str.append("64.4.23.144")
list_str.append("64.4.23.145")
list_str.append("64.4.23.150")
list_str.append("64.4.23.152")
list_str.append("64.4.23.154")
list_str.append("64.4.23.158")
list_str.append("64.4.23.159")
list_str.append("64.4.23.163")
list_str.append("64.4.23.173")
list_str.append("65.55.223.12")
list_str.append("65.55.223.21")
list_str.append("65.55.223.28")
list_str.append("65.55.223.33")
list_str.append("65.55.223.41")
list_str.append("65.55.223.44")

#result = check_ip_list(list_str)
#print result


def convert_raw_to_ipv6(byte_ip):
    print(ipaddr.IPAddress(byte_ip))


f = open('UFID.txt', 'r')
str =  f.read()
print int(str)
f.close()


