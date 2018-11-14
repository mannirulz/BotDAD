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
# Main
#

# !python2

# Parse New Pcap file


pcaplist = ['20160421_150521.pcap' ]


pcaplist2 = [ 'dns_192.168.3.104-unvirus.pcap',
'dns_2014-01-31_capture-win7.pcap',
'dns_2014-04-07_capture-win13.pcap',
'dns_2014-06-06_capture-win2.pcap',
'dns_2014-06-30_capture-win2.pcap',
'dns_2015-03-12_capture-win6.pcap',
'dns_2015-05-01_capture-win2.pcap',
'dns_2015-06-19_capture-win12.pcap',
'dns_2015-10-23_win7.pcap',
'dns_2016-02-12-capture_win4.pcap',
'dns_2016-04-29_win-3.pcap',
'dns_2016-05-27_win-4.pcap',
'dns_2017-05-16_win5.pcap',
'dns_2017-11-22_win4.pcap',
'dns_2017-11-23_win16.pcap',
'dns_2017-12-18_win2.pcap',
'dns_2018-01-29_win6.pcap',
'dns_2018-01-30_win10.pcap',
'dns_2018-01-30_win17.pcap',
'dns_2018-01-30_win9.pcap',
'dns_2018-02-16_win8.pcap',
'dns_2018-04-03_win10.pcap',
'dns_2018-04-03_win11.pcap',
'dns_capture-win6.pcap',
'dns_capture_win15.pcap'
 ]

from PcapParser import PcapParser

try:

    for files in pcaplist:
        filename = "../../" + files
        try:
            obj_dns_parser = PcapParser(10000000, 3, filename, 1)
            obj_dns_parser.start_parse()
            #break
        except Exception as e:
            print (e)
            continue

except Exception as e:
    print(e)
