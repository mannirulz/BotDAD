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


# !python2

# Experiment to check DNS query of top 100 Alexa Domains


import webbrowser
import os
import time
import subprocess

whitelist ={"google.com":1,
"facebook.com":2,
"youtube.com":3,
"baidu.com":4,
"yahoo.com":5,
"amazon.com":6,
"wikipedia.org":7,
"google.co.in":8,
"qq.com":9,
"twitter.com":10,
"live.com":11,
"taobao.com":12,
"msn.com":13,
"yahoo.co.jp":14,
"linkedin.com":15,
"google.co.jp":16,
"sina.com.cn":17,
"weibo.com":18,
"bing.com":19,
"yandex.ru":20,
"vk.com":21,
"hao123.com":22,
"instagram.com":23,
"ebay.com":24,
"google.de":25,
"amazon.co.jp":26,
"mail.ru":27,
"google.co.uk":28,
"pinterest.com":29,
"google.ru":30,
"360.cn":31,
"t.co":32,
"reddit.com":33,
"google.com.br":34,
"tmall.com":35,
"netflix.com":36,
"google.fr":37,
"paypal.com":38,
"microsoft.com":39,
"sohu.com":40,
"wordpress.com":41,
"google.it":42,
"blogspot.com":43,
"google.es":44,
"onclickads.net":45,
"gmw.cn":46,
"tumblr.com":47,
"imgur.com":48,
"ok.ru":49,
"aliexpress.com":50,
"xvideos.com":51,
"apple.com":52,
"stackoverflow.com":53,
"imdb.com":54,
"fc2.com":55,
"google.com.mx":56,
"ask.com":57,
"amazon.de":58,
"google.com.hk":59,
"google.com.tr":60,
"alibaba.com":61,
"google.ca":62,
"office.com":63,
"rakuten.co.jp":64,
"pornhub.com":65,
"google.co.id":66,
"tianya.cn":67,
"diply.com":68,
"github.com":69,
"craigslist.org":70,
"xinhuanet.com":71,
"nicovideo.jp":72,
"amazon.co.uk":73,
"soso.com":74,
"amazon.in":75,
"blogger.com":76,
"pixnet.net":77,
"coetbgsbu.org":78,
"outbrain.com":79,
"googleusercontent.com":80,
"cnn.com":81,
"bongacams.com":82,
"go.com":83,
"google.pl":84,
"naver.com":85,
"jd.com":86,
"dropbox.com":87,
"google.com.au":88,
"360.com":89,
"haosou.com":90,
"adnetworkperformance.com":91,
"adobe.com":92,
"xhamster.com":93,
"flipkart.com":94,
"coccoc.com":95,
"microsoftonline.com":96,
"whatsapp.com":97,
"chinadaily.com.cn":98,
"nytimes.com":99,
"chase.com":100}

tmpstr = ""
count  = 0

FNULL = open(os.devnull, 'w')
for key, value in whitelist.iteritems():
    count += 1
    if count == 2:
        break

    clear_cache = subprocess.check_output("ipconfig /flushdns", shell=True)
    #output = subprocess.check_output("c:/Progra~1/Wireshark/tshark -q -i 1  -Y ""dns.flags.response==0"" -a duration:5", shell=False)
    #webbrowser.get('C:/Program Files (x86)/Google/Chrome/Application/chrome.exe %s').open(key)
    #webbrowser.open("facebook,com", new=1, autoraise=False)
    
    webbrowser.open(key, new=1, autoraise=False)
    
    time.sleep(10)
    output = subprocess.check_output("ipconfig /displaydns", shell=True)
    #print(output)
    subprocess.call("taskkill /F /IM  iexplore.exe", stdout=FNULL, stderr=None)

    token = output.split("----------------------------------------")
    tmpstr += key + "," + str(value) + "," + str(len(token)-1) + "\n"


print (tmpstr)
