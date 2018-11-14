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

# IP Info Class

import geoip2.database


class IPDetails:
    def __init__(self, ip):
        try:
            self.ip = ip
            self.reader = geoip2.database.Reader('GeoLite2-City.mmdb')
            self.city_name = ""
            self.sub_name = ""
            self.country_name = ""
            response = self.reader.city(self.ip)
            # print response.country.iso_code
            self.country_name = response.country.name
            self.sub_name = response.subdivisions.most_specific.name
            # print response.subdivisions.most_specific.iso_code
            self.city_name = response.city.name
            # print response.postal.code
            # print response.location.latitude
            # print response.location.longitude
            self.reader.close()
        except:
            self.city_name = ""
            self.sub_name = ""
            self.country_name = ""


#Testing Basic IP Info
if __name__ == '__main__':
    obj = IPDetails('8.8.8.8')
    print obj.country_name, obj.sub_name, obj.city_name
    obj = IPDetails('4.4.4.4')
    print obj.country_name, obj.sub_name, obj.city_name
    obj = IPDetails('125.19.180.1')
    print obj.country_name, obj.sub_name, obj.city_name

