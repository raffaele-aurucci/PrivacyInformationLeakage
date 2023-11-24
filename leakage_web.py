# this script analyze data leakage on HTTP packages generated on workload executed on PC - Web Browser (Firefox on
# Fedora Linux, without extension and with anti tracker protection by default)

import pyshark
import re

count_pkg_http = 0

# every info contains 'str', 'counter', 'list of dict for uri/cookie/referer, sub-uri/cookie/referer, file name'
list_info = [
    {'regex': r'[^a-zA-Z0-9]name[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]gender[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]gnd[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]age[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]zip[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]ag[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]query[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]username[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]password[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]city[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]usr[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]pwd[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]sessionid[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]profile[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]userid[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]email[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]user[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]ip[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]dob[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]interests[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
    {'regex': r'[^a-zA-Z0-9]music[^a-zA-Z0-9]', 'counter': 0, 'list-leakage': []},
]


def verify_leakage(value: str, type: str, file_name: str):
    if value:
        for i in list_info:
            matches = re.finditer(i['regex'], value.lower())
            for match in matches:
                i['counter'] += 1
                index = match.start() + 1
                unchecked_information = value[index:]
                information = unchecked_information[:unchecked_information.find(' ')]
                i['list-leakage'].append({'type': type, 'info': information, 'file-name': file_name})


def search_leakage(file_name: str):
    pkgs = pyshark.FileCapture(file_name, override_prefs={'ssl.keylog_file': 'keylogfile.log'},
                               display_filter='http.request.method == GET or http.request.method == POST')

    global count_pkg_http

    for pkt in pkgs:
        if 'HTTP' in pkt:
            count_pkg_http += 1
            http_layer = pkt.http
            try:
                if hasattr(http_layer, 'request_uri'):
                    uri = http_layer.request_uri
                    verify_leakage(uri, 'uri', file_name)

                if hasattr(http_layer, 'referer'):
                    referer = http_layer.referer
                    verify_leakage(referer, 'referer', file_name)

                if hasattr(http_layer, 'cookie'):
                    cookie = http_layer.cookie
                    verify_leakage(cookie, 'cookie', file_name)
            except AttributeError:
                pass

    for i in list_info:
        print(f'Regex: {i["regex"]}')
        for elem in i['list-leakage']:
            if elem['file-name'] == file_name:
                print(f'{elem["type"]}: {elem["info"]}')
        print('--------------------')

    print('\n')
    pkgs.close()


# food
print(f"######## Searching tripadvisor ########")
search_leakage('food/web/tripadvisor.pcapng')
print(f"######## Searching thefork ########")
search_leakage('food/web/thefork.pcapng')

# music
print(f"######## Searching soundcloud ########")
search_leakage('music/web/soundcloud.pcapng')
print(f"######## Searching spotify ########")
search_leakage('music/web/spotify.pcapng')

# news
print(f"######## Searching repubblica ########")
search_leakage('news/web/larepubblica.pcapng')
print(f"######## Searching quotidiano ########")
search_leakage('news/web/liberoquotidiano.pcapng')

# travel
print(f"######## Searching skyscanner ########")
search_leakage('travel/web/skyscanner.pcapng')
print(f"######## Searching airbnb ########")
search_leakage('travel/web/airbnb.pcapng')

# shop
print(f"######## Searching ebay ########")
search_leakage('shop/web/ebay.pcapng')
print(f"######## Searching subito ########")
search_leakage('shop/web/subito_decrypted.pcapng')

# social
print(f"######## Searching x/twitter ########")
search_leakage('social/web/x-twitter.pcapng')
print(f"######## Searching youtube ########")
search_leakage('social/web/youtube.pcapng')

for item in list_info:
    print(f'Regex: {item["regex"]}; counter: {item["counter"]}/{count_pkg_http}')

