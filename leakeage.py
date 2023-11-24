# this script analyze data leakage on HTTP packages generated on workload executed on iPhone (iOS 17.X)

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
    pkgs = pyshark.FileCapture(file_name, override_prefs={'ssl.keylog_file': 'sslkeylogfile.txt'},
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


# news
print(f"######## Searching rai ########")
search_leakage('news/rai-iPhone.pcapng')
print(f"######## Searching sky ########")
search_leakage('news/sky-iPhone.pcapng')
print(f"######## Searching repubblica ########")
search_leakage('news/repubblica-iPhone.pcapng')

# shop
print("######## Searching amazon ########")
search_leakage('shop/amazon-iPhone.pcapng')
print("######## Searching ebay ########")
search_leakage('shop/ebay-iPhone.pcapng')
print("######## Searching quid-store ########")
search_leakage('shop/quid-store-iPhone.pcapng')

# fitness
print(f"######## Searching apple fitness ########")
search_leakage('fitness/fitness-apple-iPhone.pcapng')
print(f"######## Searching steps app ########")
search_leakage('fitness/steps-app-iPhone.pcapng')
print(f"######## Searching stepz app ########")
search_leakage('fitness/stepz-app-iPhone.pcapng')

# music
print(f"######## Searching spotify ########")
search_leakage('music/spotify-iPhone.pcapng')
print(f"######## Searching amazon music ########")
search_leakage('music/amazon-music-iPhone.pcapng')
print(f"######## Searching youtube music ########")
search_leakage('music/ytmusic-iPhone.pcapng')

# food
print(f"######## Searching justeat ########")
search_leakage('food/justeat-iPhone.pcapng')
print(f"######## Searching glovo ########")
search_leakage('food/glovo-iPhone.pcapng')
print(f"######## Searching the fork ########")
search_leakage('food/thefork-iPhone.pcapng')

# health
print(f"######## Searching my personal pet ########")
search_leakage('ricerca-salute/my-personal-pet-iPhone.pcapng')
print(f"######## Searching robinson pet shop ########")
search_leakage('ricerca-salute/robinson-pet-shop-iPhone.pcapng')
print(f"######## Searching farmacia soccavo ########")
search_leakage('ricerca-salute/farmaciasoccavo-iPhone.pcapng')

# travel
print(f"######## Searching viaggi.last minute ########")
search_leakage('ricerca-viaggio/viaggi.lastminute-iPhone.pcapng')
print(f"######## Searching weroad ########")
search_leakage('ricerca-viaggio/weroad-iPhone.pcapng')
print(f"######## Searching visitabudhabi ########")
search_leakage('ricerca-viaggio/visitabudhabi-iPhone.pcapng')

# social
print(f"######## Searching facebook ########")
search_leakage('social/fb-iPhone.pcapng')
print(f"######## Searching instagram ########")
search_leakage('social/insta-iPhone.pcapng')
print(f"######## Searching linkedin ########")
search_leakage('social/linkedin-iPhone.pcapng')

for item in list_info:
    print(f'Regex: {item["regex"]}; counter: {item["counter"]}/{count_pkg_http}')

