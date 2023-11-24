# this scrypt analyze the workload executed on PC - Web Browser (Firefox on Fedora Linux, without extension and
# with anti tracker protection by default)

from scapy.all import *
from scapy.layers.dns import DNSQR, DNS


count_site = {}
count_google = 0


# count of number of total site google
def count_site_google(str_site):
    global count_google
    if ('google' or 'doubleclick' or 'youtube' or 'gstatic') in str_site:
        count_google += 1


def read_packages(file_name: str):
    packets = rdpcap(file_name)
    pkgs = set()
    for pkt in packets:
        if DNSQR in pkt:
            dns_name = pkt[DNSQR].qname.decode('utf-8')
            if dns_name not in count_site:
                count_site[dns_name] = 1
            else:
                count_site[dns_name] += 1
            pkgs.add(dns_name)
    return pkgs


def workload_news(file_names: list):
    pkgs = set()
    for nf in file_names:
        pkgs = pkgs.union(read_packages(nf))
    lista = []
    for x in pkgs:
        if ('repubblica' or 'quotidiano') not in x:
            lista.append(x)
    return len(lista)


def workload_shop(file_names: list):
    pkgs = set()
    for nf in file_names:
        pkgs = pkgs.union(read_packages(nf))
    lista = []
    for x in pkgs:
        if ('ebay' and 'subito') not in x:
            lista.append(x)
    return len(lista)


def workload_music(file_names: list):
    pkgs = set()
    for nf in file_names:
        pkgs = pkgs.union(read_packages(nf))
    lista = []
    for x in pkgs:
        if ('spotify' and 'soundcloud') not in x:
            lista.append(x)
    return len(lista)


def workload_food(file_names: list):
    pkgs = set()
    for nf in file_names:
        pkgs = pkgs.union(read_packages(nf))
    lista = []
    for x in pkgs:
        if ('tripadvisor' or 'thefork') not in x:
            lista.append(x)
    return len(lista)


def workload_travels(file_names: list):
    pkgs = set()
    for nf in file_names:
        pkgs = pkgs.union(read_packages(nf))
    lista = []
    for x in pkgs:
        if ('skyscanner' or 'airbnb') not in x:
            lista.append(x)
    return len(lista)


def workload_social(file_names: list):
    pkgs = set()
    for nf in file_names:
        pkgs = pkgs.union(read_packages(nf))
    lista = []
    for x in pkgs:
        if ('x' and 'twitter' and 'youtube') not in x:
            lista.append(x)
    return len(lista)


class RunThread(Thread):

    def __init__(self, name):
        Thread.__init__(self)
        self.name = name
        self.num = None

    def run(self):
        if self.name == 'news':
            self.num = workload_news(['news/web/larepubblica.pcapng', 'news/web/liberoquotidiano.pcapng'])

        elif self.name == 'shop':
            self.num = workload_shop(['shop/web/ebay.pcapng', 'shop/web/subito_decrypted.pcapng'])

        elif self.name == 'music':
            self.num = workload_music(['music/web/soundcloud.pcapng', 'music/web/spotify.pcapng'])

        elif self.name == 'food':
            self.num = workload_food(['food/web/tripadvisor.pcapng', 'food/web/thefork.pcapng'])

        elif self.name == 'travel':
            self.num = workload_travels(['travel/web/skyscanner.pcapng', 'travel/web/airbnb.pcapng'])

        elif self.name == 'social':
            self.num = workload_social(['social/web/x-twitter.pcapng', 'social/web/youtube.pcapng'])


thread_list = [RunThread('news'), RunThread('shop'), RunThread('music'), RunThread('food'), RunThread('travel'),
               RunThread('social')]


for th in thread_list:
    th.start()

for th in thread_list:
    th.join()

for th in thread_list:
    print(f'Number of third site contacted ({th.name}): {th.num}')


# print for each domain name the number of time that is contacted
count_site_sorted = dict(sorted(count_site.items(), key=lambda x: x[1], reverse=True))
print('\n')
total_pkg = 0
for site, count in count_site_sorted.items():
    count_site_google(site)
    print(f'Site: {site}, Count: {count}')

print('\n')
print(f'Number of total site contacted: {len(count_site_sorted)}')
print(f'Number of total site google: {count_google}')