# this script analyze the workload executed on iPhone (iOS 17.X)

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
        if DNS in pkt:
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
        if ('rai' and 'sky' and 'repubblica') not in x:
            lista.append(x)
    return len(lista)


def workload_shop(file_names: list):
    pkgs = set()
    for nf in file_names:
        pkgs = pkgs.union(read_packages(nf))
    lista = []
    for x in pkgs:
        if ('amazon' and 'ebay' and 'quid') not in x:
            lista.append(x)
    return len(lista)


def workload_fitness(file_names: list):
    pkgs = set()
    for nf in file_names:
        pkgs = pkgs.union(read_packages(nf))
    lista = []
    for x in pkgs:
        if ('apple' and 'steps' and 'stepz') not in x:
            lista.append(x)
    return len(lista)


def workload_music(file_names: list):
    pkgs = set()
    for nf in file_names:
        pkgs = pkgs.union(read_packages(nf))
    lista = []
    for x in pkgs:
        if ('spotify' and 'amazon' and 'youtube') not in x:
            lista.append(x)
    return len(lista)


def workload_food(file_names: list):
    pkgs = set()
    for nf in file_names:
        pkgs = pkgs.union(read_packages(nf))
    lista = []
    for x in pkgs:
        if ('justeat' and 'glovo' and 'thefork') not in x:
            lista.append(x)
    return len(lista)


def workload_health(file_names: list):
    pkgs = set()
    for nf in file_names:
        pkgs = pkgs.union(read_packages(nf))
    lista = []
    for x in pkgs:
        if ('personaltrainer' and 'robinsonpet' and 'farmaciasoccavo') not in x:
            lista.append(x)
    return len(lista)


def workload_message_app(file_names: list):
    pkgs = set()
    for nf in file_names:
        pkgs = pkgs.union(read_packages(nf))
    lista = []
    for x in pkgs:
        if ('whatsapp' and 'facebook' and 'telegram') not in x:
            lista.append(x)
    return len(lista)


def workload_travels(file_names: list):
    pkgs = set()
    for nf in file_names:
        pkgs = pkgs.union(read_packages(nf))
    lista = []
    for x in pkgs:
        if ('lastminute' and 'weroad' and 'visitabudhabi') not in x:
            lista.append(x)
    return len(lista)


def workload_social(file_names: list):
    pkgs = set()
    for nf in file_names:
        pkgs = pkgs.union(read_packages(nf))
    lista = []
    for x in pkgs:
        if ('facebook' and 'instagram' and 'linkedin') not in x:
            lista.append(x)
    return len(lista)


class RunThread(Thread):

    def __init__(self, name):
        Thread.__init__(self)
        self.name = name
        self.num = None

    def run(self):
        if self.name == 'news':
            self.num = workload_news(['news/rai-iPhone.pcapng', 'news/sky-iPhone.pcapng',
                                      'news/repubblica-iPhone.pcapng'])

        elif self.name == 'shop':
            self.num = workload_shop(['shop/amazon-iPhone.pcapng', 'shop/ebay-iPhone.pcapng',
                                      'shop/quid-store-iPhone.pcapng'])

        elif self.name == 'fitness':
            self.num = workload_fitness(['fitness/fitness-apple-iPhone.pcapng', 'fitness/steps-app-iPhone.pcapng',
                                         'fitness/stepz-app-iPhone.pcapng'])

        elif self.name == 'music':
            self.num = workload_music(['music/spotify-iPhone.pcapng', 'music/amazon-music-iPhone.pcapng',
                                       'music/ytmusic-iPhone.pcapng'])

        elif self.name == 'food':
            self.num = workload_food(['food/justeat-iPhone.pcapng', 'food/glovo-iPhone.pcapng',
                                      'food/thefork-iPhone.pcapng'])

        elif self.name == 'health':
            self.num = workload_health(['health/my-personal-pet-iPhone.pcapng',
                                        'health/robinson-pet-shop-iPhone.pcapng',
                                        'health/farmaciasoccavo-iPhone.pcapng'])

        elif self.name == 'travel':
            self.num = workload_travels(['travel/viaggi.lastminute-iPhone.pcapng',
                                         'travel/weroad-iPhone.pcapng',
                                         'travel/visitabudhabi-iPhone.pcapng'])

        elif self.name == 'social':
            self.num = workload_social(['social/fb-iPhone.pcapng', 'social/insta-iPhone.pcapng',
                                        'social/linkedin-iPhone.pcapng'])


thread_list = [RunThread('news'), RunThread('shop'), RunThread('fitness'), RunThread('music'), RunThread('food'),
               RunThread('health'), RunThread('travel'), RunThread('social')]


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