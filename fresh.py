#!/usr/bin/env python3

from dns.resolver import Resolver
from dns.exception import DNSException
import requests
import re
from os.path import exists as path_exists
from os import remove as remove_file
from multiprocessing.pool import ThreadPool

OUTFILE = 'resolvers.txt'
NS_LIST_URL = 'http://public-dns.info/nameservers.txt'
QUERY_DOMAIN = 'example.com'
FALSE_POSITIVES = [
    r'^(198\.(?:105|40)\.2[45]4\.\d{1,3})$',
    r'^(104\.239\.\d{1,3}\.\d{1,3})$',
    r'^(36\.(?:37|86)\.\d{1,3}\.\d{1,3})$',
    r'^(172\.26\.136\.\d{1,3})$',
    r'^(202\.188\.0\.156)$',
    r'^(122\.144\.4\.98)$',
    r'^(114\.6\.128\.9)$',
    r'^(92\.242\.140\.20)$',
    r'^(203\.252\.0\.221)$',
    r'^(91\.189\.0\.\d{1,3})$',
    r'^(123\.129\.254\.\d{1,3})$',
    r'^(205\.188\.157\.232)$',
    r'^(207\.251\.96\.\d{1,3})$',
    r'^(217\.74\.65\.145)$',
    r'^(195\.154\.\d{1,3}\.\d{1,3})$',
    r'^(62\.138\.23[89]\.45)$',
    r'^((?:186\.216|187\.62)\.\d{1,3}\.\d{1,3})$',
    r'^(71\.4[023]\.\d{1,3}\.\d{1,3})$',
    r'^(69\.(?:24|38)\.\d{1,3}\.\d{1,3})$',
    r'^(78\.3[89]\.\d{1,3}\.\d{1,3})$',
    r'^(5\.102\.\d{1,3}\.\d{1,3})$',
    r'^(192\.99\.195\.\d{1,3})$',
    r'^(89\.221\.\d{1,3}\.\d{1,3})$',
    r'^(80\.191\.\d{1,3}\.\d{1,3})$',
    r'^(41\.(?:7[27]|84)\.\d{1,3}\.\d{1,3})$',
    r'^(online\.kz)$',
    #r'^((?:21[378]|10[378]|18[1256]|178|19[02469]|200)\.\d{1,3}\.\d{1,3}\.\d{1,3})$',

    # hardcoded IPs
    r'^(34\.234\.89\.0|114\.6\.128\.9|122\.144\.4\.98|91\.98\.112\.128|78\.38\.117\.206|64\.128\.251\.228|63\.134\.179\.174)$',
    
    # IPv6
    r'^((?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'
]
FALSE_POSITIVE_DOMAIN = 'www.workshop.netscape.com'


def perform_lookup(server, domain, timeout=3, tries=1):
    # create DNS resolver
    dns_resolver = Resolver()
    dns_resolver.nameservers = [server]
    dns_resolver.lifetime = timeout

    # try (tries) times
    for _ in range(0, tries):
        try:
            answer = dns_resolver.query(domain)
            return [r.to_text() for r in answer]
        except (DNSException, ValueError) as e: 
            pass
    
    return None


# called when the check_resolver function thread returns
def callback(resolver):
    if resolver is not None:
        print('Discovered {}'.format(resolver))
        with open(OUTFILE, 'a') as f:
            f.write('{}\n'.format(resolver))


# check a DNS resolver with example.com
def check_resolver(resolver, sanity_check):
    result = perform_lookup(resolver, QUERY_DOMAIN)
    if result and set(result) == sanity_check:
        # verify that the resolver does not return invalid data
        fp_result = perform_lookup(resolver, FALSE_POSITIVE_DOMAIN)
        if fp_result is not None and fp_result:
            # if an invalid lookup response is returned, indicate it
            print('Aborting {}: Resolved invalid against {}'.format(resolver, FALSE_POSITIVE_DOMAIN))
        else:
            # only valid lookups are returns from this resolver
            return resolver

    return None


def main():
    # get the list of resolvers
    res = requests.get(NS_LIST_URL)
    if res.status_code == 200:
        # perform a baseline test to compare against
        sanity_check = perform_lookup('1.1.1.1', QUERY_DOMAIN, tries=5)

        if sanity_check is not None:
            sanity_check = set(sanity_check)

            # remove false positives
            initial_resolvers = []
            for line in res.content.decode().splitlines():
                replace_result = [bool(re.sub(regex, '', line)) for regex in FALSE_POSITIVES]
                if all(replace_result):
                    initial_resolvers.append(line)

            # clean out the resolvers.txt file
            if path_exists(OUTFILE):
                remove_file(OUTFILE)

            # create a thread pool and start the workers
            thread_pool = ThreadPool(50)
            workers = []
            for resolver in initial_resolvers:
                workers.append(thread_pool.apply_async(check_resolver, (resolver, sanity_check), callback=callback))
            
            # ensure all workers complete
            for w in workers:
                w.get()

            thread_pool.close()
            thread_pool.join()
        else:
            print('Error performing sanity check! (DNS lookup example.com using 1.1.1.1)')
            print('sanity check: {}'.format(sanity_check))


if __name__ == '__main__':
    main()
