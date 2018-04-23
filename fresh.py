#!/usr/bin/env python3

from dns.resolver import Resolver
from dns.exception import DNSException
import requests
import re
from multiprocessing.pool import ThreadPool
from threading import Lock


NS_LIST_URL = 'http://public-dns.info/nameservers.txt'
QUERY_DOMAIN = 'example.com'
FALSE_POSITIVES = [r'^198\.105\.\d{1,3}\.11$']
FALSE_POSITIVE_DOMAINS = ['vpncloud.example.com']
SANITY_CHECK = None
LOCK = Lock()

FAIL_COUNT = 0


def perform_lookup(server, domain, timeout=1, tries=1):
    global FAIL_COUNT
    
    dns_resolver = Resolver()
    dns_resolver.nameservers = [server]
    dns_resolver.lifetime = timeout

    for _ in range(0, tries):
        try:
            answer = dns_resolver.query(domain)
            return [r.to_text() for r in answer]
        except DNSException as e:
            pass
    
    FAIL_COUNT += 1
    return None


def callback(resolver):
    if resolver is not None:
        print(f'Discovered {resolver}')
        with open('resolvers.txt', 'a') as f:
            f.write(f'{resolver}\n')

def check_nameserver(resolver):
    global SANITY_CHECK, QUERY_DOMAIN, FALSE_POSITIVE_DOMAINS

    result = perform_lookup(resolver, QUERY_DOMAIN)
    if result and set(result) == SANITY_CHECK:
        # verify that the resolver does not return invalid data
        fp_match = False
        for fp_domain in FALSE_POSITIVE_DOMAINS:
            fp_result = perform_lookup(resolver, fp_domain)
            if fp_result is not None:
                # if an invalid lookup response is returned, indicate it
                print(f'Aborting {resolver}: Resolved invalid against {fp_domain}')
                fp_match = True
                break

        # make sure only valid lookups are returns from this resolver
        if not fp_match:
            return resolver


    return None

def main():
    global SANITY_CHECK

    res = requests.get(NS_LIST_URL)
    if res.status_code == 200:
        sanity_check_result = perform_lookup('1.1.1.1', QUERY_DOMAIN, tries=5)

        if sanity_check_result is not None:
            SANITY_CHECK = set(sanity_check_result)
            # remove false positives
            initial_resolvers = []
            for line in res.content.decode().splitlines():
                for regex in FALSE_POSITIVES:
                    if re.sub(regex, '', line):
                        initial_resolvers.append(line)
            
            pool = ThreadPool(20)
            workers = []
            for resolver in initial_resolvers:
                workers.append(pool.apply_async(check_nameserver, (resolver,), callback=callback))
            pool.close()
            pool.join()
            
            #filtered_resolvers = list(filter(None, valid_resolvers))


            #print(filtered_resolvers)
            #with open('resolvers.txt', 'w') as f:
            #    f.write('\n'.join(filtered_resolvers))
        else:
            print('Error performing sanity check! (DNS lookup example.com from 1.1.1.1')


if __name__ == '__main__':
    main()
