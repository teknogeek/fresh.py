#!/usr/bin/env python3

from dns.resolver import Resolver
from dns.exception import DNSException
import requests
import re
from multiprocessing.pool import ThreadPool


NS_LIST_URL = 'http://public-dns.info/nameservers.txt'
QUERY_DOMAIN = 'example.com'
FALSE_POSITIVES = [
    r'^(198\.105\.\d{1,3}\.11)$',
    r'^((?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'
]
FALSE_POSITIVE_DOMAINS = ['vpncloud.example.com']


def perform_lookup(server, domain, timeout=1, tries=1):
    # create DNS resolver
    dns_resolver = Resolver()
    dns_resolver.nameservers = [server]
    dns_resolver.lifetime = timeout

    # try [tries] times
    for _ in range(0, tries):
        try:
            answer = dns_resolver.query(domain)
            return [r.to_text() for r in answer]
        except (DNSException, ValueError):
            pass
    
    return None


# called when the check_resolver function thread returns
def callback(resolver):
    if resolver is not None:
        print('Discovered {}'.format(resolver))
        with open('resolvers.txt', 'a') as f:
            f.write('{}\n'.format(resolver))


# check a DNS resolver with example.com
def check_resolver(resolver, sanity_check):
    result = perform_lookup(resolver, QUERY_DOMAIN)
    if result and set(result) == sanity_check:
        # verify that the resolver does not return invalid data
        fp_match = False
        for fp_domain in FALSE_POSITIVE_DOMAINS:
            fp_result = perform_lookup(resolver, fp_domain)
            if fp_result is not None:
                # if an invalid lookup response is returned, indicate it
                print('Aborting {}: Resolved invalid against {}'.format(resolver, fp_domain))
                fp_match = True
                break

        # make sure only valid lookups are returns from this resolver
        if not fp_match:
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
            print('Error performing sanity check! (DNS lookup example.com from 1.1.1.1')


if __name__ == '__main__':
    main()
