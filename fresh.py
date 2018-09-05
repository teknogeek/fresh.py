#!/usr/bin/env python3

import argparse
from dns.resolver import Resolver
from dns.exception import DNSException
import requests
import re
from os.path import exists as path_exists, splitext as split_path, isfile as is_file
from os import rename as rename_file, remove as remove_file
from multiprocessing.pool import ThreadPool
from socket import inet_aton, error as socket_error
from uuid import uuid4
from tqdm import tqdm

VERSION = '1.0.0'
BANNER = '''
$$$$$$$$\                            $$\\
$$  _____|                           $$ |
$$ |    $$$$$$\   $$$$$$\   $$$$$$$\ $$$$$$$\       $$$$$$\  $$\   $$\\
$$$$$\ $$  __$$\ $$  __$$\ $$  _____|$$  __$$\     $$  __$$\ $$ |  $$ |
$$  __|$$ |  \__|$$$$$$$$ |\$$$$$$\  $$ |  $$ |    $$ /  $$ |$$ |  $$ |
$$ |   $$ |      $$   ____| \____$$\ $$ |  $$ |    $$ |  $$ |$$ |  $$ |
$$ |   $$ |      \$$$$$$$\ $$$$$$$  |$$ |  $$ |$$\ $$$$$$$  |\$$$$$$$ |
\__|   \__|       \_______|\_______/ \__|  \__|\__|$$  ____/  \____$$ |
                                                   $$ |      $$\   $$ |
                                                   $$ |      \$$$$$$  |
                                                   \__|       \______/
Author: Joel Margolis (@0xteknogeek)
Version: {}\n\n'''.format(VERSION)

NS_LIST_URL = 'http://public-dns.info/nameservers.txt'

# checks if valid IP address
def is_valid_ip(parser, addr):
    try:
        inet_aton(addr)
    except socket_error:
        parser.error('{} is not a valid IP address!'.format(addr))

    return addr


# checks that clean regex pattern file exists and loads it as a list
def is_valid_clean_regex(parser, file_path):
    if path_exists(file_path) and is_file(file_path):
        with open(file_path, 'r') as f:
            patterns = f.read().splitlines()
        return [p.replace('[[:digit:]]', '\\d') for p in patterns]
    else:
        parser.error('The path {} does not exist or is not a file!'.format(file_path))

    return []


parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-q', '--query', dest='query_domain',
                    help='Valid domain to query each resolver for, e.g. example.com, images.google.com',
                    default='example.com')
parser.add_argument('-f', '--fpdomain', dest='false_positive_domain',
                    help='Invalid domain to test as a false positive for each resolver, e.g. ygsfdhauysuh.example.com, www.thisisnotarealdomain.google.com',
                    default='www.workshop.netscape.com')
parser.add_argument('-b', '--baseline', dest='baseline_server',
                    type=lambda x: is_valid_ip(parser, x),
                    help='DNS server IP to use for baseline sanity check to compare all other resolver results against, e.g. 1.1.1.1, 8.8.8.8',
                    default='1.1.1.1')
parser.add_argument('-o', '--output', dest='output_file',
                    help='Output file for valid resolvers',
                    default='resolvers.txt')
parser.add_argument('-t', '--timeout', dest='timeout', type=int,
                    help='DNS query timeout for each resolver (in seconds)',
                    default=3)
parser.add_argument('-r', '--retries', dest='retries', type=int,
                    help='Number of times to retry querying each resolver',
                    default=1)
parser.add_argument('-j', '--jobs', dest='job_count', type=int,
                    help='Number concurrent threads to use',
                    default=50)
parser.add_argument('-k', '--keep', dest='keep_old',
                    help='Keep and rename the output file if it already exists',
                    action='store_true',
                    default=False)
parser.add_argument('-v', '--verbose', dest='verbose',
                    help='Increase verbosity to show each resolver being testing (disables progress bar)',
                    action='store_true',
                    default=False)

parser.add_argument('--clean', dest='clean_regex',
                    type=lambda x: is_valid_clean_regex(parser, x),
                    help='File containing a list of regex patterns used to match and clean bad results and resolvers',
                    default='clean_regex.txt')
parser.add_argument('--noclean', dest='no_clean',
                    help='Force fresh.py not to pre-clean the resolver list with patterns from the the --clean file',
                    action='store_true',
                    default=False)

print(BANNER)
config = parser.parse_args()
progress_bar = None

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
    global progress_bar
    if not config.verbose:
        progress_bar.update(1)

    if resolver is not None:
        if config.verbose:
            print('[+] Discovered {}'.format(resolver))

        with open(config.output_file, 'a') as f:
            f.write('{}\n'.format(resolver))


# check a DNS resolver with lookup domain and compare against baseline
def check_resolver(resolver, sanity_check):
    result = perform_lookup(resolver, config.query_domain)
    if result and set(result) == sanity_check:
        # verify that the resolver does not return invalid data
        fp_result = perform_lookup(resolver, config.false_positive_domain, timeout=config.timeout, tries=config.retries)
        if fp_result is not None and fp_result:
            # if an invalid lookup response is returned, indicate it
            if config.verbose:
                print('[-] {} invalidly resolved {} (false-positive domain)'.format(resolver, config.false_positive_domain))
        else:
            # only valid lookups are returns from this resolver
            return resolver

    return None


def main():
    global progress_bar

    # get the list of resolvers
    res = requests.get(NS_LIST_URL)
    if res.status_code == 200:
        # perform a baseline test to compare against
        sanity_check = perform_lookup(config.baseline_server, config.query_domain, tries=5)

        if sanity_check is not None:
            sanity_check = set(sanity_check)


            all_resolvers = res.content.decode().splitlines()
            initial_resolvers = []

            if config.no_clean:
                # skip cleaning
                initial_resolvers = all_resolvers
            else:
                # remove false positives
                for line in all_resolvers:
                    replace_result = [bool(re.sub(regex, '', line)) for regex in config.clean_regex]
                    if all(replace_result):
                        initial_resolvers.append(line)

            # remove any existing output_file
            if path_exists(config.output_file):
                if config.keep_old:
                    name, ext = split_path(config.output_file)
                    backup_name = '{}-{}{}'.format(name, uuid4().hex, ext)
                    print('[*] Output file already exists, renaming {} to {}'.format(config.output_file, backup_name))

                    rename_file(config.output_file, backup_name)

                    # path still exists, rename failed
                    if path_exists(config.output_file):
                        print('[!] Rename failed, outputting to {} instead!'.format(backup_name))
                        config.output_file = backup_name
                else:
                    print('[*] Overwriting existing output file {}'.format(config.output_file))
                    remove_file(config.output_file)

            # create progress bar if not verbose mode
            if not config.verbose:
                progress_bar = tqdm(total=len(initial_resolvers), unit='resolvers')

            # create a thread pool and start the workers
            thread_pool = ThreadPool(config.job_count)
            workers = []
            for resolver in initial_resolvers:
                w = thread_pool.apply_async(check_resolver, (resolver, sanity_check), callback=callback)
                workers.append(w)

            # ensure all workers complete
            for w in workers:
                w.get()

            thread_pool.close()
            thread_pool.join()

            if not config.verbose:
                progress_bar.close()
        else:
            print('Error performing baseline sanity check! (DNS lookup {} using {})'.format(config.query_domain, config.baseline_server))


if __name__ == '__main__':
    main()
