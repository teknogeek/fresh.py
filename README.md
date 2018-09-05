
# fresh.py

A remix of [fresh.sh](https://github.com/almroot/fresh.sh) with threading and ~~some~~ lots of added benefits :)


# Installation
Tested on Python 3.5+

```
$ git clone https://github.com/teknogeek/fresh.py && cd fresh.py
$ pip3 install -r requirements.txt
$ python3 fresh.py
```

-----

# Usage
```
usage: fresh.py [-h] [-q QUERY_DOMAIN] [-f FALSE_POSITIVE_DOMAIN]
                [-b BASELINE_SERVER] [-o OUTPUT_FILE] [-t TIMEOUT]
                [-r RETRIES] [-j JOB_COUNT] [-k] [-v] [--clean CLEAN_REGEX]
                [--noclean]

optional arguments:
  -h, --help            show this help message and exit
  -q QUERY_DOMAIN, --query QUERY_DOMAIN
                        Valid domain to query each resolver for, e.g.
                        example.com, images.google.com (default: example.com)
  -f FALSE_POSITIVE_DOMAIN, --fpdomain FALSE_POSITIVE_DOMAIN
                        Invalid domain to test as a false positive for each
                        resolver, e.g. ygsfdhauysuh.example.com,
                        www.thisisnotarealdomain.google.com (default:
                        www.workshop.netscape.com)
  -b BASELINE_SERVER, --baseline BASELINE_SERVER
                        DNS server IP to use for baseline sanity check to
                        compare all other resolver results against, e.g.
                        1.1.1.1, 8.8.8.8 (default: 1.1.1.1)
  -o OUTPUT_FILE, --output OUTPUT_FILE
                        Output file for valid resolvers (default:
                        resolvers.txt)
  -t TIMEOUT, --timeout TIMEOUT
                        DNS query timeout for each resolver (in seconds)
                        (default: 3)
  -r RETRIES, --retries RETRIES
                        Number of times to retry querying each resolver
                        (default: 1)
  -j JOB_COUNT, --jobs JOB_COUNT
                        Number concurrent threads to use (default: 50)
  -k, --keep            Keep and rename the output file if it already exists
                        (default: False)
  -v, --verbose         Increase verbosity to show each resolver being testing
                        (disables progress bar) (default: False)
  --clean CLEAN_REGEX   File containing a list of regex patterns used to match
                        and clean bad results and resolvers (default:
                        clean_regex.txt)
  --noclean             Force fresh.py not to pre-clean the resolver list with
                        patterns from the the --clean file (default: False)
```

-----

# Cleaning Outputs

No matter how good your resolver list is, there's a pretty good chance you're gonna get false positives. While this script attempts to mitigate as much of that as it can *before* doing DNS lookups (by checking the resolvers), it's not perfect. As a resuslt, I Massdns The [clean.sh](clean.sh) and [clean_regex.txt](clean_regex.txt) files are used to clean and sanitize *both* the **resolver addresses** themselves and any **DNS lookup results**.

Massdns example: 

```
$ python3 fresh.py -o resolvers.txt
$ massdns -r resolvers.txt -t A -o S -w massdns_output.txt domain_list.txt
$ bash clean.sh massdns_output.txt > massdns_clean.txt
```

`clean.sh` is really just a `egrep -vf` that uses the `clean_regex.txt` patterns by default. You can optionally provide your own regex pattern file as a second argument:

```
$ ~/fresh.py/clean.sh
Usage: clean.sh <input_file> [regex_pattern_file]
```

This will usually end up outputting a very clean resulting file.

**I would love more regex contributions! These regex patterns come from my own personal observations and testing.**
