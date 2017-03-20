# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import sys
import argparse
import time
import requests

apikey = "3cfdaab1febc636127915dd233ebcbb4ec310e4cac8fec6ca93d8104063ae1028225cb4c91560c0662e639e49b0ceef2e3dc8cdd09008e8fa34e3938c1d5f8dd"
submit_url = "https://exfildetect.com/index.php?page=submit"
result_url = "https://exfildetect.com/index.php?page=analyses"
retries = 5

def send_file(url, key, file_path):
    
    post_data = {"apikey": key}
    post_file =  {"userfile": open(file_path, "rb")}
    
    answer = requests.post(url, timeout=60, data=post_data, files=post_file, verify=True)

    return answer

def get_results(url, key, query):
    
    post_data = {"apikey": key, "query": query}
    
    answer = requests.post(url, timeout=60, data=post_data, verify=True)
    
    print "Answer: %s" % answer

    return answer

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-f","--file", help="Path to pcap file", type=str, required=True)
    args = parser.parse_args()

    if not args.file:
        print ""
        sys.exit(0)

    answer = send_file(submit_url, apikey, file_path=args.file)

    if "Hash" in answer.text:
        query = answer.text.split(' ')[-1]
        print "Hash: %s" % query
        
        for i in range(1,retries+1):
            time.sleep(5)
            print "Try %i." % i
            answer = get_results(result_url, apikey, query)
            
            print answer.text
            
            if "No data" in answer.text or "No results" in answer.text:
                time.sleep(5*i)
            else:
                break
        
    else:
        print "Submission error."
        
    print "Done."