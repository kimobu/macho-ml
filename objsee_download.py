import json
import requests
import re
import os

JSONPATH = "/Users/kimo/OneDrive/Documents/Research/Dissertation/Malware"
JSONFILE = "malware.json"
outpath = os.path.join(JSONPATH, "objective-see")
if not os.path.isdir(outpath):
    os.mkdir(outpath)

fullpath = os.path.join(JSONPATH, JSONFILE)


def check_if_downloaded(filename: str):
    if os.path.isfile(filename):
        return True
    else:
        return False


with open(fullpath, "r") as f:
    data = f.read()

jsondata = json.loads(data)

for malware in jsondata["malware"]:
    regx = re.search(r"\b[A-Fa-f0-9]{64}\b", malware["virusTotal"])
    if regx:
        sha = regx.group(0)
        print(f"Processing hash {sha}")
    else:
        if len(malware["download"]) > 1:
            sha = malware["download"].split("/")[-1]
        else:
            continue
    outfile = os.path.join(outpath, sha)
    if check_if_downloaded(outfile):
        print("Already downloaded")
        continue
    else:
        r = requests.get(malware["download"])
        with open(outfile, "wb") as f:
            f.write(r.content)
        print("Download finished")
