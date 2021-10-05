import requests
import os
from time import sleep
base_url = "https://virusshare.com/apiv2/<request>?apikey=<apikey>&hash=<hash_string>"
hashes_file = "malwareids.txt"
download_dir = "/Users/kimo/OneDrive/Documents/Research/Dissertation/Malware/virusshare"
apikey = "5RBOEZvxWYn4IsyQn1QYTYDhgeu96oo9"

def download_file(filename: str):
	hash = filename.split("/")[-1]
	url = base_url.replace("<request>", "download")
	url = url.replace("<apikey>", apikey)
	url = url.replace("<hash_string>", hash)
	r = requests.get(url)
	with open(filename, "wb") as f:
		f.write(r.content)
	
def check_if_downloaded(filename: str):
	if os.path.isfile(filename):
		return True
	else:
		return False

def read_file(file):
	with open(hashes_file, 'r') as f:
		hashes = f.readlines()
	return hashes

if not os.path.isdir(download_dir):	
	os.mkdir(download_dir)
	
hashes = read_file(hashes_file)

for malware_hash in hashes:
	malware_hash = malware_hash.strip()
	print(f"Processing hash {malware_hash}")
	malware_file = os.path.join(download_dir, malware_hash)
	if check_if_downloaded(malware_file):
		print("Already downloaded")
		continue
	else:
		download_file(malware_file)
		print("Download finished")
		sleep(15)
	