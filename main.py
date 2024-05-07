import cmseek
import findCVE
import json
import os
from urllib.parse import urlparse
from termcolor import colored


url = input("Enter URL: ")

cmseek.checkVersion(url)
parsed_url = urlparse(url)
path = os.path.join("Result", parsed_url.hostname, "cms.json")
f = open(path)
jsons = json.load(f)
for i in jsons:
    if "Version" in jsons[i]:
        print("\n######################################")
        if jsons[i][-1] == ',':
            jsons[i] = jsons[i][:-1]
        print(colored(f"[*] {jsons[i]}", "red"))
        arr = str(jsons[i]).split(" ")
        findCVE.findCVE(arr[0].replace('-', '_'), arr[2])
# findCVE.findCVE("WordPress", "4.1.12")
