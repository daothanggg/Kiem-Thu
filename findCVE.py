import sys
import requests
import re
from termcolor import colored
import json
from pyExploitDb import PyExploitDb
from bs4 import BeautifulSoup
import subprocess
from evn import pdf


def find_cpes(component, version):
    base_url = "https://nvd.nist.gov/products/cpe/search/results"
    params = {
        "namingFormat": "2.3",
        "keyword": f"{component} {version}",
        "orderBy": "CPEURI"
    }
    cpe_matches = []
    response = requests.get(base_url, params=params)
    content = response.text
    soup = BeautifulSoup(content, 'html.parser')
    tables = soup.findChildren('tbody', id='cpeSearchResultTBody')
    tb = tables[0]
    rows = tb.findChildren('tr')
    for row in rows:
        if component.lower() == row.findChildren('span')[1].text.lower():
            cpe_matches.append(row.findChildren('a')[0].text)

    return cpe_matches


def fetch_cve_details(cpe_string, component):
    pointAvg = 0.0
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    results = []

    cve_query_string = cpe_string
    url = f"{base_url}?cpeName={cve_query_string}"

    response = requests.get(url)
    
    if response.status_code != 200:
        print(colored(f"[i] Khong tim thay CVE", "green"))
        pdf.cell(200, 10, txt= "Khong tim thay CVE", ln=1, align='L')
        return 0.0

    try:
        data = response.json()
    except json.JSONDecodeError:
        print(colored(f"[i] Khong tim thay CVE", "green"))
        pdf.cell(200, 10, txt= "Khong tim thay CVE", ln=1, align='L')
        return 0.0
    # print(data)
    if "resultsPerPage" in data:
        cves = data["vulnerabilities"]
        for cve_item in cves:
            cve_id = cve_item["cve"]["id"]

            description = cve_item["cve"]["descriptions"][0]["value"]
            link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            str = list(cve_item["cve"]["metrics"].keys())[0]
            CVSS = cve_item["cve"]["metrics"][str][0]["cvssData"]["baseScore"]
            cve_details = {
                "CVE ID": cve_id,
                "Description": description,
                "Link": link,
                "CVSS v3": CVSS
            }
            print(colored(f"\n[i] {cve_id}", "red"))
            print(colored("- Description:", "blue"), description)
            print(colored("- CVSS:", "blue"), CVSS)
            pdf.cell(200, 10, txt= f"- ID: {cve_id}", ln=1, align='L')
            pdf.cell(200, 10, txt= f"  Description: {description}", ln=1, align='L')
            pdf.cell(200, 10, txt= f"  CVSS: {CVSS}", ln=1, align='L')
            pointAvg = max(pointAvg, float(CVSS))

            github = f"https://github.com/trickest/cve/blob/main/{cve_id.split('-')[1]}/{cve_id}.md"
            res = requests.get(github)
            if res.status_code == 200:
                print(colored(f"- More information: https://github.com/trickest/cve/blob/main/{cve_id.split('-')[1]}/{cve_id}.md", "blue"))
                pdf.cell(200, 10, txt= f"  More information: https://github.com/trickest/cve/blob/main/{cve_id.split('-')[1]}/{cve_id}.md", ln=1, align='L')
            else:
                print(colored("[] PoC Not Found", "red"))
            pdf.cell(200, 10, txt= f"  PoC Not Found", ln=1, align='L')
            results.append(cve_details)
    print(colored(f"[c] Ban nen cap nhat {component} len phien ban moi nhat!", "red"))
    pdf.cell(200, 10, txt= f"=> Ban nen cap nhat {component} len phien ban moi nhat!", ln=1, align='L')
    return pointAvg

def findCVE(component, version):
    results = 0.0
    cpe_strings = find_cpes(component, version)
    
    if cpe_strings:    
        for cpe_string in cpe_strings:
            results = fetch_cve_details(cpe_string, component)
            break
    else:
        print(colored("[i] Khong tim thay CVE", "green"))
    return results

# findCVE("live_chat", "4.1.10")
