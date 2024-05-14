import cmseek
from findCVE import findCVE
import json
import os
from urllib.parse import urlparse
from termcolor import colored
from evn import pdf
from evn import pointAvg

url = input("Enter URL: ")

cmseek.checkVersion(url)
parsed_url = urlparse(url)
path = os.path.join("Result", parsed_url.hostname, "cms.json")
f = open(path)
jsons = json.load(f)

pointAvg = 0.0
# pdf = FPDF()
pdf.add_page()
pdf.set_font("Arial", size = 15, style='B')
pdf.cell(200, 10, txt = f"Pentest Report For Website: {url}", ln = 1, align = 'C')
pdf.set_font("Arial", size = 14, style='B')
pdf.cell(200, 10, txt = "I. Information", ln=1, align='L')
pdf.set_font("Arial", size = 14, style='')
for i in jsons:
    if "Version" in jsons[i]:
        if jsons[i][-1] == ',':
            pdf.cell(200, 10, txt=f"- {jsons[i][:-1]}", ln=1, align='L')
        else:
            pdf.cell(200, 10, txt=f"- {jsons[i]}", ln=1, align='L')
pdf.set_font("Arial", size = 14, style='B')
pdf.cell(200, 10, txt = "II. Vulnerability", ln=1, align='L')
pdf.set_font("Arial", size = 14, style='')
count = 1
for i in jsons:
    if "Version" in jsons[i]:
        print("\n######################################")
        if jsons[i][-1] == ',':
            jsons[i] = jsons[i][:-1]
        print(colored(f"[*] {jsons[i]}", "red"))
        pdf.cell(200, 10, txt=f"{count} {jsons[i]}", ln=1, align='L')
        count += 1
        arr = str(jsons[i]).split(" ")
        point = findCVE(arr[0].replace('-', '_'), arr[2])
        pointAvg = max(point, pointAvg)

pdf.set_font("Arial", size = 14, style='B')
pdf.cell(200, 10, txt=f"Point Average {pointAvg}")
pdf.output("report.pdf")
print(colored(f"\n[*] Point Average {pointAvg}", "red"))
# findCVE.findCVE("WordPress", "4.1.12")
