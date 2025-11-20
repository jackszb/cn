import argparse
import os
import re
import json
import requests
import maxminddb
from aggregate6 import aggregate

# ------------------ 参数解析 ------------------
parser = argparse.ArgumentParser()
parser.add_argument("--output-dir", default="./rule-set", help="Output directory for .srs files")
args = parser.parse_args()
output_dir = args.output_dir
os.makedirs(output_dir, exist_ok=True)

# ------------------ 数据源 ------------------
dnsmasq_china_list = [
    "https://raw.githubusercontent.com/Dreista/sing-box-rule-set-cn/rule-set/accelerated-domains.china.conf"
]

maxmind_urls = [
    "https://raw.githubusercontent.com/Dreamacro/maxmind-geoip/release/Country.mmdb"
]

adguard_urls = [
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
]

gfwlist_urls = [
    "https://raw.githubusercontent.com/gfwlist/gfwlist/refs/heads/master/list.txt"
]

# ------------------ 函数 ------------------
def convert_dnsmasq(url: str):
    r = requests.get(url)
    domain_suffix_list = []
    if r.status_code == 200:
        for line in r.text.splitlines():
            if not line.startswith("#"):
                m = re.match(r"server=\/(.*)\/(.*)", line)
                if m:
                    domain_suffix_list.append(m.group(1))
    result = {"version": 3, "rules": [{"domain_suffix": domain_suffix_list}]}
    filepath = os.path.join(output_dir, url.split("/")[-1] + ".json")
    with open(filepath, "w") as f:
        json.dump(result, f, indent=4)
    srs_path = filepath.replace(".json", ".srs")
    os.system(f"sing-box rule-set compile --output {srs_path} {filepath}")

def convert_maxmind(url: str, country_code: str, ip_version: str):
    r = requests.get(url)
    mmdb_path = os.path.join(output_dir, "Country.mmdb")
    with open(mmdb_path, "wb") as f:
        f.write(r.content)
    reader = maxminddb.open_database(mmdb_path)
    ip_cidr_list = []
    for cidr, info in reader.__iter__():
        code = info.get("country", {}).get("iso_code") or info.get("registered_country", {}).get("iso_code")
        if code == country_code:
            if (ip_version == "ipv4" and cidr.version == 4) or (ip_version == "ipv6" and cidr.version == 6):
                ip_cidr_list.append(str(cidr))
    reader.close()
    result = {"version": 3, "rules": [{"ip_cidr": aggregate(ip_cidr_list)}]}
    filepath = os.path.join(output_dir, f"maxmind-{country_code.lower()}-{ip_version}.json")
    with open(filepath, "w") as f:
        json.dump(result, f, indent=4)
    srs_path = filepath.replace(".json", ".srs")
    os.system(f"sing-box rule-set compile --output {srs_path} {filepath}")

def convert_adguard(url: str):
    r = requests.get(url)
    filename = url.split("/")[-1]
    filepath = os.path.join(output_dir, filename)
    with open(filepath, "wb") as f:
        f.write(r.content)
    srs_path = filepath + ".srs"
    os.system(f"sing-box rule-set convert --type adguard --output {srs_path} {filepath}")

# ------------------ 主程序 ------------------
def main():
    for url in dnsmasq_china_list:
        convert_dnsmasq(url)
    for url in maxmind_urls:
        for ip_version in ["ipv4", "ipv6"]:
            convert_maxmind(url, "CN", ip_version)
    for url in adguard_urls:
        convert_adguard(url)
    for url in gfwlist_urls:
        convert_adguard(url)
    print("All .srs files generated successfully in", output_dir)

if __name__ == "__main__":
    main()
