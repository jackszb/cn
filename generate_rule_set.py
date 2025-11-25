import math
import re
import maxminddb
import requests
import json
import os
import argparse
from aggregate6 import aggregate

# 解析输出目录参数
parser = argparse.ArgumentParser()
parser.add_argument("--output-dir", default="./work", help="Output directory for .srs files")
args = parser.parse_args()
output_dir = args.output_dir
os.makedirs(output_dir, exist_ok=True)

# ----------------------------
# 数据源配置
# ----------------------------
dnsmasq_url = "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf"
gfwlist_url = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/list.txt"
maxmind_url = "https://raw.githubusercontent.com/alecthw/mmdb_china_ip_list/release/Country.mmdb"

# ----------------------------
# 函数
# ----------------------------
def convert_dnsmasq(name, url):
    r = requests.get(url)
    domain_suffix_list = []
    if r.status_code == 200:
        for line in r.text.splitlines():
            if not line.startswith("#"):
                m = re.match(r"server=\/(.*)\/(.*)", line)
                if m:
                    domain_suffix_list.append(m.group(1))
    result = {"version": 3, "rules": [{"domain_suffix": domain_suffix_list}]}
    filepath = os.path.join(output_dir, f"{name}.json")
    with open(filepath, "w") as f:
        json.dump(result, f, indent=4)
    return filepath

def get_gfwlist(url):
    r = requests.get(url)
    filepath = os.path.join(output_dir, "gfwlist.txt")
    with open(filepath, "wb") as f:
        f.write(r.content)
    return filepath

def convert_maxmind(url):
    r = requests.get(url)
    with open("Country.mmdb", "wb") as f:
        f.write(r.content)
    reader = maxminddb.open_database("Country.mmdb")
    ip_cidr_list = []
    for cidr, info in reader.__iter__():
        country = None
        if info.get("country"):
            country = info["country"]["iso_code"]
        elif info.get("registered_country"):
            country = info["registered_country"]["iso_code"]
        if country == "CN":
            ip_cidr_list.append(str(cidr))
    reader.close()
    ip_cidr_list = aggregate(ip_cidr_list)
    result = {"version": 3, "rules": [{"ip_cidr": ip_cidr_list}]}
    filepath = os.path.join(output_dir, "maxmind-cn.json")
    with open(filepath, "w") as f:
        json.dump(result, f, indent=4)
    return filepath

def compile_to_srs(json_file):
    srs_file = json_file.replace(".json", ".srs")
    os.system(f"sing-box rule-set compile --output {srs_file} {json_file}")
    return srs_file

def convert_adguard_to_srs(txt_file):
    srs_file = txt_file + ".srs"
    os.system(f"sing-box rule-set convert --type adguard --output {srs_file} {txt_file}")
    return srs_file

# ----------------------------
# 主流程
# ----------------------------
def main():
    files_json = []
    files_txt = []

    # 1️⃣ accelerated-domains.china
    f = convert_dnsmasq("accelerated-domains.china", dnsmasq_url)
    files_json.append(f)

    # 2️⃣ maxmind-cn
    f = convert_maxmind(maxmind_url)
    files_json.append(f)

    # 3️⃣ gfwlist
    f = get_gfwlist(gfwlist_url)
    files_txt.append(f)

    # 4️⃣ 编译 json -> srs
    for f in files_json:
        compile_to_srs(f)

    # 5️⃣ 转换 gfwlist -> srs
    for f in files_txt:
        convert_adguard_to_srs(f)

    print("All .srs files generated in:", output_dir)

if __name__ == "__main__":
    main()
