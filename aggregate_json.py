import json
import argparse
import os
import pandas as pd

parser = argparse.ArgumentParser(
    description="Opens JSON files of Mach-O data and aggregates into a single pandas dataframe, saving as a CSV."
)
parser.add_argument(
    "--path",
    default="./json_data",
    type=str,
    help="Where to look for parsed JSON files.",
)
parser.add_argument(
    "--outdir",
    default="/tmp/json_data",
    type=str,
    help="Where to output the CSV.",
)
parser.add_argument(
    "--outfile",
    default="macho_feature_vector.csv",
    type=str,
    help="What to call the CSV file.",
)
args = parser.parse_args()


def load_json(filename: str) -> str:
    with open(filename, "r") as f:
        data = json.loads(f.read())
    return data


def get_files(path: str) -> list:
    filelist = []
    for root, dirs, files in os.walk(path):
        for filename in files:
            fullpath = os.path.join(root, filename)
            filelist.append(fullpath)
    return filelist


def parse_segment(load_command: object):
    segment = {}
    name = load_command["name"]
    segment["name"] = name
    segment[f"segment_{name}_vmsize"] = load_command["vmsize"]
    segment[f"segment_{name}_size"] = load_command["size"]
    segment[f"segment_{name}_initprot"] = load_command["initprot"]
    segment[f"segment_{name}_maxprot"] = load_command["maxprot"]
    segment[f"segment_{name}_nsects"] = load_command["nsects"]
    segment[f"segment_{name}_entropy"] = load_command["entropy"]
    return segment


def parse_loaddylib(load_command: object):
    dylib = {}
    name = load_command["name"]
    dylib["name"] = name
    dylib[f"dylib_{name}_cmdsize"] = load_command["cmd_size"]
    dylib[f"dylib_{name}_version"] = load_command["current_version"]
    dylib[f"dylib_{name}_timestamp"] = load_command["timestamp"]
    return dylib


def parse_json(data: object):
    if not "macho" in data:
        return
    mach = {}
    mach["size"] = data["size"]
    mach["nlcs"] = data["macho"]["nlcs"]
    mach["slcs"] = data["macho"]["slcs"]
    mach["flags"] = data["macho"]["flags"]
    mach["load_commands"] = []
    for load_command in data["macho"]["lcs"]:
        lc_type = load_command["cmd"]
        if lc_type == "SEGMENT" or lc_type == "SEGMENT_64":
            segment = parse_segment(load_command)
            name = segment["name"]
            mach[f"segment_{name}"] = segment
        if lc_type == "LOAD_DYLIB":
            dylib = parse_loaddylib(load_command)
            name = dylib["name"]
            mach[f"dylib_{name}"] = dylib
    return mach


print("start")
files = get_files(args.path)
machos = []
max_len = 0
keys = []
for file in files:
    with open(file, "r") as f:
        jsondata = json.loads(f.read())
    mach = parse_json(jsondata)
    if not mach:
        continue
    machos.append(mach)
    [keys.append(x) for x in mach.keys()]
    cur_len = len(mach)
    if cur_len > max_len:
        max_len = cur_len
df = pd.DataFrame(columns=keys)
for mach in machos:
    print(mach)
    df.append(mach, ignore_index=True)
print(df)
