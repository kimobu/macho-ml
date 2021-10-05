"""
Copyright 2021 Kimo Bumanglag <kimo.bumanglag@trojans.dsu.edu>

"""
import argparse
import py7zr
import zipfile
import magic
import os
import json
from macholibre import parse
from tqdm import tqdm

parser = argparse.ArgumentParser(
    description="Search a filesystem for Mach-O files and parse them to JSON objects."
)
parser.add_argument(
    "--path", default=".", type=str, help="Where to look for Mach-O files."
)
parser.add_argument(
    "--passwords",
    default=["infected", "virussign", "infect3d"],
    nargs="+",
    type=str,
    help="Passwords to unzip samples.",
)
parser.add_argument(
    "--tmpdir",
    default="/tmp/samples",
    type=str,
    help="Where to output extracted zip objects.",
)
parser.add_argument(
    "--outdir",
    default="/tmp/json_data",
    type=str,
    help="Where to output JSON objects.",
)
args = parser.parse_args()

if not os.path.isdir(args.tmpdir):
    os.mkdir(args.tmpdir)
if not os.path.isdir(args.outdir):
    os.mkdir(args.outdir)


def getFiletype(filename: str) -> str:
    """
    Checks whether the provided file is a Macho-O, 7-zip, or Zip.
    Argument: a filename to check
    Return: one of selected filetypes
    """
    filetype = magic.from_file(filename)
    if "Mach-O" in filetype:
        return "Macho"
    elif "7-zip" in filetype:
        return "7zip"
    elif "Zip" in filetype:
        return "Zip"


def unzipFile(filename: str):
    """
    Extracts zip files to the specified output directory
    Argument: a zip filename to extract
    """
    try:
        myzip = zipfile.ZipFile(filename)
    except zipfile.BadZipFile:
        pass
    for password in args.passwords:
        try:
            myzip.extractall(path=args.tmpdir, pwd=bytes(password, "ascii"))
            break
        except:
            print(f"Failed to extract {filename} with {password}")


def un7zipFile(filename: str):
    """
    Extracts 7zip files to the specified output directory
    Argument: a 7zip filename to extract
    """
    try:
        myzip = py7zr.SevenZipFile(filename)
    except:
        pass
    for password in args.passwords:
        try:
            myzip.extractall(path=args.tmpdir, password=bytes(password, "ascii"))
            break
        except:
            print(f"Failed to extract with {password}")


def getFiles(path: str, file_list: list):
    """
    Walk a given path and add Mach-O, Zip, or 7-Zip files to the appropriate list
    Arguments: path - the directory to walk
               file_list - a list of lists
    """
    for root, dirs, files in os.walk(path):
        for filename in files:
            fullpath = os.path.join(root, filename)
            if not os.access(fullpath, os.R_OK):
                continue
            filetype = getFiletype(fullpath)
            if filetype == "Macho":
                file_list["machos"].append(fullpath)
            elif filetype == "Zip":
                file_list["zips"].append(fullpath)
            elif filetype == "7zip":
                file_list["7zips"].append(fullpath)


def extractZipLists(file_list: list):
    """
    Iterate through the lists containing zip files and extract them
    Argument: the list of lists containing the zips and 7zips lists.
    """
    for filegroup in file_list:
        for filename in file_list["zips"]:
            unzipFile(filename)
            file_list["zips"].remove(filename)
        for filename in file_list["7zips"]:
            un7zipFile(filename)
            file_list["7zips"].remove(filename)


def parseFiles(file_list: list):
    """
    Iterate the list of Mach-Os and call macholibre.parse against each file
    Argument: the list of lists with Mach-O files
    """
    for filename in tqdm(file_list["machos"], bar_format="{l_bar}{bar}"):
        json_file = os.path.basename(filename) + ".json"
        out_file = os.path.join(args.outdir, json_file)
        try:
            print(f"[ ] Parsing {filename}")
            data = parse(filename)
            data["filepath"] = filename
            with open(out_file, "w") as f:
                f.write(json.dumps(data))
        except:
            print(f"[-] Failed to parse {filename}")


if __name__ == "__main__":
    file_list = {}
    file_list["machos"] = []
    file_list["zips"] = []
    file_list["7zips"] = []
    getFiles(args.path, file_list)
    total_files = (
        len(file_list["machos"]) + len(file_list["zips"]) + len(file_list["7zips"])
    )
    print("Found {0} files".format(total_files))
    # extractZipLists(file_list)
    getFiles(args.tmpdir, file_list)
    print("Total malware: {0}".format(len(file_list["machos"])))
    parseFiles(file_list)
