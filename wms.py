from __future__ import division
import sys
import os
import fnmatch
import re
import stat
import json
import datetime
import mimetypes
import subprocess
import string
import time
import hashlib
import math
import yara

VERSION = "1.0"

OUTPUT_FILE = ''
MATCHING_SIGNATURES = []
YARA_RULES = []
HASHTABLE = {}
SIGNATURES_PATH = ''

signaturesStats = {}

def GetApplicationPath(file=None):
    import re, os, platform
    if not hasattr(GetApplicationPath, "dir"):
        if hasattr(sys, "frozen"):
            dir = os.path.dirname(sys.executable)
        elif "__file__" in globals():
            dir = os.path.dirname(os.path.realpath(__file__))
        else:
            dir = os.getcwd()
        GetApplicationPath.dir = dir
    if file is None:
        file = ""
    if not file.startswith("/") and not file.startswith("\\") and (
            not re.search(r"^[\w-]+:", file)):
        path = GetApplicationPath.dir + os.sep + file
        if platform.system() == "Windows":
            path = re.sub(r"[/\\]+", re.escape(os.sep), path)
        path = re.sub(r"[/\\]+$", "", path)
        return path
    return str(file)

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def pmsg(msg, code = 'info', write_output = True):
    colorcode = bcolors.OKGREEN
    if code == 'warning':
        colorcode = bcolors.WARNING
    if code == 'error':
        colorcode = bcolors.FAIL
    print bcolors.OKBLUE + bcolors.UNDERLINE + ">>" + bcolors.ENDC + " " + colorcode + msg + bcolors.ENDC
    if write_output:
        datestring = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(OUTPUT_FILE, "a") as myfile:
            myfile.write("["+datestring+"] "+msg+"\n")

def progressBar(current, total, msg):
    i = (current / total) * 100
    if i > 100:
        i = 100
    if i < 0:
        i = 0

    sys.stdout.write("\r"+bcolors.OKBLUE + bcolors.UNDERLINE + ">>" + bcolors.ENDC + " " + bcolors.OKGREEN + msg + " (%d%%)" % i)
    sys.stdout.flush()

    if i == 100:
        sys.stdout.write("\n")
        sys.stdout.flush()

def checksum(fname):
    hash = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash.update(chunk)
    return hash.hexdigest()

def isText(filename):
    s=open(filename).read(512)
    text_characters = "".join(map(chr, range(32, 127)) + list("\n\r\t\b"))
    _null_trans = string.maketrans("", "")
    if not s:
        # Empty files are considered text
        return True
    if "\0" in s:
        # Files with null bytes are likely binary
        return False
    # Get the non-text characters (maps a character to itself then
    # use the 'remove' option to get rid of the text characters.)
    t = s.translate(_null_trans, text_characters)
    # If more than 30% non-text characters, then
    # this is considered a binary file
    if float(len(t))/float(len(s)) > 0.30:
        return False
    return True

def FileScan(WebPath):

    totalFiles = 0
    totalScanned = 0
    totalPermissionsScanned = 0

    results = []

    def infectedFound(filename, details):
        result = {
            'filename': filename,
            'details': details
        }
        return result

    for root, dirnames, filenames in os.walk(WebPath):
        for filename in filenames:
	    if root.find("/.git/") > -1:
	        continue
	    if filename == 'zxcvbn.js':
	        continue
            totalFiles += 1

    for root, dirnames, filenames in os.walk(WebPath):
        for filename in filenames:
	    if root.find("/.git/") > -1:
	        continue
	    if filename == 'zxcvbn.js':
	        continue

            totalScanned += 1
            progressBar(totalScanned, totalFiles, "Scanning "+str(WebPath)+" for malwares...")

            malware = False

            currentfile = os.path.join(root, filename)

            fileHandle = open(currentfile, 'rb')
            fileData = fileHandle.read()

            hash = hashlib.md5()
            hash.update(fileData)
            currentchecksum = hash.hexdigest()
            if currentchecksum in HASHTABLE:
                malware = str(HASHTABLE[currentchecksum])
                results.append(infectedFound(currentfile, malware))

            if isText(currentfile):
                for rules in YARA_RULES:
                    try:
                        result = rules.match(data=fileData)
                        if result:
                            for rule in result:
                                results.append(infectedFound(currentfile, str(rule).replace("_", " ")))
                    except:
                        pass

    # Scan for insecure permissions
    folders = [x[0] for x in os.walk(WebPath)]
    for folder in folders:
        if os.path.isdir(folder):
            totalPermissionsScanned += 1
            progressBar(totalPermissionsScanned, totalFiles, "Scanning "+str(WebPath)+" for insecure permissions...")

            mode = oct(stat.S_IMODE(os.stat(folder).st_mode))
            mode = str(mode)
            if mode.endswith('7') or mode.endswith('6') or mode.endswith('3') or mode.endswith('2'):
                results.append(infectedFound(folder, "Insecure permissions ("+str(mode)+")"))

    progressBar(totalFiles, totalFiles, "Scanning "+str(WebPath)+" for insecure permissions...")

    for result in results:
        pmsg("Scan result for file "+str(result["filename"])+" : "+str(result["details"]))

    pmsg("Scan completed and found "+str(len(results))+" potential problems.")

    sys.exit()

def LoadSignatures():
    # Load signatures for PHP files
    totalDatabases = 0
    loadedDatabases = 0

    for root, dirnames, filenames in os.walk(SIGNATURES_PATH):
        for filename in filenames:
            totalDatabases += 1

    for root, dirnames, filenames in os.walk(os.path.join(SIGNATURES_PATH, "checksum")):
        for filename in fnmatch.filter(filenames, '*.json'):
            try:
                loadedDatabases += 1
                dbdata = open(os.path.join(root, filename)).read()
                signatures = json.loads(dbdata)

                for signatureHash in signatures["Database_Hash"]:
                    HASHTABLE[signatureHash["Malware_Hash"]] = signatureHash["Malware_Name"]

                progressBar(loadedDatabases, totalDatabases, "Loading signature database...")
            except:
                pass

    yara_databases = 0
    for root, dirnames, filenames in os.walk(os.path.join(SIGNATURES_PATH, "rules")):
        for filename in fnmatch.filter(filenames, '*.yar'):
            try:
                loadedDatabases += 1
                filepath = os.path.join(root, filename)
                rules = yara.compile(filepath=filepath)
                YARA_RULES.append(rules)
                yara_databases += 1
                progressBar(loadedDatabases, totalDatabases, "Loading signature database...")
            except:
                pass

    progressBar(totalDatabases, totalDatabases, "Loading signature database...")

    pmsg("Loaded "+str(len(HASHTABLE))+" malware hash signatures.")
    pmsg("Loaded "+str(yara_databases)+" YARA ruleset databases.")

if len(sys.argv) == 3:
    WebPath = sys.argv[1]
    OUTPUT_FILE = sys.argv[2]

    SIGNATURES_PATH = os.path.join(GetApplicationPath(), 'signatures')

    pmsg("Starting OWASP Web Malware Scanner version "+str(VERSION)+"...")

    if os.path.isdir(SIGNATURES_PATH):
        LoadSignatures()
    else:
        pmsg("Unable to find signatures folder, please check installation.", 'error', False)
        sys.exit()

    if os.path.isdir(WebPath):
        FileScan(WebPath)
    else:
        pmsg("Unable to find target folder, please check input.", 'error', False)
        sys.exit()

else:
    pmsg("Usage: wms.py /path/to/website /path/to/results/output", 'info', False)
    sys.exit()
