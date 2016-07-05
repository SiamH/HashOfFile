import hashlib
import glob
import os
import math
import pefile
import peutils
import re
import zlib
import ssdeep

def getEntropy(data):
    """Calculate the entropy of a chunk of data."""

    if not data:
        return 0

    entropy = 0
    for x in range(256):
        ctr = 0
        for byte in data:
            if byte == chr(x):
                ctr += 1

        p_x = float(ctr)/len(data)
        if p_x > 0:
          entropy += - p_x*math.log(p_x, 2)

    if entropy > 6:
        return "Packed"
    return "Not Packed"

def FindKeyLoggers(data):
       if not data:
           return 0

       # Lots taken from the wonderful post at http://stackoverflow.com/questions/3115559/exploitable-php-functions
       valid_regex = re.compile('GetAsyncKeyState|Up|Num Lock|Down|Right|Left|PageDown', re.I)
       matches = re.findall(valid_regex, data)
       return len(matches)


def FindPrivilegeTokenCode(data):
       if not data:
           return 0

       # Lots taken from the wonderful post at http://stackoverflow.com/questions/3115559/exploitable-php-functions
       valid_regex = re.compile('OpenProcessToken|LookupPrivilegeValue|AdjustTokePrivilege|PROCESS_ALL_ACCESS|ReadProcessMemory', re.I)
       matches = re.findall(valid_regex, data)
       return len(matches)

def FindLongestWord(data):
       """Find the longest word in a string and append to longestword_results array"""
       if not data:
           return "", 0
       longest = 0
       longest_word = ""
       words = re.split("[\s,\n,\r]", data)
       if words:
           for word in words:
               length = len(word)
               if length > longest:
                   longest = length
                   longest_word = word
       return longest

def SearchMaliciousTokens(data):
       if not data:
           return 0

       # Lots taken from the wonderful post at http://stackoverflow.com/questions/3115559/exploitable-php-functions
       valid_regex = re.compile('(eval\(|file_put_contents|base64_decode|python_eval|exec\(|passthru|popen|proc_open|.url|pcntl|assert\(|system\(|shell)', re.I)
       matches = re.findall(valid_regex, data)
       return len(matches)


def CompressionRatio(data):
       if not data:
           return "", 0
       compressed = zlib.compress(data)
       ratio = float(len(compressed)) / float(len(data))
       return ratio


def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)

    return hash_md5.hexdigest()

target = open("OutputMachine1.txt", 'w')

sWindowsFilePath = "C:/Windows/System32/"
FilePattern = ['exe', 'doc', 'zip', 'JPG', 'mp3', 'pdf']

for pattern in FilePattern:
    patternregex = '*.' + pattern
    for current_file in glob.iglob(sWindowsFilePath + patternregex):
        # Load PE File ..
        pe = pefile.PE(current_file)

        # Displays same guessed results as PEiD -> Extra information -> Entropy ..
        "e = getEntropy( pe.__data__ )"
        "i = CompressionRatio(pe.__data__)"

        file_name = current_file[20:]
        line = file_name + ": "
        line += '\t' + md5(current_file)
        line += '\t' + str(os.path.getsize(current_file))
        line += '\t' + str(peutils.is_probably_packed(pe))
        line += '\t' + str(peutils.is_suspicious(pe))
        line += '\t' + ssdeep.hash_from_file(current_file)
        line += '\t' + getEntropy( pe.__data__ )
        line += '\t' + str(CompressionRatio(pe.__data__))
        target.write(line)
        target.write('\n')

target.close()
