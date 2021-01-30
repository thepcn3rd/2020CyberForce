#!/usr/bin/python3

# defenderCheck.py
#
# This breaks up a python script and runs it against mpCmdRun through a WinRM session.  If it detects a signature
# the file comes back as not being copied and a signature detected
#
# In the main function you specify the file you want to analyze, winrm creds (warning plaintext), and the lines at a time you want analyzed.
# Check the output.log to determine which segment was detected and the next with the clean detection.
# Re-analyze the signature detected until you identify the line or lines triggering the signature detection
#


import os
import random
import time


def submitDefender(fA, u, p, b, l):
    initialRandom = random.randint(0,100000)
    secondRandom = random.randint(5,200000)
    # fA - File being Analyzed
    # u - Useraccount being accessed
    # p - Password being passed (plain text)
    # b - Computer name of box
    # l - Lines to Analyze
    # Location where the temporary powershell script is created
    print("\n")
    print("Working with file: " + fA)
    scriptPath = "/home/kali/defenderCheck/sd.ps1"
    # Introduced a delay so the powershell script would terminate, this decreases false positives
    time.sleep(3)
    f = open(scriptPath, "w")
    log = open("output.log", "a")
    f.write("#!/usr/bin/pwsh\n")
    f.write("$pw = Convertto-Securestring -AsPlainText -Force -String \"" + p + "\"\n")
    f.write("$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist \"" + u + "\",$pw" + "\n")
    f.write("$s = New-PSSession -Computername " + b + " -Authentication Negotiate -Credential $cred\n")
    #f.write("Invoke-Command -Session $s { Remove-Item \"c:\\users\\thepcn3rd\\sigtest\\sample.file*\" }\n")
    # Does not allow the copy of the file if a virus signature is detected...
    f.write("Invoke-Expression 'Copy-Item -ToSession $s -Path \"" + str(fA) + "\" -Destination \"C:\\Users\\" + u + "\\sigTest\\sample.file_" + str(initialRandom) + "_" + str(secondRandom) + ".ps1\"' -ErrorVariable errVar\n")
    f.write("$errVar | Out-File error.txt\n\n")
    f.write("Invoke-Command -Session $s { Invoke-Expression 'cd \"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2011.6-0\\\"; .\\MpCmdRun.exe -Scan -ScanType 3 -File \"C:\\users\\thepcn3rd\\sigtest\\sample.file_" + str(initialRandom) + "_" + str(secondRandom) + ".ps1\" -DisableRemediation -Trace -Level 0x10' }\n")
    f.close()
    os.system("chmod 700 " + scriptPath)
    os.system(scriptPath)
    if os.path.exists("/home/kali/defenderCheck/error.txt"):
        result = checkError()
        os.system("rm -f /home/kali/defenderCheck/error.txt")
    else:
        result = "Clean"
    if result == "Clean":
        print("File: " + str(fA) + " Result: Clean")
        log.write("File: " + str(fA) + " Result: Clean\n")
    elif result == "Detected" and "segment" not in str(fA):
        print("File: " + str(fA) + " Result: Signature Detected")
        log.write("File: " + str(fA) + " Result: Signature Detected\n")
        #createSegments(fA, l) # Analyzes blocks of code splitup
        analyzeSegments(fA, l) # Analyzes (Size of file minus 1000 lines to see if it triggers)
    elif result == "Detected" and "segment" in str(fA):
        print("File: " + str(fA) + " Result: Signature Detected")
        log.write("File: " + str(fA) + " Result: Signature Detected\n")
    elif result == "Clean" and "segment" in str(fA):
        print("File: " + str(fA) + " Result: Clean")
        log.write("File: " + str(fA) + " Result: Clean\n")
    else:
        print("File: " + str(fA) + " Result: Clean")
        log.write("File: " + str(fA) + " Result: Clean\n")
    log.close()



def checkError():
    if (os.path.exists("/home/kali/defenderCheck/error.txt")):
        f = open("/home/kali/defenderCheck/error.txt", "r")
        for line in f:
            if "MI_RESULT_FAILED" in line or "Failed to copy file":
                return "Detected"
    else:
        return "Clean"
    return "Clean"


def createSegments(fA, lines):
    #global winrmusername
    #global winrmpassword
    #global box
    # fA - File being analyzed
    # lines - Number of lines per file segment
    lineCount = 0
    segmentCount = 0
    # Open file to be analyzed
    f = open(fA, "r")
    for line in f:
        if lineCount == 0:
            # Open Segment File
            fileSegmentName = "/home/kali/defenderCheck/segments/segment" + str(segmentCount) + ".segment"
            fileSegment = open(fileSegmentName, "w")
            fileSegment.write(line.strip() + "\n")
            lineCount += 1
        elif lineCount == lines:
            fileSegment.write(line.strip() + "\n")
            fileSegment.close()
            submitDefender(fileSegmentName, winrmusername, winrmpassword, box, linesToAnalyze)
            lineCount = 0
            segmentCount += 1
        else:
            fileSegment.write(line.strip() + "\n")
            lineCount += 1
    if lineCount > 0:
        fileSegment.write(line.strip() + "\n")
        fileSegment.close()
        submitDefender(fileSegmentName, winrmusername, winrmpassword, box)
    f.close()
        
def analyzeSegments(fA, lines):
    # Looking at ThreatCheck done by RastaMouse he analyzes the file and increases the size of it until it is triggered.
    # References: https://github.com/rasta-mouse/ThreatCheck/blob/master/ThreatCheck/ThreatCheck/Defender/Defender.cs
    #global winrmusername
    #global winrmpassword
    #global box
    # fA - File being analyzed
    # lines - Number of lines per file segment
    totalLineCount = 0
    placeholderLineCount = 0
    segmentCount = 0
    # Open file to be analyzed
    f = open(fA, "r")
    for line in f:
        totalLineCount += 1
    placeholderLineCount = totalLineCount - lines
    f.close()
    while placeholderLineCount > 0:
        lineCount = 0
        f = open(fA, "r")
        # Open Segment File for Progressive Growth
        fileSegmentName = "/home/kali/defenderCheck/segments/segmentP" + str(placeholderLineCount) + ".segment"
        fileSegment = open(fileSegmentName, "w")
        for line in f:
            fileSegment.write(line.strip() + "\n")
            if lineCount > placeholderLineCount:
                break
            lineCount += 1
        f.close()
        fileSegment.close()
        submitDefender(fileSegmentName, winrmusername, winrmpassword, box, linesToAnalyze)
        placeholderLineCount -= lines

        


def main():
    #fileToAnalyze = "/home/kali/defenderCheck/files/powerView.ps1"
    fileToAnalyze = "/home/kali/defenderCheck/files/P9614.ps1"
    global winrmusername
    winrmusername = "winrmuser"
    global winrmpassword
    winrmpassword = "winrmpass"
    global box
    box = "Win10"
    global linesToAnalyze
    linesToAnalyze = 1000
    submitDefender(fileToAnalyze, winrmusername, winrmpassword, box, linesToAnalyze)





if __name__ == "__main__":
    main()
