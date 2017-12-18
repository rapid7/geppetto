##############################################################
#
# THIS IS A WRAPPER SCRIPT FOR autoPayloadTest.py
# IT TAKES IN A TEST FILE WITH PAYLOADS AND RUNS THEM
# INDIVIDUALLY AGAINST A COMMON CONFIG FILE
# RUN THIS IN THE SAME FOLDER AS autopayloadTtest.py
#
#############################################################

import argparse
import subprocess

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-pf", "--payloadfile", help="Text file with payloads to use")
    parser.add_argument("-v", "--verbose", help="Echo test result to console", action="store_true")
    parser.add_argument("-f", "--framework", help="Framework branch to use (Overrides testfile)")
    parser.add_argument("-m", "--module", help="Module to use")
    parser.add_argument("testfile", help="json test file to use")
    args = parser.parse_args()
    
    try:
        payloadFileObj = open(args.payloadfile)
        payloadList = payloadFileObj.readlines()
        payloadFileObj.close()
    except IOError as e:
        print("FAILED TO OPEN OR READ " + args.payloadfile + "\n" + str(e))
    
    if args.framework != None:
        frameworkOption = " -f " + args.framework
    else:
        frameworkOption = ""

    if args.module != None:
        moduleOption = " -m " + args.module
    else:
        moduleOption = ""

    if args.verbose != None:
        verboseOption = " -v "
    else:
        verboseOption = ""

    cmdList = []
    for payload in payloadList:
        cmdString = "python autoPayloadTest.py -p " + payload.strip() + " " + args.testfile.strip()
        cmdString = cmdString + frameworkOption
        cmdString = cmdString + moduleOption
        cmdString = cmdString + verboseOption
        cmdList.append(cmdString)
    failures = 0
    for cmd in cmdList:
        print cmd
        if subprocess.call(cmd.split()) == 0:
            print("PASSED")
        else:
            failures += 1
            print("FAILED")
    if failures > 0:
        exit(1)
    
if __name__ == "__main__":
    main()
