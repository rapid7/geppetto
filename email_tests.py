from __future__ import print_function
from __future__ import division
from apiclient.http import MediaFileUpload
import argparse
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from googleapiclient.discovery import build
from httplib2 import Http
import datetime
import json
from oauth2client import file, client, tools
import os
import smtplib
import subprocess
from time import time

# If modifying these scopes, delete the file token.json.
SCOPES = 'https://www.googleapis.com/auth/drive.file'

def uploadFile(driveService, localFileName, remoteFileName, mimeType, remoteFolderID):
    file_metadata = {'name': remoteFileName,
                    'parents': [remoteFolderID]}
    media = MediaFileUpload(localFileName,
                            mimetype=mimeType)
    gfile = driveService.files().create(body=file_metadata,
                                    media_body=media,
                                    fields='id').execute()
    return gfile.get('id')
    
def getDriveFiles(driveService):
    results = driveService.files().list(
        pageSize=10, fields="nextPageToken, files(id, name)").execute()
    items = results.get('files', [])
    return items

def getCommitValue(commitFile):
    fileObj = open(commitFile, 'r')
    fileData = fileObj.read().split()
    fileObj.close()
    if len(fileData) > 1:
        return fileData[1]
    return None

def getCommitFile(testFolder):
    for root, dirs, files in os.walk(testFolder):
        for file in files:
            if 'commit' in file:
                return os.path.join(root, file)

def setupDriveService(tokenFile, credFile):
    store = file.Storage(tokenFile)
    creds = store.get()
    if not creds or creds.invalid:
        flow = client.flow_from_clientsecrets(credFile, SCOPES)
        creds = tools.run_flow(flow, store)
    service = build('drive', 'v3', http=creds.authorize(Http()))
    return service

def createRemoteFolder(driveService, folderName, parentID = None):
    body = {
        'name': folderName,
        'mimeType' : "application/vnd.google-apps.folder"}
    if parentID:
        body['parents'] = [parentID]
    newFolder = driveService.files().create(body = body).execute()
    return newFolder

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
        print("FAILED TO FIND JSON FILE " + fileName + "\n" + str(e))
        return retDict
    try:
        retDict = json.loads(jsonStr)
    except ValueError as f:
        print("FAILED TO PARSE JSON FILE " + fileName + "\n" + str(f))
    return retDict

def parseTableHtml(htmlString):
    startParse = htmlString.find('</table>\n<table border="1">\n') + 28
    endParse = htmlString.find('</table>\n</body>')
    return htmlString[startParse:endParse]

def parseTestData(htmlString):
    tableList = htmlString.split('<tr>')
    metadataList = []
    tableData = []
    for row in tableList:
        if '</td>' in row:
            # There's data in the row... parse it.
            rowData = row.split('</td>')
            if rowData[0].strip() == "":
                del(rowData[0])
            # get rid of closing tags 
            for index in range(len(rowData)):
                rowData[index] = rowData[index].replace('<td>', '').strip()
                rowData[index] = rowData[index].replace('</tr>', '').strip()
            if rowData[0] == 'TARGET':
                #metadata incoming
                for element in rowData:
                    metadataList.append(element.strip())
            else:
                # this should be the data
                rowDict = {}
                for index in range(len(metadataList)):
                    rowDict[metadataList[index]] = rowData[index]
                tableData.append(rowDict)
    return tableData

def generateEmailBody(testData, includedColumns):
    previousPayload = "NOT_A_PAYLOAD"
    emailBodyString = "<html>\n<body>\n<table border=\"1\">\n"
    emailBodyString = emailBodyString + "<tr>"
    for columnName in includedColumns:
        emailBodyString = emailBodyString + "<td>" + columnName + "</td>"
    emailBodyString = emailBodyString + "</tr>\n"
    commitVal = "UNKNOWN"
    for row in testData:
        if 'COMMIT' in row:
            commitVal = row['COMMIT']
            emailBodyString = emailBodyString + "<tr><td colspan=\"" + str(len(includedColumns)) + "\"><b>"
            emailBodyString = emailBodyString + "COMMIT = " + commitVal
            emailBodyString = emailBodyString + "</b></td></tr>"
        if 'PAYLOAD' in row:
            if row['PAYLOAD'].split('<br>')[0] != previousPayload.split('<br>')[0]:
                previousPayload = row['PAYLOAD']
                payloadData = row['PAYLOAD'].split("<br>")
                emailBodyString = emailBodyString + "<tr><td colspan=\"" + str(len(row)) + "\"><b>"
                emailBodyString = emailBodyString + payloadData[0]
                emailBodyString = emailBodyString + "</b></td></tr>"
        rowString = "<tr>"
        for columnName in includedColumns:
            if columnName in row:
                if '<td' in row[columnName]:
                    rowString = rowString + row[columnName] + "</td>"
                else:
                    rowString = rowString + "<td>" + row[columnName] + "</td>"
        rowString = rowString + "</tr>\n"
        emailBodyString = emailBodyString + rowString
    emailBodyString = emailBodyString + "</table>\n</body>\n</html>"
    return emailBodyString

def makeEmailString(emailData):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = emailData['subject']
    msg['From'] = emailData['fromAddress']
    msg['to'] = ','.join(emailData['toAddress'])
    text = "Results from testing"
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(emailData['body'], 'html')
    msg.attach(part1)
    msg.attach(part2)
    return msg.as_string()

def sendEmail(emailData):
    server_ssl = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    server_ssl.login(emailData['fromAddress'], emailData['password'])
    server_ssl.sendmail(emailData['fromAddress'], emailData['toAddress'], makeEmailString(emailData))
    return True

def uploadAndReplaceLinks(tableData, localTestFolder, gServiceObj, gFolderID):
    for unparsedRow in tableData:
        if 'SESSION' in unparsedRow:
            oldLinkData = str(unparsedRow['SESSION'])
            relativeFileName = oldLinkData[oldLinkData.find('=') + 1 :oldLinkData.find('>')].strip()
            absFileName = localTestFolder + relativeFileName[3:]
            shortFileName = relativeFileName.split('/')[-1]
            fileID = uploadFile(gServiceObj, absFileName, shortFileName, 'text/html', gFolderID)
            newLink = "https://drive.google.com/open?id=" + str(fileID)
            unparsedRow['SESSION'] = oldLinkData.replace(relativeFileName, newLink)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("testfile", help="json test file to use")
    args = parser.parse_args()
    # Get Config Data
    includedColumns = ['TARGET', 'MODULE', 'PAYLOAD', 'STATUS', 'SESSION']
    configDict = loadJson(args.testfile)
    emailData = {}
    emailData['fromAddress'] = configDict['email']['address']
    emailData['toAddress'] = configDict['email']['to']
    emailData['password'] = configDict['email']['password']
    emailData['port'] = configDict['email']['port']
    payloadTestDir = configDict['payloadTestDir']
    if 'subject' in configDict['email']:
        emailData['subject'] = configDict['email']['subject']
    else:
        emailData['subject'] = 'Testing Results for Metasploit'
    if 'branch' in configDict:
        frameworkBranch = ' -f ' + configDict['branch']
    else:
        frameworkBranch = ''
    testList = configDict['testList']
    gDriveService = setupDriveService(configDict['tokenFile'], configDict['credsFile'])
    timeStamp = str(datetime.date.today()) + '-' + str(time()).split('.')[0]
    remoteFolderName = "Metasploit-Payloads-" + timeStamp
    newFolderData = createRemoteFolder(gDriveService, remoteFolderName, configDict['gdriveFolder'])
    emailContents = []
    for testRun in testList:
        test = testRun['testConfig']
        for payload in testRun['payloadList']:
            try:
                if len(payload['opts']) > 0:
                    payloadOptions = ' -po ' + ','.join(payload['opts'])
                else:
                    payloadOptions = ''
                cmd = "python autoPayloadTest.py" + \
                frameworkBranch + \
                " -ss --payload " + payload['name'] + payloadOptions + " " + \
                " --verboseFilename " + os.path.abspath(test)
                testProc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, cwd=payloadTestDir)
                rawTestOutput = testProc.communicate()
                byteTestOutput = rawTestOutput[0]
                testOutput = byteTestOutput.decode('utf-8')
                fileName = testOutput.split(':')[1].rstrip().strip()
                localTestFolder = fileName.split('reports')[0]
                commitString = getCommitValue(getCommitFile(localTestFolder))
                testFile = open(fileName, 'r')
                testFileData = testFile.read()
                testFile.close()
                tableHtml = parseTableHtml(testFileData)
                tableData = parseTestData(tableHtml)
                uploadAndReplaceLinks(tableData, localTestFolder, gDriveService, newFolderData['id'])
                if tableData !=  None:
                    commitDict = {}
                    commitDict['COMMIT'] = commitString
                    emailContents.append(commitDict)
                    emailContents.extend(tableData)
            except Exception as e:
                pass
    emailBody = generateEmailBody(emailContents, includedColumns)
    emailData['body'] = emailBody
    failedTestCount = emailBody.count("FAILED")
    passedTestCount = emailBody.count("PASSED")
    emailData['subject'] = str(round((failedTestCount/(failedTestCount+passedTestCount))*100, 2)) + '% Failed on ' + emailData['subject']
    sendEmail(emailData)    
            
    testOutput = open('test.html', 'w')
    testOutput.write(emailBody)
    testOutput.close()
    uploadFile(gDriveService, 'test.html', 'results.html', 'text/html', newFolderData['id'])
if __name__ == "__main__":
    main()
    
