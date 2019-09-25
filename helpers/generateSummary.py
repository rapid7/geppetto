from __future__ import print_function
from __future__ import division
import argparse
import glob
import json
import os


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


def parseTestData(htmlString, linkPath=None):
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
    for dataRow in tableData:
        if linkPath is not None and dataRow['SESSION'] is not None:
            dataRow['SESSION'] = dataRow['SESSION'].replace('../', './' + linkPath + '/')
    return tableData


def generateReportBody(testData, includedColumns):
    previousPayload = "NOT_A_PAYLOAD"
    reportBodyString = "<html>\n<body>\n<table border=\"1\">\n"
    reportBodyString += "<tr>"
    for columnName in includedColumns:
        reportBodyString += "<td>" + columnName + "</td>"
    reportBodyString += "</tr>\n"
    for row in testData:
        if 'COMMIT' in row:
            commitVal = row['COMMIT']
            reportBodyString += "<tr><td colspan=\"" + str(len(includedColumns)) + "\"><b>"
            reportBodyString += "COMMIT = " + commitVal
            reportBodyString += "</b></td></tr>"
        if 'PAYLOAD' in row:
            if row['PAYLOAD'].split('<br>')[0] != previousPayload.split('<br>')[0]:
                previousPayload = row['PAYLOAD']
                payloadData = row['PAYLOAD'].split("<br>")
                reportBodyString += "<tr><td colspan=\"" + str(len(row)) + "\"><b>"
                reportBodyString += payloadData[0]
                reportBodyString += "</b></td></tr>"
        rowString = "<tr>"
        for columnName in includedColumns:
            if columnName in row:
                if '<td' in row[columnName]:
                    rowString += row[columnName] + "</td>"
                else:
                    rowString += "<td>" + row[columnName] + "</td>"
        rowString += "</tr>\n"
        reportBodyString += rowString
    reportBodyString += "</table>\n</body>\n</html>"
    return reportBodyString


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("resultPath", help="path to folder containing geppetto results to aggregate")
    args = parser.parse_args()
    includedColumns = ['TARGET', 'MODULE', 'PAYLOAD', 'STATUS', 'SESSION']
    reportData = {'subject': 'Testing Results for Metasploit'}
    reportContents = []
    for os_dir in os.listdir(args.resultPath):
        if os.path.isdir(os.path.join(args.resultPath, os_dir)):
            try:
                currentDir = os.getcwd()
                os.chdir(os.path.join(args.resultPath, os_dir, "reports"))
                htmlFiles = glob.glob('*.html')
                fileName = htmlFiles[0]
                os.chdir(currentDir)
                localTestFolder = os.path.join(args.resultPath, os_dir)
                commitString = getCommitValue(getCommitFile(localTestFolder))
                testFile = open(os.path.join(args.resultPath, os_dir, "reports", fileName), 'r')
                testFileData = testFile.read()
                testFile.close()
                tableHtml = parseTableHtml(testFileData)
                tableData = parseTestData(tableHtml, linkPath=os_dir)
                if tableData is not None:
                    commitDict = {'COMMIT': commitString}
                    reportContents.append(commitDict)
                    reportContents.extend(tableData)
            except Exception as e:
                pass
    reportBody = generateReportBody(reportContents, includedColumns)
    reportData['body'] = reportBody
    failedTestCount = reportBody.count("FAILED")
    passedTestCount = reportBody.count("PASSED")
    reportData['subject'] = str(round((failedTestCount/(failedTestCount+passedTestCount))*100, 2)) + '% Failed on ' + reportData['subject']

    os.chdir(args.resultPath)
    testOutput = open('subject.txt', 'w')
    testOutput.write(reportData['subject'])
    testOutput.close()

    testOutput = open('index.html', 'w')
    testOutput.write(reportData['body'])
    testOutput.close()


if __name__ == "__main__":
    main()
