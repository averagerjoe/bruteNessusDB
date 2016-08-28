# Joe McGrath
# 8/22/2016
#

import sys
import requests
import json
import os.path

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

port = ":8834"
wordListPath = ""
nessusdbPath = ""
nessusIP = ""
username = ""
password = ""


# importScan() takes in the uploaded filename, authentication token, and password to try importing with
# if unsuccessful, nothing happens
# if successful a message is printed showing the password and we exit
def importScan(filename, token, password):

	#print ""
	#print "Importing {0} ...".format(filename)
	#print "with password = " + password
	#print ""

	importURL = "https://" + nessusIP + port + "/scans/import"
	importHeadersToken = {'X-Cookie':'token='+token,'Content-Type': 'application/json'}


	filePayload = json.dumps({'password':password, 'file':filename})
	
	
	try:
		importResponse = requests.post(importURL, headers=importHeadersToken, data=filePayload, verify=False)
	except:
		print "Error importing file: {0}.".format(filename)
		sys.exit(0)


	if("scan" in importResponse.text):
		print ""
		print ""
		print "Import Successful with password '" + password + "'"
		print ""
		sys.exit(0)
	

	#print importResponse.text

# upload() takes in the filename to upload, file content and authenticaiton token
# this uploads the file to the Nessus server
# returns the uploaded fileName
# NOTE: after a certain amount of uploads, uploading causes an error
# -removeing the files off the server resolves the issue /opt/nessus/var/nessus/users/<username>/files
def upload(filename, content, token):

	#print ""
	print "Uploading {0}...".format(filename)
	#print ""

	uploadURL = "https://" + nessusIP + port + "/file/upload"

	uploadHeadersToken = {'X-Cookie':'token='+token}

	parameters = {'no_enc': 0}

	uploadData = {'Filename':(filename,filename), 'Filedata':(filename,content)}

	try: 
			uploadResponse = requests.post(uploadURL, headers=uploadHeadersToken, params=parameters, files=uploadData, verify=False)
	except:
		print "Error uploading file: {0}.".format(filename)
		sys.exit(0)


	response = json.loads(uploadResponse.text)

	#print ""
	#print response
	#print response["fileuploaded"]
	#print ""

	return response["fileuploaded"]



# login() does not take in any arguments
# authenticates with the nessus scanner
# returns the authentication token
def login():

	print ""
	print "Logging in...."
	#print ""

	nessusHost = "https://" + nessusIP + port

	loginUrl = nessusHost + "/session"

	dataCreds = {'username':username,'password':password}

	try:
		token = requests.post(loginUrl, data=dataCreds, verify=False)
	except:
		print "Error connecting to export Nessus host. Exiting"
		sys.exit(0)

	#print ""
	#print('Token: {0}.'.format(token.text))
	#print ""

	tokens = json.loads(token.text)

	try: 
		if(tokens["error"] != ""):
			print tokens["error"]
			print "Exiting..."
			sys.exit(0)	
	except KeyError:
		print "Login Successful!"
		#print ""
	
	return tokens

# verifyFiles() used to validate the files exist
# returns true if both files are available
# exits if an issue with any file
def verifyFiles():

	#print ""
	print "Verifying files..."
	#print ""

	if(os.path.isfile(wordListPath)):
		#print "wordList file exists"
		if(os.path.isfile(nessusdbPath)):
			#print "nessusdb file exists"
			return True
		else:
			print ""
			print "Nessusdb file does not exist."
			print "Exiting..."
			sys.exit(0)
	else: 
		print ""
		print "Word list file does not exist."
		print "Exiting..."
		sys.exit(0)

	return False


# main() - calls the rest of the functions
# 
def main():
	#1) Authenticate
	token = login()

	#2) verify wordListPath and nessusdbPath
	if(verifyFiles()):

		splitPath = nessusdbPath.split("/")
		filename = splitPath[-1]
		#print "This is the nessusdb filename: " + filename

		#3) upload scan file
		with open(nessusdbPath,'r') as f:
			uploadedFileName = upload(filename, f, token["token"])
			f.close()
		

		#4) open wordListPath for reading
		with open(wordListPath, 'r') as file:
			#5) loop and attempt import
			for pwLine in file:
				#strip out newline characters
				pwLineStrip = pwLine.strip('\n')
				
				importScan(uploadedFileName, token["token"], pwLineStrip)
			file.close()

			print ""
			print "File not successfully imported. Password unknown :("
			print ""






# validateArgs() - Takes in the arguments
# parses through the arguments to populate variables
# if not all variables are populated print message and exit
# otherwise return true
def validateArgs(arguments):

	global wordListPath
	global nessusIP
	global username
	global password
	global nessusdbPath

	for x in range(len(arguments)):
		#print "Argument = " + str(x)
		if(arguments[x] == "-w"):
			wordListPath = arguments[x+1]
		elif(arguments[x] == "-i"):
			nessusIP = arguments[x+1]
		elif(arguments[x] == "-u"):
			username = arguments[x+1]
		elif(arguments[x] == "-p"):
			password = arguments[x+1]
		elif(arguments[x] == "-n"):
			nessusdbPath = arguments[x+1]

	if(wordListPath == "" or nessusdbPath == "" or nessusIP == "" or username == "" or password == ""):
		print ""
		print "Please enter the correct arguments."
		print ""
		printExample()
		sys.exit(0)

	return True

# printHelp
# called when help menu is needed
def printHelp():
	print ""
	print "This is the bruteNessusDB help page."
	print ""
	print "There are a number of necessary arguments for this script."
	print "They are as follows: "
	print "-h Print this Help Page"
	print "-w </path/to/word/list>"
	print "-i <IPofNessusScanner>"
	print "-u <username>"
	print "-p <password>"
	print "-n </path/to/NessusdbFile>"
	print ""

# printExample
# called when example syntax is needed
def printExample():
	print ""
	print "For example:"
	print "python bruteNessusDB.py -u name -p pass -w /word/list/path -n /path/to/NessusdbFile -i 192.168.1.2"
	print ""

#print "Arguments Length = " + str(len(sys.argv))

if(len(sys.argv) == 2 and sys.argv[1] == "-h"):
	printHelp()
	printExample()
elif(len(sys.argv) < 11 or len(sys.argv) > 11):
	print ""
	print "Please enter the proper number of arguments."
	print ""
	printExample()
elif(len(sys.argv) == 11):
	#validate input
	if(validateArgs(sys.argv)):
		main()
else: 
	print ""
	print "Please eneter valid number of arguments or -h for the help page."
	print ""
