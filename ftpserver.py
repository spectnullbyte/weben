import ftplib

import settings

class Ftpserver():
    """ The Class for Ftp server enumeration """

    def __init__(self,mainParam,port):
        self.port = port
        self.server = mainParam.target
        self.settings = mainParam.settings
        self.directories = {}

    def enumeration(self):
        ftp = ftplib.FTP()
        ftp.connect(self.server,int(self.port))
        try:
            ftp.login()
        except:
            print("[-] Anonymous login was not successful")
        else:
            print("[+] Anonymous login is enabled")
            print("[+] Directory listing :")
            ftp.pwd()
            ftp.dir()
            i = 0
            first = True
            currentDirectory = '.'
            self.directories[i] = {'.':'.'} 
            while bool(self.directories[i]):
                self.directories[i+1] = {}
                first = False
                firstDirectory = True
                for parent,directory in self.directories[i].items():
                    if firstDirectory:
                        ftp.cwd(directory)
                        firstDirectory = False
                        currentDirectory = directory
                    else: 
                        ftp.cwd('..')
                        ftp.cwd(directory)
                        currentDirectory = directory
                    ftp.pwd()
                    ftp.dir()
                    listOfFiles = ftp.nlst()
                    for oneFile in listOfFiles:
                        try:    
                            ftp.cwd(oneFile)
                        except:
                            ftp.retrbinary(f"RETR {oneFile}",open(f"{oneFile}","wb").write)
                            print(f"[+] {oneFile} was successfully saved to the current directory")
                        else:
                            ftp.cwd('..')
                            self.directories[i+1][currentDirectory]=oneFile
                            print(f"[+] {oneFile} is a directory")     
                i += 1
