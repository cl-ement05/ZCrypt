import utils.miscs as miscs
import utils.settings as settings

import requests
import urllib.request as urlr
import os
from printy import printy, inputy

manifestAddress = "https://github.com/cl-ement05/ZCrypt/releases/latest/download/manifest.json"
ZCryptMinorVersion = "1"
ZCryptMajorVersion = "4"
ZCryptVersionName = "ZCrypt V4.1"

def downloadFile(fileUrl: str, fileName: str, fileExtension: str) :
    fileToSave = miscs.askFilename(fileName + fileExtension, "Please enter a filename that is currently NOT assigned to any file in this directory", fileExtension)
    printy("Info : Downloading " + fileToSave, "c")
    downloadedFile = urlr.urlopen(fileUrl).read()
    with open(fileToSave, "wb") as fileToWrite :
        fileToWrite.write(downloadedFile)
    printy("Success : " + fileToSave + " was downloaded", "n")
    return fileToSave

def checkForUpdates() :
    try :
        req = requests.get(manifestAddress)
        manifestData = req.json()['ZCrypt']
    except :
        printy("Warning : there was an error while fetching ZCrypt online manifest. Maybe your device is offline", "y")
        printy("Warning : since latest information about ZCrypt could not be fetched, ZCrypt won't check for updates", "y")
        return None
    else :
        latestMajorVersion, latestMinorVersion = manifestData['versionCode'].split(".")
        if int(latestMajorVersion) > int(ZCryptMajorVersion) :
            printy("A new major update has been released for ZCrypt !", "c")
            printy("Warning : changing between major versions means API change. If you install this new version, you will NOT be able to decrypt messages encrypted with another major version number", "y")
            printy("Info : You are currently running " + ZCryptVersionName + " and latest version (which can be downloaded) is " + manifestData['versionName'], "n")
            return manifestData
        elif int(latestMajorVersion) == int(ZCryptMajorVersion) and int(latestMinorVersion) > int(ZCryptMinorVersion) :
            printy("Info : A new update is available for ZCrypt !", "c")
            printy("You are currently running " + ZCryptVersionName + " but you can update it to " + manifestData['versionName'], "c")
            return manifestData
        else :
            printy("Info : ZCrypt is up to date", "c")
            return None

def update(manifestData, settingsVar) :
    answer = inputy("Do you want to install " + manifestData['versionName'] + " ? (Y/n) ", "c")
    if answer.lower() != "n" :
        try :
            savedFile = downloadFile(manifestData['download'], "newZCrypt", ".py")
            printy("ZCrypt will now quit. Please run the new version file")
            settingsVar['deleteOld'] = os.path.basename(__file__) + "|" + savedFile
            settings.writeSettings(settingsVar)
        except :
            printy("Error : " + manifestData['versionName'] + " could not be downloaded. Are you connected to the internet ?", "m")
            return False
        else :
            return True
    else : return False
