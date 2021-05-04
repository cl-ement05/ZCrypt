from datetime import datetime
from calendar import day_name
from random import randint
import base64 as b64
import requests
import os
import sys

Error_Code = str()

defaultSettings = {
    "fileOutput" : "Mail.txt",
    "dateFormat" : '1',
    "warnBeforeOW" : True,
    "outModeDecrypt" : 0,
    "encryptionMode" : "ask",
    "rsaKeyBytes" : 1024,
    "checkForUpdates" : "atStart"
}
manifestAddress = "https://raw.githubusercontent.com/cl-ement05/ZCrypt/master/manifest.json"
ZCryptMinorVersion = "0"
ZCryptMajorVersion = "4"
ZCryptVersionName = "ZCrypt V4.0"

errorsDict = {
    "E101" : "OS-level error : your file does not exist, is corrupted or cannot be read (check permissions)",
    "E201" : "File not matching ZCrypt requirements : the file's length does not match the length ZCrypt expected",
    "E202" : "File not matching ZCrypt requirements : one or more lines couldn't be read (convert to string/bytes impossible due to unknow character type)",
    "E211" : "File not matching ZCrypt requirements : the first line (which contains timestamp) couldn't be read OR is less or more than 43 characters long",
    "E214" : "File not matching ZCrypt requirements : the fourth line does not match zcrypt format requirements",
    "E215" : "File not matching ZCrypt requirements : the fith line which contains the whole message couldn't be converted to an integer"
}

lastKey = randint(35, 100)                                            #This line runs just once, at the programm start because the encryption module needs the last key (and there is no last key at the first time)

def ZfileCheck() -> bool :
#All this section checks the file integrity and assings all the lines to a dynamic variable
    global line1
    global line2
    global line3
    global line4
    global line5
    global Error_Code

    try :
        file = open(file_name, 'r+')
    except FileNotFoundError :
        Error_Code = "E101"
        return False

    else :
        text = file.readlines()

        # Checks if the file has 5 lines
        if len(text) > 5 or len(text) < 5 :
            Error_Code = "E201"
            return False

        #Assigns a variable name with the line number to each element (line) in the file
        line1 = text[0][:-1]
        line2 = text[1][:-1]
        line3 = text[2][:-1]
        line4 = text[3][:-1]
        line5 = text[4][:-1]

        try :
            assert type(line1) == str
            assert type(line2) == str
            assert type(line3) == str
            assert type(line4) == str
            assert type(line5) == str
        except AssertionError :
            Error_Code = "E202"
            return False


        if len(line1) == 42 :
            try :
                int(line1[:42])
            except ValueError :
                Error_Code = "E211"
                return False
        else :
            Error_Code = "E211"
            return False

        if "b" in line4 :
            try :
                int(line4[:8], 2)
                int(line4[9:15])
            except ValueError :
                Error_Code = "E214"
                return False
        else :
            Error_Code = "E214"
            return False

        try :
            int(line5)
        except ValueError :
            Error_Code = "E215"
            return False

    return True

def RfileCheck() :
    global line1
    global line2
    global line3
    global line4
    global line5
    global Error_Code

    try :
        file = open(file_name, 'rb+')
    except FileNotFoundError :
        Error_Code = "E101"
        return False

    else :
        currentByte = file.read(1)
        lines = list()
        currentLine = bytes()

        while currentByte != b"" :
            string = currentByte.decode("utf8")
            if string == "|" :
                lines.append(currentLine)
                currentLine = bytes()
            else :
                currentLine += currentByte
            currentByte = file.read(1)

        try :
            assert len(lines) == 4
        except AssertionError :
            Error_Code = "E201"
            return False

        line1 = b64.b64decode(lines[0])
        line2 = b64.b64decode(lines[1])
        line3 = b64.b64decode(lines[2])
        line5 = b64.b64decode(lines[3])
        line4 = None      #since no key is stored on line 4 when using RSA crypt mode, not defining line4 could raise a NameError not defined so assigning None value
        return True


#Here all functions are defined
#Gets the key which is encrypted in binary
def ZretrieveKey() :
    global keyMethod, decryptKey, limitHigh, limitLow

    keys = line4
    decryptKey = int(keys[:8], 2)
    if decryptKey % 2 == 0 :
        keyMethod = 'plus'
    else :
        keyMethod = 'minus'

    limitLow, limitHigh = int(keys[9:11]), int(keys[11:14])

def RretrieveKey() :
    printy("In order to decrypt a message that was encrypted with RSA, a private key is needed", "c")
    printy("If you saved it when encrypting your message, the private key specs will be automatically retrieved", "c")
    printy("Otherwise you will need to provide each value", "c")

    print("Do you have your private key saved in a file ? (Y/n) ", end = "")
    if input("").lower() == "n" :
        n = input("Please enter the N value of your privKey : ")
        e = input("Please enter the e value of your privKey : ")
        d = input("Please enter the d value of your privKey : ")
        p = input("Please enter the p value of your privKey : ")
        q = input("Please enter the q value of your privKey : ")
    else :
        fileNameInput = input("Please enter the COMPLETE name of the file which contains the private key (must end with .txt) : ")
        try :
            file = open(fileNameInput, "r")
            keys = file.readlines()
            try :
                assert len(keys) == 5
                n = int(keys[0])
                e = int(keys[1])
                d = int(keys[2])
                p = int(keys[3])
                q = int(keys[4])
            except (ValueError, AssertionError) :
                printy("Error : this file does not contain valid data", "m")
                return None

        except FileNotFoundError :
            printy("Error : this file does not exist", "m")
            return None

    try :
        privKey = rsa.PrivateKey(int(n), int(e), int(d), int(p), int(q))
    except ValueError :
        printy("Error : please make sure the numbers you entered are integers", "m")
        return None
    return privKey

#Encrypts the key
def ZcreateKey() :
    global keyNum, keyBin, lastKey, limitHigh, limitLow

    #creating new limits
    limitLow = randint(10, 31)
    limitHigh = randint(100, 255)

    keyNum = randint(limitHigh - 65, limitHigh - limitLow)
    #All this part tests if the current key is far enough from the last key
    while True :
        if abs(keyNum - lastKey) > 5 :
            break
        else :
            keyNum = randint(limitHigh - 65, limitHigh - limitLow)

    lastKey = keyNum
    keyBin = format(keyNum, '08b')

def RcreateKey() :
    global privKey, pubKey, keyBin
    printy("Info : generating RSA keys", 'c')
    (pubKey, privKey) = rsa.newkeys(int(settings['rsaKeyBytes']))
    printy("Warning : here are your private key specs. DO NOT SHARE THEM UNLESS YOU KNOW WHAT YOU ARE DOING !", 'y')
    print("PrivateKey N : ", privKey.n)
    print("PrivateKey e : ", privKey.e)
    print("PrivateKey d : ", privKey.d)
    print("PrivateKey p : ", privKey.p)
    print("PrivateKey q : ", privKey.q)
    printy("\nWarning : you will need to provide these numbers in order to decrypt your message", "y")
    printy("Since it is hard to remeber them, ZCrypt offers you an option to save them", "c")
    printy("Do you want to save your private key to a text file ? (Y/n) ", "c", end = ' ')
    answer = input("")
    if answer != "n" :
        fileName = askFilename("keys")
        printy("Info : saving private key...", "c")
        file = open(fileName, "w")
        file.write(str(privKey.n) + "\n")
        file.write(str(privKey.e) + "\n")
        file.write(str(privKey.d) + "\n")
        file.write(str(privKey.p) + "\n")
        file.write(str(privKey.q))
        file.close()
        printy("Success : saved private key specs to " + fileName, "n")



#All this part contains child functions used for encrypting
#Encrypting date and time
def encryptTime(mode) :
    finalTimeEncr = ''
    finalTimeList = list()
    now = datetime.now()
    currentTime = now.strftime("%d/%m/%Y %H:%M:%S")

    if mode == "z" :
        for element in currentTime :
            #This try is used to skip date characters like (/ and :) that will be removed in order to make decrypt easier to process (especially because of dateFormat)
            try :
                int(element)
            except ValueError :
                if element != '/' and element != ':' and element != ' ' :
                    printy("Error : unexpected error. Please try again", "m")
                    sys.exit()

            #If the try passes and the current element is an integer (so a number that is part from the date), encyption starts
            else :
                encryptedInt = int(element) + int(keyNum)
                finalTimeList.append(str(encryptedInt))
        finalTimeEncr = "".join(finalTimeList)
    else :
        return b64.b64encode(rsa.encrypt(
            currentTime.encode(),
            pubKey))


    assert len(finalTimeEncr) == 42
    return finalTimeEncr


#Encrypting sender
def encryptSender(mode, sender) :
    senderEncr = ''
    if mode =="z" :
        for letter in sender :
            senderAscii = ord(letter)
            senderEncr += ZmainEncrypt(senderAscii)
        return senderEncr
    else :
        return b64.b64encode(rsa.encrypt(
            sender.encode(),
            pubKey))

#Encrypts receiver
def encryptReciever(mode, receiver) :
    recieverEncr = ''
    if mode == "z" :
        for letter in receiver :
            recieverAscii = ord(letter)
            recieverEncr += ZmainEncrypt(recieverAscii)
        return recieverEncr
    else :
        return b64.b64encode(rsa.encrypt(
            receiver.encode(),
            pubKey))

#Main encrypt engine
def ZmainEncrypt(toEncrypt: int) -> str :             #takes a single int argument which must be the ascii representation of a char; returns the binary representation of the encrypted ascii
    #If the key is a pair number
    if keyNum % 2 == 0 :
        if toEncrypt - keyNum >= limitLow :
            encrypted = toEncrypt - keyNum

        else :
            cut = 0
            while toEncrypt >= limitLow :
                toEncrypt -= 1
                cut += 1
            remainingKey = keyNum - cut
            encrypted = limitHigh - remainingKey

    #If the key is an impair number
    elif keyNum % 2 == 1 :
        if toEncrypt + keyNum <= limitHigh :
            encrypted = toEncrypt + keyNum

        else :
            cut = 0
            while toEncrypt <= limitHigh :
                toEncrypt += 1
                cut += 1
            remainingKey = keyNum - cut
            encrypted = limitLow + remainingKey

    letterBinary = list()
    #If the Ascii number contains only two numbers, the programm adds a 0 in front oh the two to get a number with 3 binaires at the end
    if len(str(encrypted)) == 2 :
        letterBinary.append('00000000')
        for asciiNbr in range(2) :
            letterBinary.append(format(int(str(encrypted)[asciiNbr]), '08b'))

    elif len(str(encrypted)) == 3 :
        for asciiNbr in range(3) :
            letterBinary.append(format(int(str(encrypted)[asciiNbr]), '08b'))

    return ''.join(letterBinary)


# Crypting the message
def encryptMessage(mode, message_input) :
    finalMessageBinary = str()

    if mode == "z" :
        for letter in message_input :
            #Transforms the character in its ascii number
            asciiChr = ord(letter)
            letterBinary = ZmainEncrypt(asciiChr)

            finalMessageBinary += letterBinary

        printy("Info : Your key is : " + str(keyNum), 'c')
        return finalMessageBinary
    else :
        return b64.b64encode(rsa.encrypt(
            message_input.encode(),
            pubKey))


#Get all settings and encrypted variables from child functions and starts the writeFile function to apply changes
def prepareEncryptedOutput(cryptingMode: str) :

    if cryptingMode.lower() == "zcrypt" :
        mode = "z"
        printy("Info : entering ZCrypt encryption mode...", "c")
        ZcreateKey()                          #creates a new key shared accross whole program
        keyToWrite = keyBin + 'b' + str(limitLow) + str(limitHigh)

    else :
        mode = "RSA"
        printy("Info : entering RSA encryption mode...", "c")
        printy("Warning : decrypting RSA messages is only supported on ZCrypt V3.0+, make sure the receiver meets this requirement", "y")
        RcreateKey()
        print("")

    message_input = input("First, type the message you want to encrypt : ")
    sender = input("Please type your name that will be used in the file as the sender information : ")
    receiver = input("Finally, type the receiver of this message : ")

    finalMessageBinary = encryptMessage("z" if mode == "z" else "rsa", message_input)
    finalTimeEncr = encryptTime("z" if mode == "z" else "rsa")
    senderEncr = encryptSender("z" if mode == "z" else "rsa", sender)
    recieverEncr = encryptReciever("z" if mode == "z" else "rsa", receiver)

    fileOutput = settings['fileOutput']

    try :
        open(fileOutput, "r")            #opening in read mode the name specified by the user so that if a file with the same already exists, no error will be raised
    except FileNotFoundError :                         #else if an error is thrown, file was not found so no file will be overwritten -> writeFile
        writeFile(mode, finalTimeEncr, senderEncr, recieverEncr, keyToWrite if mode == "z" else None, finalMessageBinary)
    else :
        if settings['warnBeforeOW'] :                          #boolean setting 1 -> warn user that a file will be overwritten
            printy("Warning : " + fileOutput + " already exists", 'y')
            printy("Warning : if you continue the encryption process, the existing file will be overwritten", 'y')
            printy("Note : this operation cannot be undone", 'c')
            printy("Note : we highly recommend you to backup this file if personnal infos are stored on it", 'c')
            printy(fileOutput + " will be overwritten !!", 'y')
            printy("Are you sure you want to continue ? (y/N)", 'y', end = '')
            answer = input(" ").lower()
            if answer == "y" :
                writeFile(mode, finalTimeEncr, senderEncr, recieverEncr, keyToWrite if mode == "z" else None, finalMessageBinary)   #after user confirmation that file can be overwritten -> writeFile
            else :
                printy("Info : encryption aborted", 'c')

        #if the warning has been disabled
        else :
            writeFile(mode, finalTimeEncr, senderEncr, recieverEncr, keyToWrite if mode == "z" else None, finalMessageBinary)
            printy("Info : a file has been overwritten", "y")


#Write all encrypted content to the file using the settings prepared by the prepareEncryptedOutputt function
def writeFile(mode: str, *args: str or bytes) :
    #'\n' is used to go to a new line at every new file settings
    file_w = open(settings['fileOutput'], "w" if mode == "z" else "wb")
    if mode == "z" :
        for elementToW in args :
            if elementToW is not None : file_w.write(elementToW + "\n")
        file_w.close()
    else :
        for elementToW in args :
            if elementToW is not None : file_w.write(elementToW + '|'.encode("utf8"))
        file_w.close()

    printy("Success : your message has been securely encrypted !", 'n')


#All decrypt child functions
#Decrypts the date and time
def decryptTime(mode) :
    if mode == "z" :
        #Here, the entire line1 that contains the date is spread into different variables
        chSize = 3
        date = line1[:(chSize * 8)]
        time = line1[(chSize * 8):len(line1)]

        #Decrypting date
        dateDecr = str()
        for number in range(0, len(date), 3) :
            dateDecr += str(int(date[number] + date[number + 1] + date[number + 2]) - decryptKey)      #decrypting each digit with the key
                                #here we loop with a step of chSize since 1 decrypted digit -> chSize encrypted digits (depends of keyNum)
        #spreading decrypted date into different variables
        dayDecrypted = dateDecr[:2]
        monthDecrypted = dateDecr[2:4]
        yearDecrypted = dateDecr[4:]

        if len(str(dayDecrypted)) == 1 :
            nbr = str(dayDecrypted)[0]
            dayDecrypted = str(0) + str(nbr)

        if len(str(monthDecrypted)) == 1 :
            nbr = str(monthDecrypted)[0]
            monthDecrypted = str(0) + str(nbr)


        #Decrypting time (same as date)
        timeDecr = str()
        for number in range(0, len(time), 3) :
            timeDecr += str(int(time[number] + time[number + 1] + time[number + 2]) - decryptKey)

        hourDecrypted = timeDecr[:2]
        minDecrypted = timeDecr[2:4]
        secDecrypted = timeDecr[4:]

        if len(str(hourDecrypted)) == 1 :
            nbr = str(hourDecrypted)[0]
            hourDecrypted = str(0) + str(nbr)

        if len(str(minDecrypted)) == 1 :
            nbr = str(minDecrypted)[0]
            minDecrypted = str(0) + str(nbr)

        if len(str(secDecrypted)) == 1 :
            nbr = str(secDecrypted)[0]
            secDecrypted = str(0) + str(nbr)

        return dayDecrypted, monthDecrypted, yearDecrypted, hourDecrypted, minDecrypted, secDecrypted
    else :
        date = rsa.decrypt(line1, privKey).decode()
        return (date[:2], date[3:5], date[6:10], date[11:13], date[14:16], date[17:])         #formatting to match decryptTime() Z mode format


def decryptSender(mode) :
    if mode == "z" :
        senderEncr = [line2[i:i+24] for i in range(0, len(line2), 24)]
        senderDecr = ''
        for encrBits in senderEncr :
            senderDecr += chr(ZmainDecrypt(encrBits))
        return senderDecr
    else :
        return rsa.decrypt(line2, privKey).decode()


def decryptReciever(mode) :
    if mode == "z" :
        recieverEncr = [line3[i:i+24] for i in range(0, len(line3), 24)]
        recieverDecr = ''
        for encrBits in recieverEncr :
            recieverDecr += chr(ZmainDecrypt(encrBits))
        return recieverDecr
    else :
        return rsa.decrypt(line3, privKey).decode()

#main decrypt engine
def ZmainDecrypt(bitsOfAscii: str) -> int :         #bitsOfAscii must be an str containing 24 bits
    encryptedAscii = str(int(bitsOfAscii[:8], 2)) + str(int(bitsOfAscii[8:16], 2)) + str(int(bitsOfAscii[16:], 2))   # Joins the three ascii numbers got from the binaries
    toDecrypt = int(encryptedAscii)

    if keyMethod == 'plus' :
        if toDecrypt + decryptKey <= limitHigh :
            decryptedAscii = toDecrypt + decryptKey

        elif toDecrypt + decryptKey > limitHigh :                     # Will be triggered if the decrypted ascii number is out of range of the ascii table
            cut = 0
            while toDecrypt <= limitHigh :
                toDecrypt += 1
                cut += 1
            remainingKey = decryptKey - cut
            decryptedAscii = limitLow + remainingKey

    elif keyMethod == 'minus' :
        if toDecrypt - decryptKey >= limitLow :
            decryptedAscii = toDecrypt - decryptKey

        elif toDecrypt - decryptKey < limitLow :
            cut = 0
            while toDecrypt >= limitLow :
                toDecrypt -= 1
                cut += 1
            remainingKey = decryptKey - cut
            decryptedAscii = limitHigh - remainingKey

    return decryptedAscii

#decrypting message
def decryptMessage(mode) :
    if mode == "z" :
        finalDecrypted = ''

        messageEncr = [line5[i:i+24] for i in range(0, len(line5), 24)]
        for encrBits in messageEncr :
            decryptedAscii = ZmainDecrypt(encrBits)
            finalDecrypted += chr(decryptedAscii)
        return finalDecrypted
    else :
        return rsa.decrypt(line5, privKey).decode()

#This function gather all decrypted variables processed by the other functions (decryptTime, decrypt...) and does something according setting 4
def prepareDecrypted(mode: str) :
    global privKey
    if mode == "z" :
        printy("Info : entering ZCrypt decryption mode...", "c")
        if ZfileCheck() :
            printy("Success : your file was checked and no file integrity errors were found. Continuing...", "n")
            ZretrieveKey()
            finalDecrypted = decryptMessage("z")
            senderDecr = decryptSender("z")
            recieverDecr = decryptReciever("z")
            dateDecr = decryptTime("z")
        else :
            printy("Error ! Either the file specified does not use the needed format for the program either it is corrupted.", "m")
            print("Aborting...")
            return
    else :
        printy("Info : entering RSA decryption mode...", "c")
        if RfileCheck() :
            printy("Sucess : your file was checked and no file integrity errors were found. Continuing...", "n")
            privKey = RretrieveKey()
            if privKey != None :
                try :
                    finalDecrypted = decryptMessage("rsa")
                    senderDecr = decryptSender("rsa")
                    recieverDecr = decryptReciever("rsa")
                    dateDecr = decryptTime("rsa")
                except rsa.DecryptionError :
                    printy("Error : private key is not valid or does not match the public key used to encrypt this message", "m")
                    return
            else :
                print("Aborting...")
                return
        else :
            printy("Error ! Either the file specified does not use the needed format for the program either it is corrupted.", "m")
            print("Aborting...")
            return

    #list of the months to know which month number corresponds to what month -> used for date format plain text
    references = {

        'months' : {
            '01' : 'january',
            '02' : 'february',
            '03' : 'march',
            '04' : 'april',
            '05' : 'may',
            '06' : 'june',
            '07' : 'july',
            '08' : 'august',
            '09' : 'september',
            '10' : 'october',
            '11' : 'november',
            '12' : 'december'
            }

        }

    printy("Success : file decrypted", "n")
    print("")

    finalEntireDate, finalEntireTime = '', ''
    dateFormat = settings['dateFormat']

    #changing the final str according to what user specified in dateFormat parameter
    if dateFormat == '1' :
        finalEntireDate = dateDecr[0] + '/' + dateDecr[1] + '/' + dateDecr[2]
    elif dateFormat == '2' :
        finalEntireDate = dateDecr[0] + '/' + dateDecr[1] + '/' + dateDecr[2][2:4]
    elif dateFormat == '3' :
        finalEntireDate = dateDecr[2] + '/' + dateDecr[1] + '/' + dateDecr[0]
    elif dateFormat == '4' :
        month_text = references['months'][dateDecr[1]]

        #Used to find the day of the week with the date number
        dayWeek = findDayName(dateDecr[0] + ' ' + dateDecr[1] + ' ' + dateDecr[2])

        #This part analysis what is the day and adds the 'th', 'st'... at the end
        completeDay = ''
        if dateDecr[0] == 1 :
            completeDay = dateDecr[0] + 'st'
        elif dateDecr[0] == 2 :
            completeDay = dateDecr[0] + 'nd'
        elif dateDecr[0] == 3 :
            completeDay = dateDecr[0] + 'rd'
        else :
            completeDay = dateDecr[0] + 'th'

        finalEntireDate = dayWeek + ", " + month_text + " the " + completeDay + " " + dateDecr[2]

    finalEntireTime = dateDecr[3] + ':' + dateDecr[4] + ':' + dateDecr[5]

    if settings['outModeDecrypt'] == 0 :
        choiceMode = inputy("Would you like to output the decrypted content to be saved to a file or simply to be displayed on screen ? (PRINT/file) ", "c")
        if choiceMode == "file" :
            printy("Info : entering file mode...")
            saveDecryptedContent(
            {
                "Timestamp" : finalEntireDate + ' at ' + finalEntireTime,
                "Sender" : senderDecr,
                "receiver" : recieverDecr,
                "Message" : finalDecrypted
            })
        else :
            printy("Info : entering print mode...")
            printDecryptedContent(senderDecr, recieverDecr, finalDecrypted, finalEntireDate, finalEntireTime)

    elif settings['outModeDecrypt'] == 1 :
        saveDecryptedContent(
            {
                "Timestamp" : finalEntireDate + ' at ' + finalEntireTime,
                "Sender" : senderDecr,
                "receiver" : recieverDecr,
                "Message" : finalDecrypted
            })
    else : printDecryptedContent(senderDecr, recieverDecr, finalDecrypted, finalEntireDate, finalEntireTime)


def printDecryptedContent(senderDecr, recieverDecr, finalDecrypted, date, time) :
    printy("This message was created " + date + ' at ' + time, "c>")
    print("")

    printy(senderDecr + " sent it !", "c>")
    print("")

    printy(recieverDecr + " should receive it !", "c>")
    print("")

    printy("The message is : " + finalDecrypted, "c>")

    print("")

#func used to save decrypted output to a human-readable file
def saveDecryptedContent(dico: dict) :
    fileName = askFilename("Decrypted")

    fileToWrite = open(fileName, 'w')
    for element in dico.keys() :
        fileToWrite.write(element + " : " + dico[element] + "\n")
    fileToWrite.close()

    printy("Success : decrypted data has been saved to " + fileName, 'n')

# UTILS
def askFilename(defaultName: str, message: str = "Please enter the name of file you want to save. ", fileExp: str = ".txt") :
    printy(message, 'c')
    printy("Please note this name MUST end with " + fileExp, "c")
    printy("If the name you enter is not a valid one, " + defaultName + fileExp, 'c', end = ' ')
    printy("will be used", 'c')
    fileNameInput = input("Enter file name : ")
    print("")

    #because e.g. filname is "abc" then abc[-4:] returns "abc" and ".txt" is 4 char long so in order to have a valid name both len() > 4 and ends with ".txt" is required
    if not (len(fileNameInput) > len(fileExp) and fileNameInput[-len(fileExp):] == fileExp) :
        printy("Warning : the name you entered is not valid. " + defaultName + " will be used instead", "y")
        return defaultName + fileExp
    else : return fileNameInput

def findDayName(date) :
    dayNumber = datetime.strptime(date, '%d %m %Y').weekday()
    return day_name[dayNumber]

# UPDATES AND DOWNLOADS
def downloadFile(fileUrl: str, fileName: str, fileExtension: str) :
    fileName = askFilename(fileName, "Please enter a filename that is currently NOT assigned to any file in this directory", fileExtension)
    printy("Info : Downloading " + fileName, "c")
    downloadedFile = urlr.urlopen(fileUrl).read()
    with open(fileName, "wb") as fileToWrite :
        fileToWrite.write(downloadedFile)
    printy("Success : " + fileName + " was downloaded", "c")

def checkForUpdates() :
    try :
        req = requests.get(manifestAddress)
        manifestData = req.json()['ZCrypt']
    except :
        printy("Warning : there was an error while fetching ZCrypt online manifest. Maybe your device is offline", "y")
        printy("Warning : since latest information about ZCrypt could not be fetched, ZCrypt won't check for updates", "y")
        return False, None
    else :
        latestMajorVersion, latestMinorVersion = manifestData['versionCode'].split(".")
        if int(latestMajorVersion) > int(ZCryptMajorVersion) :
            printy("A new major update has been released for ZCrypt !", "c")
            printy("Warning : changing between major versions means API change. If you install this new version, you will NOT be able to decrypt messages encrypted with another major version number", "y")
            printy("Info : You are currently running " + ZCryptVersionName + " and latest version (which can be downloaded) is " + manifestData['versionName'], "n")
            return True, manifestData
        elif int(latestMinorVersion) > int(ZCryptMinorVersion) :
            printy("Info : A new update is available for ZCrypt !", "c")
            printy("You are currently running " + ZCryptVersionName + " but you can update it to " + manifestData['versionName'], "c")
            return True, manifestData
        else :
            printy("Info : ZCrypt is up to date", "c")
            return False, None

def update(manifestData) :
    answer = inputy("Do you want to install " + manifestData['versionName'] + " ? (Y/n) ", "c")
    if answer.lower() != "n" :
        try :
            downloadFile(manifestData['download'], "ZCryptV" + manifestData['versionCode'], ".py")
            printy("ZCrypt will now quit. Please run the new version file")
            settings['deleteOld'] = os.path.basename(__file__)
            writeSettings(settings)
        except :
            printy("Error : " + manifestData['versionName'] + " could not be downloaded. Are you connected to the internet ?", "m")
            return False
        else :
            return True
    else : return False

# SETTINGS
def writeSettings(settingsToWrite: dict = defaultSettings) :
    global settings
    with open("ZCrypt-settings", "w") as settingsFile :
        settingsFile.write("This file has been automatically created by ZCrypt. Do NOT modify it unless you know what you are doing \n")
        for element in settingsToWrite.keys() :
            settingsFile.write(element + ":" + str(settingsToWrite[element]) + ";")
            settings = settingsToWrite

def loadSettings() :
    global settings
    with open("ZCrypt-settings", "r") as settingsFile :
        settingsList = settingsFile.readlines()[1].split(";")[:-1]
        assert len(settingsList) == 7 or 8
        settings = dict()
        for setting in settingsList :
            elements = setting.split(":")
            assert elements[0] != "" and elements[1] != ""
            settings[elements[0]] = elements[1]

def runSettings() :
    global settings
    print("")

    dateFormatDict = {
        "1" : "dd/mm/YYYY",
        "2" : "dd/mm/YY",
        "3" : "YYYY-mm-dd",
        "4" : "plain"
    }

    print("\n")
    printy("You are now in the settings !", "c")
    printy("Here, are the options you can change :", "c")
    printy("    - 1: encrypted file name", "c")
    printy("    - 2: date display format", "c")
    printy("    - 3: warn before overwrite", "c")
    printy("    - 4: decrypted content output mode", "c")
    printy("    - 5: encryption and decryption algorithm", "c")
    printy("    - 6: RSA keys size (number of bits)", "c")
    printy("    - 7: Fetch ZCrypt updates\n", "c")

    printy("If you want to see the current value of an option, type \"see\" followed by the number linked to the option", "c")
    printy("If you want to change this value, type \"set\" followed by the number linked to the option", "c")
    printy("If you want to exit this page, you can also type \"exit\"", "c")

    while True :
        printy("You are currenly in settings ! Encrypt and decrypt are not part of this context. To go back to the main menu type \"exit\"", 'y')
        settingsCmd = input(">>> ")

        if 'see' in settingsCmd and len(settingsCmd) == 5 :
            if settingsCmd[4] == '1' :
                print("Your encrypted messages are currently saved in a file named :", settings['fileOutput'])

            elif settingsCmd[4] == '2' :
                print("The date format is currently set to", settings['dateFormat'])

            elif settingsCmd[4] == '3' :
                print(("Warning before overwrite is currently enabled" if settings['warnBeforeOW'] else "No warning will be shown before you overwrite an existing file"))

            elif settingsCmd[4] == '4' :
                if settings['outModeDecrypt'] != 0 :
                    printy("Any content you decrypt will be outputed to " + (file_name if settings['outModeDecrypt'] == 1 else "screen directly"), "c")
                else : printy("ZCrypt will always ask you if you want to save your decrypted content to a file or if you want to print it on screen", "c")

            elif settingsCmd[4] == '5' :
                if settings['encryptionMode'] == "ask" : printy("ZCrypt will always ask you if you want to encrypt a message using ZCrypt algorithm or RSA", 'c')
                elif settings['encryptionMode'] == "RSA" : printy("ZCrypt will always encrypt using RSA", "c")
                else : printy("ZCrypt will always encrypt your messages using ZCrypt algorithm")

            elif settingsCmd[4] == '6' :
                printy("RSA uses public and private keys to encrypt/decrypt content. These keys are made of very high numbers (more than 20 digits)", "c")
                printy("Currently RSA keys have a length of " + str(settings['rsaKeyBytes']) + " bits", "c")

            elif settingsCmd[4] == "7" :
                printy("ZCrypt can automatically fetch updates for you", "c")
                if settings["checkForUpdates"] == "atStart" :
                    printy("Currently ZCrypt checks for updates every time you start ZCrypt", "c")
                elif settings["checkForUpdates"] == "atOperation" :
                    printy("Currenly ZCrypt check for updates every time an operation is performed (decryption or encryption) AND at ZCrypt start", "c")
                else :
                    printy("ZCrypt will never check if updates are available", "c")

            else :
                printy("Error ! The option you tried to view does not exists or does have a number assigned to it", "m")


        elif 'set' in settingsCmd and len(settingsCmd) == 5 :
            if settingsCmd[4] == '1' :
                fileOutput = input("Please enter the name of file you want to be saved as. Don't forget to ad (.txt) at the end ! : ")
                if not (len(fileOutput) > 4 and fileOutput[-4:] == ".txt") :
                    printy("Error : the name you entered is not valid. Nothing has been changed", "m")
                else :
                    settings['fileOutput'] = fileOutput
                    writeSettings(settings)
                    printy("Sucess : the name of the output file has been successfully changed to", "n", end = ' ')
                    printy(fileOutput, 'n')

            elif settingsCmd[4] == '2' :
                printy("You have the choice between 4 date formats : 1) dd/mm/YYYY, 2) dd/mm/YY, 3) YYYY-mm-dd or just the 4) plain text format", 'c')
                choice = inputy("Please enter the number of the date format you want to use (1, 2, 3 or 4) : ", 'c')
                try :
                    if int(choice) <= 4 and int(choice) > 0 :
                        settings['dateFormat'] = choice
                        writeSettings(settings)
                        printy('Success : set date format to ' + dateFormatDict[choice], 'n')
                    else :
                        printy("Error : " + choice + " is not an offered choice", 'm')
                except ValueError : printy("Error : Please enter an integer", "m")

            elif settingsCmd[4] == '3' :
                printy("Sometimes when you encrypt a file, another file with the same name already exists", 'c')
                printy("When this happens, ZCrypt offers you to choice between overwriting the existing file or doing nothing", 'c')
                printy("When the file is overwritten, you lose all the data stored on it. This is why we recommend you to backup its content before overwriting", 'c')
                print("")
                printy("You can disable this warning by typing \"disable\"", 'c')
                printy("You don't want to disable this warning type anything except \"disable\"", 'c')
                printy("Please be careful when disabling this warning. You could lose important data and ZCrypt assumes no responsability in this. Do it at your own risk", 'm')
                testdisable = input("Input : ")
                if testdisable == "disable" :
                    settings['warnBeforeOW'] = False
                    writeSettings(settings)
                    printy("Success : Warning before overwrite is now disabled", 'n')
                else :
                    printy("Nothing has been changed", 'n')
                    printy("Returning...", 'n')

            elif settingsCmd[4] == "4" :
                printy("3 values are available for this setting : 0, 1 and 2", "c")
                printy("If you choose 0, ZCrypt will always ask you if you want to save to a file or just show the content on screen", "c")
                printy("If you choose 1, ZCrypt will always save your decrypted content to a file", "c")
                printy("If you choose 2, ZCrypt will always output your descrypted content to your screen", "c")
                printy("Note : mode 2 works just like ZCypt used to function in releases before V2.3", 'c')
                choice = input("Input : ")
                try :
                    if 0 <= int(choice) <= 2 :
                        settings['outModeDecrypt'] = int(choice)
                        writeSettings(settings)
                        printy("Success : set output mode to " + choice, 'n')
                    else : printy("Error : " + choice + " is not an offered choice", "m")
                except ValueError :
                    printy("Error : please enter an integer", "m")

            elif settingsCmd[4] == '5' :
                printy("ZCrypt offers you 2 different encryption algorithms for encrypting your messages", "c")
                printy("3 values are available for this setting : ask, RSA and zcrypt", "c")
                printy("If you choose ask, ZCrypt will always ask you if you want to use RSA or ZCrypt custom algorithm to encrypt your messages", "c")
                printy("If you choose RSA, your messages will always be encrypted using RSA", "c")
                printy("Lastly, as the name suggests, if you choose zcrypt, ZCrypt will always encrypt your messages using ZCrypt algorithm", "c")
                choice = input("Input : ").lower()
                if choice == "ask" :
                    settings['encryptionMode'] = "ask"
                    writeSettings(settings)
                    printy("Successfully set encryption mode to " + choice, 'n')
                elif choice == "rsa" :
                    settings['encryptionMode'] = "RSA"
                    writeSettings(settings)
                    printy("Successfully set encryption mode to " + choice, 'n')
                elif choice == "zcrypt" :
                    settings['encryptionMode'] = "zcrypt"
                    writeSettings(settings)
                    printy("Successfully set encryption mode to " + choice, 'n')
                else :
                    printy("The value you entered is not valid. Nothing has been changed", "m")

            elif settingsCmd[4] == '6' :
                printy("RSA uses public and private keys to encrypt/decrypt content. These keys are made of very high numbers (more than 20 digits)", "c")
                printy("You can set the length of these numbers by entering the number of bits which must be a pow of 2 (256, 512, 1024, 2048...)", "c")
                printy("The highest number of bits, the higher security but also the longer time to generate the keys", "c")
                printy("By default this value is set to 1024. We do not recommend to enter a number lower than 256 (too low encryption) and higher than 4096 (your computer could take minutes to generate keys)", "c")
                choice = input("Input : ")
                try :
                    choice = int(choice)
                    assert (choice & (choice-1) == 0) and choice != 0      #checking if choice is power of 2
                    if choice > 4096 or choice < 256 :
                        printy("Warning : you entered a non-recomended value. Expect low security/crashes/slowness when generating keys", 'y')
                        settings['rsaKeyBytes'] = choice
                        writeSettings(settings)
                        printy("Success : set RSA keys length to " + str(choice) + " bytes", 'n')
                    else :
                        settings['rsaKeyBytes'] = choice
                        writeSettings(settings)
                        printy("Success : set RSA keys length to " + str(choice) + " bytes", 'n')
                except ValueError :
                    printy("Error : please enter an integer", "m")
                except AssertionError :
                    printy("Error : please enter a power of 2", "m")

            elif settingsCmd[4] == '7' :
                printy("ZCrypt can automatically check for new updates and download them if necessary", "c")
                printy("By default, ZCrypt does that every time you start however you can change this behavior", "c")
                printy("3 values are available for this setting", "c")
                printy("If you enter start which is the default value for this setting that's to available updates will be fetched at start", "c")
                printy("If you enter operation, ZCrypt will check for available updates every time you start ZCrypt AND every time you encrypt or decrypt something", "c")
                printy("If you enter never ZCrypt will NEVER check for updates", "c")
                choice = input("Input : ").lower()
                if choice == "start" :
                    settings['checkForUpdates'] = "atStart"
                    writeSettings(settings)
                    printy("Success : ZCrypt will check for updates at boot", "n")
                elif choice == "operation" :
                    settings['checkForUpdates'] = "atOperation"
                    writeSettings(settings)
                    printy("Success : ZCrypt will check for updates each time an operation is performed", "n")
                elif choice == "never" :
                    settings['checkForUpdates'] = "never"
                    writeSettings(settings)
                else : printy("Error : this is not an offered choice", "m")
                printy("Success : ZCrypt will never check for updates", "n")

            else :
                printy("Error : the option you tried to view does not exists or does have a number assigned to it", "m")


        elif settingsCmd == 'exit' :
            break

        else :
            printy("Error : either this command is unknown either it does not use the needed format ! See the manual to learn more ", "m")


if __name__ == '__main__' :
    # START-UP
    #Module check routine
    print(ZCryptVersionName)
    print("Info : ZCrypt is starting up...")
    try :
        from printy import printy, inputy
        import rsa
    except ImportError :
        print("Error : it seems at least one ZCrypt requirement, a module in this case, is not satisfied")
        print("ZCrypt can install the missing modules for you. If you don't want to do so you are also free to install them")
        answer = input("Would like to proceed to automatic installation ? (Y/n) ")
        if answer.lower() != "n" :
            print("Info : installing missing dependencies...")
            command = ("python" if os.name == "nt" else "python3") + " -m pip install -r PackageRequirements.txt"
            if not os.system(command) :
                print("Success : missing modules were successfully installed !")
                from printy import printy, inputy
                import rsa
                print("Info : ZCrypt requirements are satified, continuing...")
            else :
                print("Error : please make sure pip is installed and try again")
                sys.exit()
        else : sys.exit()

    #Loading settings from file routine
    try :
        loadSettings()
    except (IndexError, KeyError, AssertionError) :
        printy("Error : ZCrypt-settings file seems to be corrupt", "m")
        answer = inputy("Do you want to restore it to defaults (Y/n) ? ")
        if answer.lower() != "n" :
            try :
                os.remove("ZCrypt-settings")
                writeSettings()
                loadSettings()
            except :
                printy("Error : ZCrypt was unable to automatically recover the settings file, please re-install ZCrypt if this problem keeps happening", "m")
                sys.exit()
        else :
            sys.exit()

    except FileNotFoundError :
        writeSettings()
        loadSettings()

    #check if older python file is present
    try :
        if settings['deleteOld'] != os.path.basename(__file__) :    #to avoid deleting itself
            os.remove(settings['deleteOld'])
        else :
            printy("Error : you are not launching the right ZCrypt file", "m")
            printy("Please run the Python file called " + settings['deleteOld'], "m")
            printy("Info : since this version of ZCrypt is not the newest version, ZCrypt will now exit...", "c")
            sys.exit()
    except KeyError :
        pass
    else :
        settings.pop('deleteOld')
        writeSettings(settings)
    
    #Check for updates if necessary
    if settings['checkForUpdates'] == "atStart" or settings['checkForUpdates'] == "atOperation":
        import urllib.request as urlr
        result = checkForUpdates()
        if result[0] and update(result[1]) :
            input("Press any enter to continue...")
            sys.exit()
    else : printy("Warning : not checking for updates since it has been disabled in settings", "y")

    # WELCOME SCREEN
    printy("#######################", "c>")
    printy("# Welcome to ZCrypt ! #", "c>")
    printy("#######################", "c>")
    printy("Here are the commands you can use : encrypt, decrypt and you can also see the user manual by typing \"manual\"", "n>")
    printy("If this is your first time using the program, please consider using the \"instructions\" command", "n>")
    printy("If you want to access the settings, type \"settings\"", "n>")
    printy("You can also exit the program by typing \"exit\"", "n>")

    # MAIN LOOP
    while True :
        print("")
        printy("Please input a command ", "c")
        command = input(">>> ")

        if "encrypt" in command :
            #Here, the user inputs all informations required to encrypt
            print("Ok ! Let's encrypt your message !")
            if settings['encryptionMode'] == "ask" :
                cryptMode = input("Do you want to crypt using ZCrypt algorithm or RSA (see Manual for details) ? (RSA/zcrypt) ")
                prepareEncryptedOutput(cryptMode)
            else : prepareEncryptedOutput(settings['encryptionMode'])


        elif "decrypt" in command :
            Error_Code = ""
            decryptMode = input("Was your file encrypted with RSA or ZCrypt algorithm (ask the sender if you don't know) ? (RSA/zcrypt) ")
            printy("Please specify the COMPLETE name of the file with the .txt end !", "c")
            file_name = input()
            if decryptMode.lower() == "zcrypt" :
                prepareDecrypted("z")
            else : prepareDecrypted("rsa")

        elif "settings" in command :
            runSettings()

        elif "showError" in command :
            if Error_Code != "" :
                print("We are sorry to hear that your file has a problem")
                print("Here is your error code :", Error_Code)
                print("This is an extract from the UserManual where your error code is discussed")

                #Showing info about the error code starting with ...
                print(errorsDict[Error_Code])

            else :
                printy("Your file has been decrypted without any errors.", "c")

        elif "manual" in command :
            printy("Info : See ZCrypt manual at https://github.com/cl-ement05/ZCrypt/blob/master/UserManual.md", "c")

        elif "instructions" in command :
            print("Dear User, welcome to ZCrypt !")
            print("ZCrypt was developped by Clement")
            print("This software was created in order to encrypt messages easily, send them and decrypt them quickly !")
            print("")

            print("If you want to encrypt a file, remeber that it will be saved in the same location of this program")
            print("It will be created with the name \"Mail.txt\"")
            print("You can always changes this name in the settings")
            print("")

            print("If you want to decrypt a file, you will need to specify its name as you launch the decrypting process")
            print("")

            print("If the program says that your file has a problem and that it can't be decrypted, don't panic !")
            print("You can use the \"showError\" command !")
            print("")

            print("Enjoy !")

        elif command == 'exit' :
            printy("Thank you for using ZCrypt ! See you soon...", "c")
            printy("Info : exiting...", "c")
            break

        else :
            printy("Error : unknown command, please try again", "m")
            if 'encr' in command : printy("Did you mean \"encrypt\" command ?", "y")
            elif 'decr' in command : printy("Did you mean \"decrypt\" command ?", "y")
