from datetime import datetime
from calendar import day_name
from random import randint
from printy import printy, inputy
import rsa
import base64 as b64

file = ''
Error_Code = str()

#Default settings
fileOutput = "Mail.txt"
dateFormat = '1'
warnBeforeOW = True
outModeEncrypt = 0
encryptionMode = "ask"
rsaKeyBytes = 1024

lastKey = 15                                            #This line runs just once, at the programm start because the encryption module needs the last key (and there is no last key at the first time)


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
        line1 = text[0]
        line2 = text[1]
        line3 = text[2]
        line4 = text[3]
        line5 = text[4]

        try :
            assert(type(line1) == str)
            assert(type(line2) == str)
            assert(type(line3) == str)
            assert(type(line4) == str)
            assert(type(line5) == str)
        except AssertionError :
            Error_Code = "E202"
            return False


        if len(line1) == 29 :                                                              #29 because there is a \n at the end of the line and the n is a character
            try :
                assert(type(int(line1[:28]))) is int
            except (ValueError, AssertionError) :
                Error_Code = "E301"
                return False
        else :
            Error_Code = "E302"
            return False

        if len(line4) == 9 :
            try :
                assert(type(int(line4, 2))) is int
            except (ValueError, AssertionError) :
                Error_Code = "E313"
                return False
        else :
            Error_Code = "E314"
            return False

        if ';' in line5 :
            try :
                assert(type(int(line5[:24]))) is int
            except (ValueError, AssertionError) :
                Error_Code = "E325"
                return False
        else :
            Error_Code = "E326"
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
        
        line1 = b64.b64decode(lines[0])
        line2 = b64.b64decode(lines[1])
        line3 = b64.b64decode(lines[2])
        line5 = b64.b64decode(lines[3])
        line4 = None      #since no key is stored on line 4 when using RSA crypt mode, not defining line4 could raise a NameError not defined so assigning None value
        return True


#Here all functions are defined
#Gets the key which is encrypted in binary
def ZretrieveKey() :
    key = line4
    global keyMethod
    global decryptKey
    decryptKey = int(key, 2)
    if decryptKey % 2 == 0 :
        keyMethod = 'plus'
    else :
        keyMethod = 'minus'

def RretrieveKey() :
    printy("In order to decrypt a message that was encrypted with RSA, a private key is needed", "c")
    printy("If you saved it when encrypting your message, the private key specs will be automatically retrieved", "c")
    printy("Otherwise you will need to remember and enter each value", "c")

    print("Do you have your private key saved in a file ? (y/N) ", end = "")
    if input("").lower() != "y" :
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
                assert(len(keys) == 5)
                n = int(keys[0])
                e = int(keys[1])
                d = int(keys[2])
                p = int(keys[3])
                q = int(keys[4])
            except (ValueError, AssertionError) :
                printy("Error : this file does not contain valid data about the private key", "m")
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
    global keyNum
    global keyBin
    global lastKey
    keyNum = randint(10, 40)
    #All this part tests if the current key is far enough from the last key to the message be securely encyrpted
    key_diff = False
    while key_diff == False :
            
        if keyNum > lastKey :
            if (keyNum - lastKey) > 15 :
                key_diff = True
            else :
                keyNum = randint(10, 40)
            
        elif keyNum < lastKey :
            if (lastKey - keyNum) > 15 :
                key_diff = True
            else :
                keyNum = randint(10, 40)
            
        elif keyNum == lastKey :
                keyNum = randint(10, 40)
    
    lastKey = keyNum
    keyBin = format(keyNum, '08b')

def RcreateKey() :
    global privKey, pubKey, keyBin
    printy("Info : generating RSA keys", 'c')
    (pubKey, privKey) = rsa.newkeys(rsaKeyBytes)
    keyBin = pubKey          #sample value used to have 5 lines for all encrypted files no matter if it was encrypted with RSA or ZCrypt
    printy("Warning : here are your private key specs. DO NOT SHARE THEM UNLESS YOU KNOW WHAT YOU ARE DOING !", 'y')
    print("PrivateKey N : ", privKey.n)
    print("PrivateKey e : ", privKey.e)
    print("PrivateKey d : ", privKey.d)
    print("PrivateKey p : ", privKey.p)
    print("PrivateKey q : ", privKey.q)
    printy("\nWarning : you will need to provide these numbers in order to decrypt your message", "y")
    printy("Since they are very long, so hard to remeber, ZCrypt provides you an option to save them", "c")
    printy("Do you want to save your private key to a text file ? (Y/n) ", "c", end = ' ')
    answer = input("")
    if answer != "n" :
        fileName = askCheckFilename("keys.txt")
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
    current_time = now.strftime("%d/%m/%Y %H:%M:%S")

    if mode == "z" :
        for element in range(len(current_time)) :
            #This try is used to skip date characters like (/ and :) that cannot be encrypted and will be removed
            try :
                int(current_time[element])
            except ValueError :
                if current_time[element] != '/' and current_time[element] != ':' and current_time[element] != ' ' :
                    printy("Error : runtime error. Please try again", "m")
                    exit()

            #If the try passes and the current element is an integer (so a number that is part from the date), encyption starts
            else :
                encrypted_int = int(str(current_time[element])) + int(keyNum)
                finalTimeList.append(str(encrypted_int))
        finalTimeEncr = "".join(finalTimeList)
    else :
        return b64.b64encode(rsa.encrypt(
            current_time.encode(), 
            pubKey))
        

    assert(len(finalTimeEncr) == 28)
    return finalTimeEncr


#Encrypting sender
def encryptSender(mode, sender) :
    senderEncr = ''
    if mode =="z" :
        for character in range(len(sender)) :
            senderAscii = ord(sender[character])
            senderEncr += chr(ZmainEncrypt(senderAscii))
        return senderEncr
    else :
        return b64.b64encode(rsa.encrypt(
            sender.encode(), 
            pubKey))

#Encrypts receiver
def encryptReciever(mode, reciever) :
    recieverEncr = ''
    if mode == "z" :
        for character in range(len(reciever)) :        
            recieverAscii = ord(reciever[character])
            recieverEncr += chr(ZmainEncrypt(recieverAscii))
        return recieverEncr
    else :
        return b64.b64encode(rsa.encrypt(
            reciever.encode(), 
            pubKey))

#Main encrypt engine
def ZmainEncrypt(toEncrypt: int) -> int :             #takes a single int argument which must be the ascii representation of a char; returns the encrypted ascii
    #If the key is a pair number
    if keyNum % 2 == 0 :
        if toEncrypt - keyNum >= 33 :
            encrypted = toEncrypt - keyNum

        elif toEncrypt - keyNum < 33 :
            cut = 0
            while toEncrypt >= 33 :
                toEncrypt -= 1
                cut += 1
            remainingKey = keyNum - cut
            encrypted = 126 - remainingKey

    #If the key is an impair number
    elif keyNum % 2 == 1 :
        if toEncrypt + keyNum <= 126 :
            encrypted = toEncrypt + keyNum

        elif toEncrypt + keyNum > 126 :
            cut = 0
            while toEncrypt <= 126 :
                toEncrypt += 1
                cut += 1
            remainingKey = keyNum - cut
            encrypted = 33 + remainingKey

    return encrypted


# Crypting the message
def ZencryptMessage(mode, message_input) :
    finalMessageBinary = list()

    if mode == "z" :
        for i in range(len(message_input)) :
            #Transforms the character in its ascii number
            currentChr = message_input[i]
            asciiChr = ord(currentChr)

            #Spaces are encoded as is they were "~" (its ascii is 126) so to avoid errors, the programm does not support this character
            if asciiChr == 126 :
                printy("Error : your message contains a character that is not supported", "m")
                break

            asciiEncr = ZmainEncrypt(asciiChr)
            letterBinary = list()
            #If the Ascii number contains only two numbers, the programm adds a 0 in front oh the two to get a number with 3 binaires at the end
            if len(str(asciiEncr)) == 2 :
                letterBinary.append('00000000')
                for asciiNbr in range(2) :
                    letterBinary.append(format(int(str(asciiEncr)[asciiNbr]), '08b'))

            elif len(str(asciiEncr)) == 3 :
                for asciiNbr in range(3) :
                    letterBinary.append(format(int(str(asciiEncr)[asciiNbr]), '08b'))

            assert(len(letterBinary) == 3)

            letterBinary.append(';')                                       #Adds the separator (;) to create a difference between de letters
            letter_str = ''
            for x in range(4) :
                letter_str += letterBinary[x]

            finalMessageBinary.append(letter_str)

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

    else :
        mode = "RSA"
        printy("Info : entering RSA encryption mode...", "c")
        printy("Warning : decrypting RSA messages is only supported on ZCrypt V3.0+, make sure the reciever meets this requirement", "y")
        RcreateKey()
        print("")

    message_input = input("First, type the message you want to encrypt : ")
    sender = input("Please type your name that will be used in the file as the sender information : ")
    reciever = input("Finally, type the reciever of this message : ")

    finalMessageBinary = ZencryptMessage("z" if mode == "z" else "rsa", message_input)
    finalTimeEncr = encryptTime("z" if mode == "z" else "rsa")
    senderEncr = encryptSender("z" if mode == "z" else "rsa", sender)
    recieverEncr = encryptReciever("z" if mode == "z" else "rsa", reciever)


    txt = False                      #boolean variable which is set to true when the file name specified by user is valid that's to say, ends with ".txt"

    for letter in range(len(fileOutput)) :
        if fileOutput[letter] == '.' and fileOutput[letter + 1] == 't' and fileOutput[letter + 2] == 'x' and fileOutput[letter + 1] == 't' :
            txt = True

    if txt :
        try :
            open(fileOutput, "r")            #opening in read mode the name specified by the user so that if a file with the same already exists, no error will be raised
        except FileNotFoundError :                         #else if an error is thrown, file was not found so no file will be overwritten -> writeFile
            writeFile(mode, finalMessageBinary, finalTimeEncr, senderEncr, recieverEncr, keyBin if mode == "z" else None)
        else :
            if warnBeforeOW :                          #boolean setting 1 -> warn user that a file will be overwritten
                printy("Warning : " + fileOutput + " already exists", 'y')
                printy("Warning : if you continue the encryption process, the existing file will be overwritten", 'y')
                printy("Note : this operation cannot be undone", 'c')
                printy("Note : we highly recommend you to backup this file if personnal infos are stored on it", 'c')
                printy("Are you sure you want to continue ? (y/n)", 'y', end = '')
                firstanswer = input(" ")
                if firstanswer == "y" :
                    printy(fileOutput, 'y', end = ' ')
                    printy("will be overwritten !! Proceed anyway ? (y/n)", 'y', end ='')
                    confirmation = input(" ")
                    if confirmation == "y" :
                        writeFile(mode, finalMessageBinary, finalTimeEncr, senderEncr, recieverEncr, keyBin if mode == "z" else None)   #after user confirmation that file can be overwritten -> writeFile
                    else :
                        printy("Info : encryption aborted", 'c') 
                else :
                    printy("Info : encryption aborted", 'c')     
            
            #if the warning has been disabled
            else :
                writeFile(mode, finalMessageBinary, finalTimeEncr, senderEncr, recieverEncr, keyBin if mode == "z" else None)
                printy("Note : a file has been overwritten", "y")

    else :
        printy("Error : the name of the file you want to save is incorect. Please try another one !", 'm')



#Write all encrypted content to the file using the settings prepared by the prepareEncryptedOutputt function
def writeFile(mode: str, messageW: list or bytes, *args: str or bytes) :
    #'\n' is used to go to a new line at every new file settings
    file_w = open(fileOutput, "w" if mode == "z" else "wb")
    if mode == "z" :
        for elementToW in args :
            if elementToW is not None : file_w.write(elementToW + "\n")
        file_w.write("".join(messageW))
        file_w.close()
    else :
        for elementToW in args :
            if elementToW is not None : file_w.write(elementToW + '|'.encode("utf8"))
        file_w.write(messageW + '|'.encode('utf8'))
        file_w.close()

    printy("Success : your message has been securely encrypted !", 'n')


#All decrypt child functions
#Decrypts the date and time
def ZdecryptTime() :
    #Here, the entire line1 that contains the date is spread into different variables
    chSize = 2
    date = line1[:(chSize * 8)]
    time = line1[(chSize * 8):len(line1) - 1]

    #Decrypting date
    dateDecr = str()
    for number in range(0, len(date), 2) :
        dateDecr += str(int(date[number] + date[number + 1]) - decryptKey)      #decrypting each digit with the key
                            #here we loop with a step of 2 since 1 decrypted digit -> 2 encrypted digits (because key > 10)
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
    for number in range(0, len(time), 2) :
        timeDecr += str(int(time[number] + time[number + 1]) - decryptKey)

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

def ZdecryptSender() :
    senderEncr = line2
    senderDecr = ''
    for character in range(len(senderEncr)) :
        sender_chr = ord(senderEncr[character])
        senderDecr += chr(ZmainDecrypt(sender_chr))

    senderDecr = senderDecr[:(len(senderDecr) - 1)]                                                  #This line removes the 0 that spaws after the name
    return senderDecr


def ZdecryptReciever() :
    recieverEncr = line3
    recieverDecr = ''
    for character in range(len(recieverEncr)) :
        reciever_chr = ord(recieverEncr[character])
        recieverDecr += chr(ZmainDecrypt(reciever_chr))

    recieverDecr = recieverDecr[:(len(recieverDecr) - 1)]                                                  #This line removes the 0 that spawns after the name
    return recieverDecr    

#main decrypt engine
def ZmainDecrypt(toencrypt: int) -> int :
    if keyMethod == 'plus' :
        if toencrypt + decryptKey <= 126 :
            decryptedAscii = toencrypt + decryptKey
            
        elif toencrypt + decryptKey > 126 :                     # Will be triggered if the decrypted ascii number is out of range of the ascii table
            cut = 0
            while toencrypt <= 126 :
                toencrypt += 1
                cut += 1
            remainingKey = decryptKey - cut
            decryptedAscii = 33 + remainingKey

    elif keyMethod == 'minus' :
        if toencrypt - decryptKey >= 33 :
            decryptedAscii = toencrypt - decryptKey
            
        elif toencrypt - decryptKey < 33 :
            cut = 0
            while toencrypt >= 33 :
                toencrypt -= 1
                cut += 1
            remainingKey = decryptKey - cut
            decryptedAscii = 126 - remainingKey
    
    if decryptedAscii == 126 : return 32    #Since spaces are encrypted as a "~", if the programm finds a 126 number (which is the ascii code of ~), it changes the ~ character into a space
    else : return decryptedAscii

#decrypting message
def ZdecryptMessage() :
    finalDecrypted = ''

    nbr_letters = int(len(line5) / 25)
    message_encr = line5.split(";")
    for letter in range(nbr_letters) :
        encrCharacter = message_encr[letter]

        #Transforms the binary string into an ascii number
        binaryCh1 = encrCharacter[:8]
        encrypted_ascii1 = int(binaryCh1, 2)

        a = encrCharacter[8:]
        binaryCh2 = a[:8]
        encrypted_ascii2 = int(binaryCh2, 2)

        binary_ch3 = encrCharacter[16:]
        encrypted_ascii3 = int(binary_ch3, 2)

        charAsciiEncr = int(str(encrypted_ascii1) + str(encrypted_ascii2) + str(encrypted_ascii3))            # Joins the three ascii numbers got from the binaries
        #print("Encrypted ascii:", charAsciiEncr)
        #The encrypt/decrypt method is different for pair/impair numbers
        decryptedAscii = ZmainDecrypt(charAsciiEncr)

        finalDecrypted += chr(decryptedAscii)
    return finalDecrypted

def RmainDecrypt() :
    try :
        mess = rsa.decrypt(line5, privKey)
        date = rsa.decrypt(line1, privKey).decode()
        sender = rsa.decrypt(line2, privKey)
        reciever = rsa.decrypt(line3, privKey)
        dateFormatted = (date[:2], date[3:5], date[6:10], date[11:13], date[14:16], date[17:])         #formatting to match ZdecryptTime() return format
    except rsa.DecryptionError :
        printy("Error : private key is not valid or does not match the public key used to encrypt this message", "m")
    else :
        processDecrypted(mess.decode(), sender.decode(), reciever.decode(), dateFormatted)

#This function gather all decrypted variables processed by the other functions (decryptTime, decrypt...) and does action following the outMode setting 4
def processDecrypted(finalDecrypted: str, senderDecr: str, recieverDecr: str, dateDecr: tuple) :
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

    printy("Success : file decrypting finished", "n")
    print("")

    finalEntireDate, finalEntireTime = '', ''
        #changing the final str according to what user specified for date format
    if dateDecr != None :
        if dateFormat == '1' :
            finalEntireDate = dateDecr[0] + '/' + dateDecr[1] + '/' + dateDecr[2]
        elif dateFormat == '2' :
            finalEntireDate = dateDecr[0] + '/' + dateDecr[1] + '/' + dateDecr[2][2:4]
        elif dateFormat == '3' :
            finalEntireDate = dateDecr[2] + '/' + dateDecr[1] + '/' + dateDecr[0]
        elif dateFormat == '4' :
            month_text = references['months'][dateDecr[1]]
            
            #Used to find the day of the week with the date number
            dayWeek = findDayDate(dateDecr[0] + ' ' + dateDecr[1] + ' ' + dateDecr[2])

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
    
    if outModeEncrypt == 0 :
        choiceMode = inputy("Would you like to output the encrypted content to be saved to a file or simply to be displayed on screen ? (FILE/print) ", "c")
        if choiceMode == "print" :
            printy("Info : entering print mode...")
            printDecrypted(senderDecr, recieverDecr, finalDecrypted, finalEntireDate, finalEntireTime)
        else :
            printy("Info : entering file mode...")
            saveDecryptedToFile(
            {
                "Timestamp" : finalEntireDate + ' at ' + finalEntireTime,
                "Sender" : senderDecr,
                "Reciever" : recieverDecr,
                "Message" : finalDecrypted
            })     #changing finalDecrypted from bytes to str because dict must only contain strings
    
    elif outModeEncrypt == 1 :    
        saveDecryptedToFile(
            {
                "Timestamp" : finalEntireDate + ' at ' + finalEntireTime,
                "Sender" : senderDecr,
                "Reciever" : recieverDecr,
                "Message" : finalDecrypted
            })
    else : printDecrypted(senderDecr, recieverDecr, finalDecrypted, finalEntireDate, finalEntireTime)


def printDecrypted(senderDecr, recieverDecr, finalDecrypted, date, time) :
    printy("This message was created " + date + ' at ' + time, "c>")
    print("")

    printy(senderDecr + " sent it !", "c>")
    print("")

    printy(recieverDecr + " should recieve it !", "c>")
    print("")

    printy("The message is : " + finalDecrypted, "c>")

    print("")


def saveDecryptedToFile(dico: dict) :  
    fileName = askCheckFilename("Decrypted.txt")
    
    fileToWrite = open(fileName, 'w')
    for element in dico.keys() :
        if dico[element] != None :                                        #used to avoid writing None elements i.e. in RSA mode where sender reciever and time = None
            fileToWrite.write(element + " : " + dico[element] + "\n")
    fileToWrite.close()

    printy("Success : decrypted data has been saved to " + fileName, 'n')


def askCheckFilename(defaultName: str) :
    printy("Please enter the name of file you want to save. Please note this name MUST end with .txt", 'c')
    printy("If the name you enter is not a valid one, " + defaultName, 'c', end = ' ')
    printy("will be used", 'c')
    fileNameInput = inputy("Enter file name : ")
    print("")

    #because e.g. filname is "abc" then abc[-4:] returns "abc" and ".txt" is 4 char long so in order to have a valid name both len() > 4 and ends with ".txt" is required
    if not (len(fileNameInput) > 4 and fileNameInput[-4:] == ".txt") :
        printy("Warning : the name you entered is not valid. " + defaultName + " will be used instead", "y")
        return defaultName
    else : return fileNameInput

def findDayDate(date) :
    dayNumber = datetime.strptime(date, '%d %m %Y').weekday()
    return (day_name[dayNumber])


def settings() :
    global fileOutput
    global dateFormat
    global warnBeforeOW
    global outModeEncrypt
    global encryptionMode
    global rsaKeyBytes
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
    printy("    - 4: encrypted content output mode", "c")
    printy("    - 5: encryption and decryption algorithm", "c")
    printy("    - 6: RSA keys size (number of bits)\n", "c")

    printy("If you want to see the current value of an option, type \"see\" followed by the number linked to the option", "c")
    printy("If you want to change this value, type \"set\" followed by the number linked to the option", "c")
    printy("If you want to exit this page, you can also type \"exit\"", "c")

    while True :
        printy("You are currenly in settings ! Encrypt and decrypt are not part of this context. To go back to the main menu type \"exit\"", 'y')
        settingsCmd = input(">>> ")

        if 'see' in settingsCmd and len(settingsCmd) == 5 :
            if settingsCmd[4] == '1' :
                print("Your encrypted messages are currently saved with the following name :", fileOutput)

            elif settingsCmd[4] == '2' :
                print("The date format is currently set to", dateFormat)

            elif settingsCmd[4] == '3' :
                print(("Warning before overwrite is currently enabled" if warnBeforeOW else "No warning will be shown before you overwrite an existing file"))
            
            elif settingsCmd[4] == '4' :
                if outModeEncrypt != 0 :
                     printy("Any content you encrypt will be outputed to " + (file_name if outModeEncrypt == 1 else "screen directly"), "c")
                else : printy("ZCrypt will always ask you if you want to save your encrypted content to a file or if you want to print it on screen", "c")
            
            elif settingsCmd[4] == '5' :
                if encryptionMode == "ask" : printy("ZCrypt will always ask you if you want to encrypt a message using ZCrypt algorithm or RSA", 'c')
                elif encryptionMode == "RSA" : printy("ZCrypt will always encrypt using RSA", "c")
                else : printy("ZCrypt will always encrypt your messages using ZCrypt algorithm")

            elif settingsCmd[4] == '6' :
                printy("RSA uses public and private keys to encrypt/decrypt content. These keys are made of very high numbers (more than 20 digits)", "c")
                printy("Currently RSA keys have a length of " + str(rsaKeyBytes) + " bits", "c")
            
            else :
                printy("Error ! The option you tried to view does not exists or does have a number assigned to it", "m")

        
        elif 'set' in settingsCmd and len(settingsCmd) == 5 :
            if settingsCmd[4] == '1' :
                fileOutput = input("Please enter the name of file you want to be saved as. Don't forget to ad (.txt) at the end ! : ")
                printy("Sucess : the name of the output file has been successfully changed to", "n", end = ' ')
                printy(fileOutput, 'n')

            elif settingsCmd[4] == '2' :
                printy("You have the choice between 4 date formats : 1) dd/mm/YYYY, 2) dd/mm/YY, 3) YYYY-mm-dd or just the 4) plain text format", 'c')
                choice = inputy("Please enter the number of the date format you want to use (1, 2, 3 or 4) : ", 'c')
                try :
                    if int(choice) <= 4 and int(choice) > 0 :
                        dateFormat = choice
                        printy('Success : set date format to ' + dateFormatDict[choice], 'n')
                    else :
                        printy("Error : " + choice + " is not an offered choice", 'm')
                except ValueError : printy("Error : Please enter an integer", "m")

            elif settingsCmd[4] == '3' :
                printy("Sometimes when you encrypt a file, another file with the same name already exists", 'c')
                printy("When this happens, ZCrypt offers you to choice between overwriting the existing file or doing nothing", 'c')
                printy("When the file is overwritten, you lose all the data stored on it. This is why we recommend you to backup its content before overwriting", 'c')
                print("")
                printy("If you have to save files often, these warning may bore you. If this is so you can disable this warning by typing \"disable\"", 'c')
                printy("You don't want to disable this warning type anything except \"disable\"", 'c')
                printy("Please be careful when disabling this warning. You could lose important data and ZCrypt assumes no responsability in this. Do it at your own risk", 'm')
                testdisable = input("Input : ")
                if testdisable == "disable" :
                    printy("Caution : Warning before overwrite is now disabled", 'y')
                    warnBeforeOW = False
                else :
                    printy("Nothing has been changed", 'n')
                    printy("Returning...", 'n')

            elif settingsCmd[4] == "4" :
                printy("Starting from V2.3 you can now chose what you want ZCrypt to do with your encrypted content", 'c')
                printy("3 values are available for this setting : 0, 1 and 2", "c")
                printy("If you choose 0, ZCrypt will always ask you if you want to save to a file or just show the content on screen", "c")
                printy("If you choose 1, ZCrypt will always save your encrypted content to a file, here " + fileOutput, "c")
                printy("If you choose 2, ZCrypt will always output your encrypted content to your screen", "c")
                printy("Note : mode 2 works just like ZCypt used to function in releases before V2.3", 'c')
                choice = input("Input : ")
                try :
                    if 0 <= int(choice) <= 2 : 
                        outModeEncrypt = int(choice)
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
                printy("Note : ZCrypt algorithm is much less secure but offers many more features (such as addind a sender, reciever and date to your message. On the other hand RSA is much more secure (used by thousands of companies) but can only encrypt messages", "y")
                choice = input("Input : ")
                if choice.lower() == "ask" : encryptionMode = "ask"; printy("Successfully set encryption mode to " + choice, 'n')
                elif choice.lower() == "rsa" : encryptionMode = "RSA"; printy("Successfully set encryption mode to " + choice, 'n')
                elif choice.lower() == "zcrypt" : encryptionMode = "zcrypt"; printy("Successfully set encryption mode to " + choice, 'n')
                else : 
                    printy("The value you entered is not valid. Please note that ZCrypt has been saved as default value", "m")
                    encryptionMode = "zcrypt"

            elif settingsCmd[4] == '6' :
                printy("RSA uses public and private keys to encrypt/decrypt content. These keys are made of very high numbers (more than 20 digits)", "c")
                printy("You can set the length of these numbers by entering the number of bits which must be a pow of 2 (256, 512, 1024, 2048...)", "c")
                printy("The highest number of bits, the higher security but also the longer time to generate the keys", "c")
                printy("By default this value is set to 1024. We do not recommend to enter a number lower than 256 (too low encryption) and higher than 4096 (your computer could take minutes to generate keys)", "c")
                choice = input("Input : ")
                try :
                    choice = int(choice)
                    if choice > 4096 or choice < 256 :
                        printy("Warning : you entered non-recomended values. Expect low security/crashes/slowness when generating keys", 'y')
                        rsaKeyBytes = choice
                    else :
                        rsaKeyBytes = choice
                        printy("Success : set RSA keys length to " + str(choice) + " bytes", 'n')
                except ValueError :
                    printy("Error : please enter an integer", "m")

            else :
                printy("Error : the option you tried to view does not exists or does have a number assigned to it", "m")


        elif settingsCmd == 'exit' :
            break

        else :
            printy("Error : either this command is unknown either it does not use the needed format ! See the manual to learn more ", "m")
    

if __name__ == '__main__' :
    #Welcome screen
    printy("#######################", "c>")
    printy("# Welcome to ZCrypt ! #", "c>")
    printy("#######################", "c>")
    printy("Here are the commands you can use : encrypt, decrypt and you can also see the user manual by typing \"manual\"", "n>")
    printy("If this is your first time using the program, please consider using the \"instructions\" command", "n>")
    printy("If you want to access the settings, type \"settings\"", "n>")
    printy("You can also exit the program by typing \"quit\"", "n>")                                                
        
    #main loop
    while True :
        print("")
        printy("Please input a command ", "c")
        command = input(">>> ")

        if "encrypt" in command :
            #Here, the user inputs all informations required to encrypt
            print("Ok ! Let's encrypt your message !")
            if encryptionMode == "ask" :
                cryptMode = input("Do you want to crypt using ZCrypt algorithm or RSA (see Manual for details) ? (RSA/zcrypt) ")
                prepareEncryptedOutput(cryptMode)
            else : prepareEncryptedOutput(encryptionMode)


        elif "decrypt" in command :
            Error_Code = ""
            decryptMode = input("Was your file encrypted with RSA or ZCrypt algorithm (ask the sender if you don't know) ? (RSA/zcrypt) ")
            printy("Please specify the COMPLETE name of the file with the .txt end !", "c")
            file_name = input()
            if decryptMode.lower() == "zcrypt" :
                printy("Info : entering ZCrypt decryption mode...", "c")
                if ZfileCheck() :
                    printy("Your file was successfully checked and no file integrity errors were found. Continuing...", "n")
                    ZretrieveKey()
                    processDecrypted(ZdecryptMessage(), ZdecryptSender(), ZdecryptReciever(), ZdecryptTime())
                else :
                    printy("Error ! Either the file specified does not use the needed format for the program either it is corrupted.", "m")
                    print("Aborting...")
            else :
                printy("Info : entering RSA decryption mode...", "c")
                if RfileCheck() : 
                    printy("Your file was successfully checked and no file integrity errors were found. Continuing...", "n")
                    privKey = RretrieveKey()
                    if privKey != None :
                        RmainDecrypt()
                    else : print("Aborting...")
                else : printy("Error : file not found or corrupted", "m")

        elif "settings" in command :
            settings()

        elif "showErrors" in command : 
            if Error_Code != "" :
                print("We are sorry to hear that your file has a problem")
                print("Here is your error code :", Error_Code)
                print("This is an excract from the UserManual where your error code is discussed")

                #Showing info about the error code starting with ...
                manual_file = open("UserManual.txt", "r")
                
                #Explaining the error itself
                all_lines = manual_file.readlines()
                for line in range(len(all_lines)) :
                    if Error_Code in all_lines[line] : print(all_lines[line])
                
            else :
                printy("Your file has been decrypted without any errors.", "c")

        elif "manual" in command :
            manual_file = open("UserManual.txt", "r")
            manual_text = manual_file.readlines()
            for line in range(len(manual_text)) :
                print(manual_text[line])

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
            print("You can use the \"showErrors\" command !")
            print("")

            print("Enjoy !")

        elif command == 'exit' :
            printy("Thank you for using ZCrypt ! See you soon...", "c")
            exit()
        
        else :
            printy("Sorry this command is unknown. Please try again", "m")
            if 'encr' in command : printy("Did you mean \"encrypt\" command ?", "y")
            elif 'decr' in command : printy("Did you mean \"decrypt\" command ?", "y")
