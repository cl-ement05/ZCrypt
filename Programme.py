from datetime import datetime
from calendar import day_name
from random import randint
from printy import printy, inputy
import rsa

file = ''
Error_Code = str()

#Default settings
fileOutput = "Mail.txt"
dateFormat = '1'
warnBeforeOW = True
defaultName = "Decryted.txt"
outModeEncrypt = 0

lastKey = 15                                            #This line runs just once, at the programm start because the encryption module needs the last key (and there is no last key at the first time)


def fileCheck() -> bool :
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


#Here all functions are defined
#Gets the key which is encrypted in binary
def ZkeySettings() :
    key = line4
    global keyMethod
    global decryptKey
    decryptKey = int(key, 2)
    if decryptKey % 2 == 0 :
        keyMethod = 'plus'
    else :
        keyMethod = 'minus'

#Encrypts the key
def ZkeySetup() :
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


#All this part contains child functions used for encrypting
#Encrypting date and time
def ZencryptTime() :
    finalTimeEncr = ''
    finalTimeList = list()
    now = datetime.now()
    current_time = now.strftime("%d/%m/%Y %H:%M:%S")

    for element in range(len(current_time)) :
        #This try is used to skip date characters like (/ and :) that cannot be encrypted and will be removed
        try :
            test = int(current_time[element])
        except ValueError :
            if current_time[element] != '/' and current_time[element] != ':' and current_time[element] != ' ' :
                printy("Sorry there was an error. Please try again", "m")
                exit()

        #If the try passes and the current element is an integer (so a number that is part from the date), encyption starts
        else :
            encrypted_int = int(str(current_time[element])) + int(keyNum)
            finalTimeList.append(str(encrypted_int))

    finalTimeEncr = "".join(finalTimeList)

    assert(len(finalTimeEncr) == 28)
    return finalTimeEncr


#Encrypting sender
def ZencryptSender() :
    senderEncr = ''
    for character in range(len(sender)) :
        senderAscii = ord(sender[character])
        senderEncr += chr(mainEncrypt(senderAscii))
    return senderEncr

#Encrypts receiver
def ZencryptReciever() :
    recieverEncr = ''
    for character in range(len(reciever)) :        
        recieverAscii = ord(reciever[character])
        recieverEncr += chr(mainEncrypt(recieverAscii))
    return recieverEncr

#Main encrypt engine
def mainEncrypt(toEncrypt: int) -> int :             #takes a single int argument which must be the ascii representation of a char; returns the encrypted ascii
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
def Zencrypt() :
    finalMessageBinary = list()

    for i in range(len(message_input)) :
        #Transforms the character in its ascii number
        currentChr = message_input[i]
        asciiChr = ord(currentChr)

        #Spaces are encoded as is they were "~" (its ascii is 126) so to avoid errors, the programm does not support this character
        if asciiChr == 126 :
            printy("Error ! Your message contains a character that is not supported", "m")
            break

        asciiEncr = mainEncrypt(asciiChr)
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

    printy("Your key is :", 'c', end = ' ')
    printy(str(keyNum), 'c')
    return finalMessageBinary


#Get all settings and encrypted variables from child functions and starts the writeFile function to apply changes
def prepareEncryptedOutput(cryptingMode: str) :

    if cryptingMode.lower() == "zcrypt" :
        printy("Info : entering ZCrypt encryption mode...", "c")

        ZkeySetup()                          #creates a new key shared accross whole program
        finalTimeEncr = ZencryptTime()
        senderEncr = ZencryptSender()
        recieverEncr = ZencryptReciever()
        finalMessageBinary = Zencrypt()
    else :
        printy("Info : entering RSA encryption mode...", "c")



    txt = False                      #boolean variable which is set to true when the file name specified by user is valid that's to say, ends with ".txt"
    messageStr = "".join(finalMessageBinary)

    for letter in range(len(fileOutput)) :
        if fileOutput[letter] == '.' and fileOutput[letter + 1] == 't' and fileOutput[letter + 2] == 'x' and fileOutput[letter + 1] == 't' :
            txt = True

    if txt :
        try :
            testfileOW = open(fileOutput, "r")            #opening in read mode the name specified by the user so that if a file with the same already exists, no error will be raised
        except FileNotFoundError :                         #else if an error is thrown, file was not found so no file will be overwritten -> writeFile
            writeFile(finalTimeEncr, senderEncr, recieverEncr, keyBin, messageStr)

        else :
            if warnBeforeOW :                          #boolean setting 1 -> warn user that a file will be overwritten
                printy("Warning !", 'y', end = ' ')
                printy(fileOutput, 'y', end = ' ')
                printy("already exists.", 'y')
                printy("If you continue the encryption process, the existing file will be overwritten", 'y')
                printy("This will irremediably delete its current data", 'y')
                printy("We highly recommend you to backup this file if personnal infos are stored on it", 'y')
                printy("Are you sure you want to continue ? (y/n)", 'y', end = '')
                firstanswer = input(" ")
                if firstanswer == "y" :
                    printy(fileOutput, 'y', end = ' ')
                    printy("will be overwritten !! Proceed anyway ? (y/n)", 'y', end ='')
                    confirmation = input(" ")
                    if confirmation == "y" :
                        writeFile(finalTimeEncr, senderEncr, recieverEncr, keyBin, messageStr)    #after user confirmation that file can be overwritten -> writeFile
                    else :
                        printy("OK. Encryption aborted", 'c') 
                else :
                    printy("OK. Encryption aborted", 'c')     
            
            #if the warning has been disabled
            else :
                writeFile(finalTimeEncr, senderEncr, recieverEncr, keyBin, messageStr)
                printy("Note : a file has been overwritten", "y")

    else :
        printy("Error ! The name of the file you want to save is incorect. Please try another one !", 'm')



#Write all encrypted content to the file using the settings prepared by the prepareEncryptedOutputt function
def writeFile(timeW: str, senderW: str, recipientW: str, keyW: str, messageW: str) :
    #'\n' is used to go to a new line at every new file settings
    file_w = open(fileOutput, "w")
    file_w.write(timeW)
    file_w.write("\n")
    file_w.write(senderW)
    file_w.write("\n")
    file_w.write(recipientW)
    file_w.write("\n")
    file_w.write(keyW)
    file_w.write("\n")
    file_w.write(messageW)
    file_w.close()

    printy("Done ! Your message has been securely encrypted !", 'n')


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
        senderDecr += chr(mainDecrypt(sender_chr))

    senderDecr = senderDecr[:(len(senderDecr) - 1)]                                                  #This line removes the 0 that spaws after the name
    return senderDecr


def ZdecryptReciever() :
    recieverEncr = line3
    recieverDecr = ''
    for character in range(len(recieverEncr)) :
        reciever_chr = ord(recieverEncr[character])
        recieverDecr += chr(mainDecrypt(reciever_chr))

    recieverDecr = recieverDecr[:(len(recieverDecr) - 1)]                                                  #This line removes the 0 that spaws after the name
    return recieverDecr    

#main decrypt engine
def mainDecrypt(toencrypt: int) -> int :
    if keyMethod == 'plus' :
        if toencrypt + decryptKey <= 126 :
            decryptedAscii = toencrypt + decryptKey
            
        elif toencrypt + decryptKey > 126 :                     # Will be enabled if the decrypted ascii number is out of range of the ascii table
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
    
    if decryptedAscii == 126 : return 32    #Since spaces are encrypted as a "~", if the programm finds an ascii of 126 (which is the code of ~), it transoforms the ~ character into a space
    else : return decryptedAscii

#decrypting message
def Zdecrypt() :
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
        decryptedAscii = mainDecrypt(charAsciiEncr)

        finalDecrypted += chr(decryptedAscii)
    return finalDecrypted


#This function gather all decrypted variables processed by the other functions (decryptTime, decrypt...) and does action following the outMode setting 4
def printDecrypted(senderDecr: str, recieverDecr: str, finalDecrypted: str) :
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

    printy("We finished decrypting your file !", "n")
    print("")

    dateDecr = ZdecryptTime()

    finalEntireDate = ''
    #changing the final str according to what user specified for date format
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
            printy("OK. Entering print mode...")
            printOutMode(senderDecr, recieverDecr, finalDecrypted, finalEntireDate, finalEntireTime)
        else :
            printy("OK. Entering file mode...")
            saveToExtFile(senderDecr, recieverDecr, finalDecrypted, finalEntireDate, finalEntireTime)
    elif outModeEncrypt == 1 : saveToExtFile(senderDecr, recieverDecr, finalDecrypted, finalEntireDate, finalEntireTime)
    else : printOutMode(senderDecr, recieverDecr, finalDecrypted, finalEntireDate, finalEntireTime)


def printOutMode(senderDecr, recieverDecr, finalDecrypted, date, time) :
    printy("This message was created " + date + ' at ' + time, "c>")
    print("")

    printy(senderDecr + " sent it !", "c>")
    print("")

    printy(recieverDecr + " should recieve it !", "c>")
    print("")

    printy("And the message is : " + finalDecrypted, "c>")

    print("")


def saveToExtFile(senderDecr, recieverDecr, finalDecrypted, date, time) :
    print("")
    printy("Please enter the name of file you want to save. Please note this name MUST end with .txt", 'c')
    printy("If the name you enter is not a valid one, the default name,", 'c', end = ' ')
    printy(defaultName, 'c', end = ' ')
    printy("will be used", 'c')
    filename = inputy("Enter file name : ")
    print("")
    
    #because e.g. filname is "abc" then abc[-4:] returns "abc" and ".txt" is 4 char long so in order to have a valid name both len() > 4 and ends with ".txt" is required 
    if not (len(filename) > 4 and filename[-4:] == ".txt") :
        printy("Error the name you entered is not valid", 'm')
        printy(defaultName, "y", end = " ")
        printy("will be used instead" ,'y')
        filename = defaultName
    
    fileToWrite = open(filename, 'w')
    fileToWrite.write("Timestamp : ")
    fileToWrite.write(date + ' at ' + time)
    fileToWrite.write("\n")
    fileToWrite.write("Sender : ")
    fileToWrite.write(senderDecr)
    fileToWrite.write("\n")
    fileToWrite.write("Reciever : ")
    fileToWrite.write(recieverDecr)
    fileToWrite.write("\n")
    fileToWrite.write("Message : ")
    fileToWrite.write(finalDecrypted)
    fileToWrite.close()

    printy("All the decrypted data has been securely saved to", 'c', end = ' ')
    printy(filename, 'c')


def findDayDate(date) :
    dayNumber = datetime.strptime(date, '%d %m %Y').weekday()
    return (day_name[dayNumber])


def settings() :
    global fileOutput
    global dateFormat
    global warnBeforeOW
    global outModeEncrypt
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
    printy("    - 4: encrypted content output mode\n", "c")

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

            
            else :
                printy("Error ! The option you tried to view does not exists or does have a number assigned to it", "m")

        
        elif 'set' in settingsCmd and len(settingsCmd) == 5 :
            if settingsCmd[4] == '1' :
                fileOutput = input("Please enter the name of file you want to be saved as. Don't forget to ad (.txt) at the end ! : ")
                printy("Done ! The name of the output file has been successfully changed to", "n", end = ' ')
                printy(fileOutput, 'n')

            elif settingsCmd[4] == '2' :
                printy("You have the choice between 4 date formats : 1) dd/mm/YYYY, 2) dd/mm/YY, 3) YYYY-mm-dd or just the 4) plain text format", 'c')
                choice = inputy("Please enter the number of the date format you want to use (1, 2, 3 or 4) : ", 'c')
                try :
                    if int(choice) <= 4 and int(choice) > 0 :
                        dateFormat = choice
                        printy('Successfully set date format to ' + dateFormatDict[choice], 'n')
                    else :
                        printy("Error ! " + choice + " is not an offered choice", 'm')
                except ValueError : printy("Please enter an integer", "m")

            elif settingsCmd[4] == '3' :
                printy("Sometimes when you encrypt a file, another file with the same name already exists", 'c')
                printy("When this happens, ZCrypt offers you to choice between overwriting the existing file or doing nothing", 'c')
                printy("When the file is overwritten, you lose all the data stored on it. This is why we recommend you to backup its content before overwriting", 'c')
                print("")
                printy("If you have to save files often, these warning may bore you. If this is so you can disable this warning by typing \"disable\"", 'c')
                printy("You don't want to disable this warning type anything except \"disable\"", 'c')
                printy("Please be careful when disabling this warning. You could lose important data and ZCrypt assumes no responsability in this. Do it at your own risk", 'm')
                testdisable = inputy("Input : ")
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
                printy("Note : mode 1 works just like ZCypt used to function in releases before V2.3", 'c')
                printy("If you choose 2, ZCrypt will always output your encrypted content to your screen", "c")
                choice = inputy("Input :  ")
                try :
                    if 0 <= int(choice) <= 2 : 
                        outModeEncrypt = int(choice)
                        printy("Successfully set output mode to " + choice, 'n')
                    else : printy(choice + " is not an offered choice", "m")
                except ValueError :
                    printy("Please enter an integer", "m")
            
            else :
                printy("Error ! The option you tried to view does not exists or does have a number assigned to it", "m")


        elif settingsCmd == 'exit' :
            break

        else :
            printy("Error ! Either this command is unknown either it does not use the needed format ! See the manual to learn more ", "m")
    


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

    if command == "encrypt" :
        #Here, the user inputs all informations required to encrypt
        print("Ok ! Let's encrypt your message !")
        message_input = input("First, type the message you want to encrypt : ")
        sender = input("Please type your name that will be used in the file as the sender information : ")
        reciever = input("Finally, type the reciever of this message : ")

        cryptMode = input("Do you want to crypt using ZCrypt algorithm or RSA (see Manual for details) ? (RSA/zcrypt) ")

        prepareEncryptedOutput(cryptMode)


    elif command == "decrypt" :
        Error_Code = ""
        printy("Please specify the COMPLETE name of the file with the .txt end !", "c")
        file_name = input()
        if fileCheck() :
            printy("Your file was successfully checked and no file integrity violations were found. Continuing...", "n")
            ZkeySettings()
            printDecrypted(ZdecryptSender(), ZdecryptReciever(), Zdecrypt())
        else :
            printy("Error ! Either the file specified does not use the needed format for the program either it is corrupted.", "m")
            print("Aborting...")

    elif command == "settings" :
        settings()

    elif command == "showErrors" : 
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

    elif command == "manual" :
        manual_file = open("UserManual.txt", "r")
        manual_text = manual_file.readlines()
        for line in range(len(manual_text)) :
            print(manual_text[line])

    elif command == "instructions" :
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
        printy("Thanks for using ZCrypt ! See you soon...", "c")
        exit()
    
    else :
        printy("Sorry this command is unknown. Please try again", "m")
        if 'encr' in command : printy("Did you mean \"encrypt\" command ?", "y")
        elif 'decr' in command : printy("Did you mean \"decrypt\" command ?", "y")
