from datetime import date, datetime
from calendar import day_name
from random import randint
from printy import printy, inputy

file_test = False
file = ''
Error_Code = list()
file_output = "Mail.txt"

#Default settings
date_format = '1'
warnBeforeOW = True
defaultName = "Decryted.txt"
outModeEncrypt = 0

last_key = 15


def fileCheck() -> bool :
#All this section checks the file integrity and assings all the lines to a dynamic variable
    global line1
    global line2
    global line3
    global line4
    global line5

    try :
        file = open(file_name, 'r+')
    except FileNotFoundError :
        Error_Code.append("E101")
        return False

    else :
        text = file.readlines()

        # Checks if the file has 5 lines
        if len(text) > 5 or len(text) < 5 :
            Error_Code.append("E201")
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
            Error_Code.append("E202")
            return False


        if len(line1) == 29 :                                                              #29 because there is a \n at the end of the line and the n is a character
            try :
                test21 = int(line1[:28])
            except ValueError :
                Error_Code.append("E301")
                return False
        else :
            Error_Code.append("E302")
            return False

        if len(line4) == 9 :
            try :
                test = int(line4, 2)
            except ValueError :
                Error_Code.append("E313")
                return False
        else :
            Error_Code.append("E314")
            return False

        if ';' in line5 :
            try :
                test3 = int(line5[:24])
            except ValueError :
                Error_Code.append("E325")
                return False
        else :
            Error_Code.append("E326")
            return False
    
    return True


#Here all functions are defined
#Gets the key which is encrypted in binary
def keySettings() :
    key = line4
    global key_method
    global decrypt_key
    decrypt_key = int(key, 2)
    if decrypt_key % 2 == 0 :
        key_method = 'plus'
    else :
        key_method = 'minus'

#Encrypts the key
def keySetup() :
    global key_num
    global key_bin
    global last_key
    key_num = randint(10, 40)
    #All this part tests if the current key is far enough from the last key to the message be securely encyrpted
    key_diff = False
    while key_diff == False :
            
        if key_num > last_key :
            if (key_num - last_key) > 15 :
                key_diff = True
            else :
                key_num = randint(10, 40)
            
        elif key_num < last_key :
            if (last_key - key_num) > 15 :
                key_diff = True
            else :
                key_num = randint(10, 40)
            
        elif key_num == last_key :
                key_num = randint(10, 40)
    
    last_key = key_num
    key_bin = format(key_num, '08b')

#All this part contains all functions used for encrypting
def encryptTime() :
    final_time_encr = ''
    final_time_list = list()
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
            encrypted_int = int(str(current_time[element])) + int(key_num)
            final_time_list.append(encrypted_int)

    #Now all the date components are encrypted and in the list
    for original_number in range(len(final_time_list)) :
        final_time_encr += str(final_time_list[original_number])

    assert(len(final_time_encr) == 28)
    return final_time_encr


#Finding and encrypting sender
def encryptSender() :
    sender_encr = ''
    for character in range(len(sender)) :
        sender_ascii = ord(sender[character])
        sender_encr += chr(mainEncrypt(sender_ascii))
    return sender_encr


def encryptReciever() :
    reciever_encr = ''
    for character in range(len(reciever)) :        
        reciever_ascii = ord(reciever[character])
        reciever_encr += chr(mainEncrypt(reciever_ascii))
    return reciever_encr

def mainEncrypt(toEncrypt) -> int :
    #If the key is a pair number
    if key_num % 2 == 0 :
        if toEncrypt - key_num >= 33 :
            encrypted = toEncrypt - key_num

        elif toEncrypt - key_num < 33 :
            cut = 0
            while toEncrypt >= 33 :
                toEncrypt -= 1
                cut += 1
            remaining_key = key_num - cut
            encrypted = 126 - remaining_key

    #If the key is an impair number
    elif key_num % 2 == 1 :
        if toEncrypt + key_num <= 126 :
            encrypted = toEncrypt + key_num

        elif toEncrypt + key_num > 126 :
            cut = 0
            while toEncrypt <= 126 :
                toEncrypt += 1
                cut += 1
            remaining_key = key_num - cut
            encrypted = 33 + remaining_key

    return encrypted


#Main encrypt engine
def encrypt() :
    keySetup()

    check = 0
    final_message_binary = list()

    nbr_letters = len(message_input)
    for _ in range(nbr_letters) :
        #Transforms the character in its ascii number
        current_chr = message_input[check]
        ascii_chr = ord(current_chr)

        #Spaces are encoded as is they were "~" (its ascii is 126) so to avoid errors, the programm does not support this character
        if ascii_chr == 126 :
            printy("Error ! Your message contains a character that is not supported", "m")
            break

        #If the key is a pair number
        ascii_encr = mainEncrypt(ascii_chr)
        letter_binary = list()
        #If the Ascii number contains only two numbers, the programm adds a 0 in front oh the two to get a number with 3 binaires at the end
        if len(str(ascii_encr)) == 2 :
            letter_binary.append('00000000')
            for ascii_nbr in range(2) :
                letter_binary.append(format(int(str(ascii_encr)[ascii_nbr]), '08b'))

        elif len(str(ascii_encr)) == 3 :
            for ascii_nbr in range(3) :
                letter_binary.append(format(int(str(ascii_encr)[ascii_nbr]), '08b'))

        assert(len(letter_binary) == 3)
        check += 1

        letter_binary.append(';')                                       #Adds the separator (;) to make difference between de letters
        letter_str = ''
        for x in range(4) :
            letter_str += letter_binary[x]

        final_message_binary.append(letter_str)

    printy("Your key is :", 'c', end = ' ')
    printy(str(key_num), 'c')
    return final_message_binary

#Get all settings and variables and starts the writeFile function to apply changes with the variables
def prepareOutput() :
    #Rajouter ici la fonction qui va faire tt les cmd liées au serv

    txt = False
    message_str = ''
    message_binary = encrypt()
    for i in range(len(message_binary)) :
        message_str += message_binary[i]
    assert(type(message_str) is str)

    for letter in range(len(file_output)) :
        if file_output[letter] == '.' and file_output[letter + 1] == 't' and file_output[letter + 2] == 'x' and file_output[letter + 1] == 't' :
            txt = True

    if outModeEncrypt == 0 :
        choiceMode = inputy("Would you like to output the encrypted content to be saved to a file or simply to be displayed on screen ? (FILE/print) ", "c")
        if choiceMode == "print" :
            printy("OK. Entering print mode...")
            printOutMode(message_str)
        else :
            printy("OK. Entering file mode...")
            fileModeOut(message_str, txt)
    elif outModeEncrypt == 1 : fileModeOut(message_str, txt)
    else : printOutMode(message_str)

def printOutMode(message_str) :
    print(encryptTime())
    print(encryptSender())
    print(encryptReciever())
    print(key_bin)
    print(message_str)

def fileModeOut(final_message_str, txt) :
    if txt :
        try :
            testfileOW = open(file_output, "r")

        except FileNotFoundError :
            writeFile(encryptTime(), encryptSender(), encryptReciever(), key_bin, final_message_str)

        else :

            if warnBeforeOW :
                printy("Warning ! " + file_output + ' already exists', 'y')
                printy("If you continue the encryption process, the existing file will be overwritten", 'y')
                printy("This will irremediably delete its current data", 'y')
                printy("We highly recommend you to backup this file if personnal infos are stored on it", 'y')
                printy("Are you sure you want to continue ? (y/n)", 'y', end = '')
                firstanswer = input(" ")
                if firstanswer == "y" :
                    printy(file_output + " will be overwritten !! Proceed anyway ? (y/n)", 'y', end = '')
                    confirmation = input(" ")
                    if confirmation == "y" :
                        writeFile(encryptTime(), encryptSender(), encryptReciever(), key_bin, final_message_str)
                    else :
                        printy("OK. Encryption aborted", 'c') 
                else :
                    printy("OK. Encryption aborted", 'c')     
            
            #if the warning has been disabled
            else :
                writeFile(encryptTime(), encryptSender(), encryptReciever(), key_bin, final_message_str)
                printy("Note : a file has been overwritten", "y")            

    else :
        printy("Error ! The name of the file you want to save is incorect. Please try another one !", 'm')





#Write all changes to the file using the settings prepared by the prepareOutput function
def writeFile(time_w, sender_w, recipient_w, key_w, message_w) :
    #'\n' is used to go to a new line at every new file settings
    file_w = open(file_output, "w")
    file_w.write(time_w)
    file_w.write("\n")
    file_w.write(sender_w)
    file_w.write("\n")
    file_w.write(recipient_w)
    file_w.write("\n")
    file_w.write(key_w)
    file_w.write("\n")
    file_w.write(message_w)
    file_w.close()

    printy("Done ! Your message has been securely encrypted !", 'n')


#Decrypts the date and time
def decryptTime() :
    #Here, the entire line1 that contains the date is spread in different variables
    chSize = 2
    date = line1[:(chSize * 8)]
    time = line1[(chSize * 8):]

    #Spreading the time list into the hour, minutes...
    hour = time[:4]
    minutes = time[4:8]
    seconds = time[8:]

    #Spreading the date list into the days, months...
    day = date[:4]
    month = date[4:8]
    year = date[8:]

    try :
        hour = int(hour)
        minutes = int(minutes)
        seconds = int(seconds)
    except ValueError :
        raise ValueError()

    #Decrypting days
    day1_decrypted = int(day[:2]) - decrypt_key                  #first number => 2 because ChSize is 2
    day2_decrypted = int(day[2:]) - decrypt_key
    day_decrypted = str(day1_decrypted) + str(day2_decrypted)
    if len(str(day_decrypted)) == 1 :
        nbr = str(day_decrypted)[0]
        day_decrypted = str(0) + str(nbr)

    #Decrypting the month
    month1_decrypted = int(month[:2]) - decrypt_key
    month2_decrypted = int(month[2:]) - decrypt_key
    month_decrypted = str(month1_decrypted) + str(month2_decrypted)
    if len(str(month_decrypted)) == 1 :
        nbr = str(month_decrypted)[0]
        month_decrypted = str(0) + str(nbr)

    #Decrypting the year
    year1_decrypted = int(year[:2]) - decrypt_key
    year2_decrypted = int(year[2:4]) - decrypt_key
    year3_decrypted = int(year[4:6]) - decrypt_key
    year4_decrypted = int(year[6:]) - decrypt_key
    year_decrypted = str(year1_decrypted) + str(year2_decrypted) + str(year3_decrypted) + str(year4_decrypted)

    #Decrypting hour
    hour1_decrypted = hour[:2] - decrypt_key
    hour2_decrypted = hour[2:] - decrypt_key
    hour_decrypted = str(hour1_decrypted) + str(hour2_decrypted)
    if len(str(hour_decrypted)) == 1 :
        nbr = str(hour_decrypted)[0]
        hour_decrypted = str(0) + str(nbr)

    #Decrypting minutes
    min1_decrypted = minutes[:2] - decrypt_key
    min2_decrypted = minutes[2:] - decrypt_key
    min_decrypted = str(min1_decrypted) + str(min2_decrypted)
    if len(str(min_decrypted)) == 1 :
        nbr = str(min_decrypted)[0]
        min_decrypted = str(0) + str(nbr)

    #Decrypting seconds
    sec1_decrypted = seconds[:2] - decrypt_key
    sec2_decrypted = seconds[2:] - decrypt_key
    sec_decrypted = str(sec1_decrypted) + str(sec2_decrypted)
    if len(str(sec_decrypted)) == 1 :
        nbr = str(sec_decrypted)[0]
        sec_decrypted = str(0) + str(nbr)

    return day_decrypted, month_decrypted, year_decrypted, hour_decrypted, min_decrypted, sec_decrypted

def decryptSender() :
    sender_encr = line2
    sender_decr = ''
    for character in range(len(sender_encr)) :
        sender_chr = ord(sender_encr[character])
        sender_decr += chr(mainDecrypt(sender_chr))

    sender_decr = sender_decr[:(len(sender_decr) - 1)]                                                  #This line removes the 0 that spaws after the name
    return sender_decr


def decryptReciever() :
    reciever_encr = line3
    reciever_decr = ''
    for character in range(len(reciever_encr)) :
        reciever_chr = ord(reciever_encr[character])
        reciever_decr += chr(mainDecrypt(reciever_chr))

    reciever_decr = reciever_decr[:(len(reciever_decr) - 1)]                                                  #This line removes the 0 that spaws after the name
    return reciever_decr    


def mainDecrypt(toencrypt) -> int :
    if key_method == 'plus' :
        if toencrypt + decrypt_key <= 126 :
            decrypted_ascii = toencrypt + decrypt_key
            
        elif toencrypt + decrypt_key > 126 :                     # Will be enabled if the decrypted ascii number is out of range of the ascii table
            cut = 0
            while toencrypt <= 126 :
                toencrypt += 1
                cut += 1
            remaining_key = decrypt_key - cut
            decrypted_ascii = 33 + remaining_key

    elif key_method == 'minus' :
        if toencrypt - decrypt_key >= 33 :
            decrypted_ascii = toencrypt - decrypt_key
            
        elif toencrypt - decrypt_key < 33 :
            cut = 0
            while toencrypt >= 33 :
                toencrypt -= 1
                cut += 1
            remaining_key = decrypt_key - cut
            decrypted_ascii = 126 - remaining_key
    
    return decrypted_ascii

def decrypt() :
    keySettings()                                                                  #Decrypts the key in the file and find its method
    final_decrypted = ''

    nbr_letters = int(len(line5) / 25)
    message_encr = line5.split(";")
    for letter in range(nbr_letters) :
        encr_character = message_encr[letter]

        #Transforms the binary string into an ascii number
        binary_ch1 = encr_character[:8]
        encrypted_ascii1 = int(binary_ch1, 2)

        a = encr_character[8:]
        binary_ch2 = a[:8]
        encrypted_ascii2 = int(binary_ch2, 2)

        binary_ch3 = encr_character[16:]
        encrypted_ascii3 = int(binary_ch3, 2)

        char_asciiencr = int(str(encrypted_ascii1) + str(encrypted_ascii2) + str(encrypted_ascii3))            # Joins the three ascii numbers got from the binaries
        #print("Encrypted ascii:", char_asciiencr)
        #The encrypt/decrypt method is different for pair/impair numbers
        decrypted_ascii = mainDecrypt(char_asciiencr)

        #Since spaces are encrypted as a "~", if the programm finds an ascii of 126 (which is the code of ~), he transoforms the ~ character into a space
        if decrypted_ascii == 126 :
            decrypted_ascii = 32

        final_decrypted += chr(decrypted_ascii)
    return final_decrypted


#This function gather all decrypted variables processed by the other functions (decryptTime, decrypt...) and prints everything in a user friendly presentation
def printDecrypted(sender_decr, reciever_decr, final_decrypted) :
    #list of the months to know which month number corresponds to what month in plain text
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
    printy("Here is everything you need to know about it :", "n")
    print("")

    date_decr = decryptTime()

    finalEntireDate = ''
    if date_format == '1' :
        finalEntireDate = date_decr[0] + '/' + date_decr[1] + '/' + date_decr[2]
    elif date_format == '2' :
        finalEntireDate = date_decr[0] + '/' + date_decr[1] + '/' + date_decr[2][2:4]
    elif date_format == '3' :
        finalEntireDate = date_decr[2] + '/' + date_decr[1] + '/' + date_decr[0]
    elif date_format == '4' :
        month_text = references['months'][date_decr[1]]
        
        #Used to find the day of the week with the date number
        dayWeek = findDayDate(date_decr[0] + ' ' + date_decr[1] + ' ' + date_decr[2])

        #This part analysis what is the day and adds the 'th', 'st'... at the end
        completeDay = ''
        if date_decr[0] == 1 :
            completeDay = date_decr[0] + 'st'
        elif date_decr[0] == 2 :
            completeDay = date_decr[0] + 'nd'
        elif date_decr[0] == 3 :
            completeDay = date_decr[0] + 'rd'
        else :
            completeDay = date_decr[0] + 'th'
        
        finalEntireDate = dayWeek + ", " + month_text + " the " + completeDay + " " + date_decr[2]
        
    finalEntireTime = date_decr[3] + ':' + date_decr[4] + ':' + date_decr[5]
    printy("This message was created " + finalEntireDate + ' at ' + finalEntireTime, "c>")
    print("")

    printy(sender_decr + "sent it !", "c>")
    print("")

    printy(reciever_decr + " should recieve it !", "c>")
    print("")

    print("And the message is : " + final_decrypted, "c>")

    print("")
    printy("You can now save this decrypted information into a text file")
    choice = inputy("Do you want to do so (yes/no) ? ", 'c')
    if choice == "yes" or choice == "y" :
        saveToExtFile(sender_decr, reciever_decr, final_decrypted, finalEntireDate, finalEntireTime)
    else :
        print("No problem. Nothing has been written")

def saveToExtFile(sender_decr, reciever_decr, final_decrypted, date, time) :
    txt = False
    
    print("")
    printy("Please enter the name of file you want to save. Please note this name MUST end with .txt", 'c')
    printy("If the name you enter is not a valid one, the default name,", 'c', end = ' ')
    printy(defaultName, 'c', end = ' ')
    printy("will be used", 'c')
    filename = inputy("Enter file name : ")
    print("")

    if filename[-4:] == ".txt" and len(filename) > 4 :     #because e.g. filname is "abc" then abc[-4:] returns "abc" and ".txt" is 4 char long so in order to have a valid name both len() > 4 and ends with ".txt" is required
        txt = True
    
    if not txt :
        printy("Error the name you entered is not valid", 'm')
        printy(defaultName, "y", end = " ")
        printy("will be used instead" ,'y')
        filename = defaultName
    
    fileToWrite = open(filename, 'w')
    fileToWrite.write("Timestamp : ")
    fileToWrite.write(date + ' at ' + time)
    fileToWrite.write("\n")
    fileToWrite.write("Sender : ")
    fileToWrite.write(sender_decr)
    fileToWrite.write("\n")
    fileToWrite.write("Reciever : ")
    fileToWrite.write(reciever_decr)
    fileToWrite.write("\n")
    fileToWrite.write("Message : ")
    fileToWrite.write(final_decrypted)
    fileToWrite.close()

    printy("All the decrypted data has been securely saved to", 'c', end = ' ')
    printy(filename, 'c')


def findDayDate(date) :
    dayNumber = datetime.strptime(date, '%d %m %Y').weekday()
    return (day_name[dayNumber])

def settings() :
    global file_output
    global date_format
    global warnBeforeOW
    global outModeEncrypt
    stop = False
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

    while stop != True :
        printy("You are currenly in settings ! Encrypt and decrypt are not part of this context. To go back to the main menu type \"exit\"", 'y')
        settings_cmd = input(">>> ")

        if 'see' in settings_cmd and len(settings_cmd) == 5 :
            if settings_cmd[4] == '1' :
                print("Your encrypted messages are currently saved with the following name :", file_output)

            elif settings_cmd[4] == '2' :
                print("The date format is currently set to", date_format)

            elif settings_cmd[4] == '3' :
                print(("Warning before overwrite is currently enabled" if warnBeforeOW else "No warning will be shown before you overwrite an existing file"))
            elif settings_cmd[4] == '4' :
                if outModeEncrypt != 0 :
                     printy("Any content you encrypt will be outputed to " + (file_name if outModeEncrypt == 1 else "screen directly"), "c")
                else : printy("ZCrypt will always ask you if you want to save your encrypted content to a file or if you want to print it on screen", "c")

            
            else :
                printy("Error ! The option you tried to view does not exists or does have a number assigned to it", "m")

        
        elif 'set' in settings_cmd and len(settings_cmd) == 5 :
            if settings_cmd[4] == '1' :
                file_output = input("Please enter the name of file you want to be saved as. Don't forget to ad (.txt) at the end ! : ")
                printy("Done ! The name of the output file has been successfully changed to", "n", end = ' ')
                printy(file_output, 'n')

            elif settings_cmd[4] == '2' :
                printy("You have the choice between 4 date formats : 1) dd/mm/YYYY, 2) dd/mm/YY, 3) YYYY-mm-dd or just the 4) plain text format", 'c')
                choice = inputy("Please enter the number of the date format you want to use (1, 2, 3 or 4) : ", 'c')
                if int(choice) <= 4 and int(choice) > 0 :
                    date_format = choice
                    printy('Successfully set date format to', 'c', end = ' ')
                    printy(dateFormatDict[choice], 'c')
                else :
                    printy("Error ! " + choice + " is not an offered choice", 'm')

            elif settings_cmd[4] == '3' :
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
                    printy("Nothing has been changed", 'c')
                    printy("Returning...", 'c')

            elif settings_cmd[4] == "4" :
                printy("Starting from V2.3 you can now chose what you want ZCrypt to do with your encrypted content", 'c')
                printy("3 values are available for this setting : 0, 1 and 2", "c")
                printy("If you choose 0, ZCrypt will always ask you if you want to save to a file or just show the content on screen", "c")
                printy("If you choose 1, ZCrypt will always save your encrypted content to a file, here " + file_output, "c")
                printy("Note : mode 1 works just like ZCypt used to function in releases before V2.3", 'c')
                printy("If you choos 2, ZCrypt will always output your encrypted content to your screen", "c")
                choice = inputy("Input :  ")
                if 0 <= int(choice) <= 2 : 
                    outModeEncrypt = int(choice)
                    printy("Successfully set output mode to " + choice, 'c')
                else : printy(choice + " is not an offered choice", "m")
            
            else :
                printy("Error ! The option you tried to view does not exists or does have a number assigned to it", "m")


        elif settings_cmd == 'exit' :
            stop = True
            return

        else :
            printy("Error ! Either this command is unknown either it does not use the needed format ! See the manual to learn more ", "m")
    


#Welcome screen
printy("#######################", "c>")
printy("# Welcome to ZCrypt ! #", "c>")
printy("#######################", "c>")
printy("Here are the commands you can use : encrypt, decrypt and you can also see the user manual by typing \"manual\"", "n>")
printy("If this is your first time using the program, please consider using the \"instructions\" command", "n>")
printy("If you want to access the settings, type \"settings\"", "n>")
printy("You can also exit the program by typing \"quit\"", "n>")                                                #This line runs just once, at the programm start because the encryption module needs the last key (and there is no last key at the first time)
    

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

        prepareOutput()


    elif command == "decrypt" :
        Error_Code.clear()
        printy("Please specify the COMPLETE name of the file with the .txt end !", "c")
        file_name = input()
        if fileCheck() :
            printy("Your file was successfully checked and no file integrity violations were found. Continuing...", "n")
            keySettings()
            printDecrypted(decryptSender(), decryptReciever(), decrypt())
        else :
            printy("Error ! Either the file specified does not use the needed format for the program either it is corrupted.", "m")
            print("Aborting...")

    elif command == "settings" :
        settings()

    elif command == "showErrors" : 
        if len(Error_Code) == 1 :
            print("We are sorry to hear that your file has a problem")
            print("Please consider reading the manual by typing manual and search for the Error Code ", Error_Code[0])
            print("Otherwise, ask the sender to send the message again")
        else :
            printy("Your file has been decrypted without any errors.", "c")

    elif command == "manual" :
        manual_file = open("Manual.txt", "r")
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
