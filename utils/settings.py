from printy import printy, inputy

defaultSettings = {
    "fileOutput" : "Mail.txt",
    "dateFormat" : '1',
    "warnBeforeOW" : True,
    "outModeDecrypt" : 0,
    "encryptionMode" : "ask",
    "rsaKeyBytes" : 1024,
    "checkForUpdates" : "atStart"
}

def writeSettings(settingsToWrite: dict = defaultSettings) :
    with open("ZCrypt-settings", "w") as settingsFile :
        settingsFile.write("This file has been automatically created by ZCrypt. Do NOT modify it unless you know what you are doing \n")
        for element in settingsToWrite.keys() :
            settingsFile.write(element + ":" + str(settingsToWrite[element]) + ";")

def loadSettings() :
    with open("ZCrypt-settings", "r") as settingsFile :
        settingsList = settingsFile.readlines()[1].split(";")[:-1]
        assert len(settingsList) == 7 or 8
        settings = dict()
        for setting in settingsList :
            elements = setting.split(":")
            assert elements[0] != "" and elements[1] != ""
            settings[elements[0]] = elements[1]
    return settings

def runSettings(settings) :
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
                    printy("Any content you decrypt will be outputed to " + ("a file" if settings['outModeDecrypt'] == 1 else "screen directly"), "c")
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
                    printy("Success : ZCrypt will never check for updates", "n")
                else : printy("Error : this is not an offered choice", "m")

            else :
                printy("Error : the option you tried to view does not exists or does have a number assigned to it", "m")


        elif settingsCmd == 'exit' :
            break

        else :
            printy("Error : either this command is unknown either it does not use the needed format ! See the manual to learn more ", "m")