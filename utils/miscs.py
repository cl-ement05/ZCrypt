from printy import printy
from datetime import datetime
from calendar import day_name

def askFilename(defaultName: str, message: str = "Please enter the name of file you want to save. ", fileExp: str = ".txt") :
    printy(message, 'c')
    printy("Please note this name MUST end with " + fileExp + ". If the name you enter is not a valid one, " + defaultName + fileExp + " will be used", "c")
    fileNameInput = input("Enter file name : ")
    print("")

    #because e.g. filname is "abc" then abc[-4:] returns "abc" and ".txt" is 4 char long so in order to have a valid name both len() > 4 and ends with ".txt" is required
    if not (len(fileNameInput) > len(fileExp) and fileNameInput[-len(fileExp):] == fileExp) :
        printy("Warning : the name you entered is not valid. " + defaultName + fileExp + " will be used instead", "y")
        return defaultName + fileExp
    else : return fileNameInput

def findDayName(date) :
    dayNumber = datetime.strptime(date, '%d %m %Y').weekday()
    return day_name[dayNumber]