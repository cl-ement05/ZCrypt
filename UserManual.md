# Manual summary
 - [Introduction](#introduction)
 - [Crypting Engine](#crypting-engine)
 - [Commands and their use](#command-usage)
   - [Encrypt](#encrypt)
   - [Decrypt](#decrypt)
   - [Error Codes](#error-codes)
   - [Settings](#settings)


# Introduction
This software is being developped by Clement and has been released the February, the 24th 2020

ZCrypt is a progam that uses Python to run
Please, take into consideration that, all the files linked to this program or which were created by this app will be saved to the software root directory
So, if you want to decrypt a message, please paste the file you want to decrypt in the software's folder


# Crypting Engine
Now Let's talk a bit about cryptography...
Here is how ZCrypt encrypting engine works
When you type your message, ZCrypt makes an analysis of each character
After that, it assigns to each character its corresponding Ascii number and changes this number by adding or removing another number : the key !
The program deicdes to add or remove a number considering one more time the key : if the key is a pair number, it removes the key from the original Ascii but if the key is an impair number, it adds the key to the Ascii code of the character
After that, ZCrypt splits the final encrypted ascii in three number (eg : 126; 093; 105...) and for each character of this Ascii number, it transforms it in its binary version
At the end, we get three binary codes (3 * 8) so a total lenght of 24 numbers for one chacarcter
Recap, let's take an example your message is "a" : a ==> 97 ==> 97 + 25(key) ==> 122 ==> 00000001 (binary of 1) 00000010 (binary of 2) 00000010 (binary of 2)


# Command usage
You can type different commands to use ZCrypt
Here are they : `encrypt`, `decrypt`, `settings`, `instructions`, `showErrors` and `manual`

## Encrypt
When you want to `encrypt` a message, type encrypt and press enter
Everything will be explained using prints as you go on this process
At the end, the file containing the encrypted message will be saved with a name as text file
This name is, by default, set to "Mail.txt" but this can be changed in settings

## Decrypt
When you want to `decrypt` a message, everything is very simple you just need to type decrypt
After that, ZCrypt will prompt the user to enter the file name
Finally, all informations about the message will be displayed
These information are : the date the message was created/wrote; the sender; the reciever and finally the message
Note : these information can be saved to a text file

## Settings
ZCrypt also offers a settings page
In this part of the software, only 3 commands are allowed : see, set and exit
Every settings has its own number (eg : 1; 2; 3...)

When you want to see the status or value of a setting, type "see X" where X is the number of the setting you want to see
If you want to change this value, type "set X" where is X is one more time the number assigned to the setting you want to edit
If you want to go back to the software main page, type exit and will be able to encrypt or decrypt messages again
!!! Warning : Since the commands (enrypt or decrypt) are not registered in the settings, crypting or decrypting messages is not possible when you are in the settings

The instructions command explains shortly how the program works and how to use it
Please consider reading it if this is your first time using ZCrypt

## Error Codes
Sometimes ZCrypt is not able to decrypt your message
When this happens, you can type showErrors to understand why your file can't be decrypted
When you type this command, ZCrypt returns you error codes (eg : E301; E421...) which each of them is linked to a specific reason ZCrypt could not decrypt your file
This is usually because the file does not match ZCrypt requirements
Here is the list of the Error Codes and their meaning :

I) Errors starting with E1XX : Operating-System-Level error
    - E101 : your file does not exist or is corrupted and cannot be read by your system

II) Errors starting with E2XX : File does not match basic ZCrypt requirements
    - E201 : the file has more or less than 5 lines (and ZCrypt needs 5 lines in the file)
    - E202 : one or more lines couldn't be read (convert to string impossible so unknow character type)

III) Errors starting with E3XX : File does not match advanced requirements of ZCrypt (easier to fix)
    - E301 : the first line (which contains time informations) couldn't be read (convert to string impossible so unknow character type)
    - E302 : the first line that contains time informations is less or more than 29 characters long
    - E313 : the fourth line which contains the encrypting key couldn't be converted to a number which made ZCrypt unable to understand it
    - E314 : the fourth line that contains encrypting key is less or more than 9 characters long
    - E325 : the fith line which contains the whole message couldn't be converted to a specific type of character which led to a an impossible understanding
    - E326 : the fith line that contains the whole message does not contain a ';' wich is needed, at least one time, to decrypt the message










