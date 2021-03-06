# Manual summary
 - [Introduction](#introduction)
 - [Crypting Engine](#crypting-engine)
 - [Commands and their use](#command-usage)
   - [Encrypt](#encrypt)
   - [Decrypt](#decrypt)
   - [Error Codes](#error-codes)
   - [Settings](#settings)


# Introduction
ZCrypt has been released on February the 24th, 2020 and was originally created by Clement

Please, take into consideration that, all the files linked to this program or which were created by this app will be saved to the software root directory.
So, if you want to decrypt a message, please paste the file you want to decrypt in the software's folder

ZCrypt is under the [GNU GPLv3 license](LICENSE.md)

<a name="cryptEng"></a>
# Crypting Engine
Now Let's talk a bit about cryptography...

Here is how ZCrypt encrypting engine works :

When you type your message, ZCrypt makes an analysis of each character.
After that, it assigns to each character its corresponding Ascii number and changes this number by adding or removing another number : the key !
The program chooses to add or remove a number considering one more time the key : if the key is a pair number, it removes the key from the original Ascii but if the key is an impair number, it adds the key to the Ascii code of the character.
After that, ZCrypt splits the final encrypted ascii in three number (eg : 126; 093; 105...) and for each character of this Ascii number, it transforms it in its binary version
At the end, we get three binary codes (3 * 8) so a total lenght of 24 numbers for one chacarcter.

Let's take an example with the letter "a" : a ==> 97 ==> 97 + 25(key) ==> 122 ==> 00000001 (binary of 1) 00000010 (binary of 2) 00000010 (binary of 2)


# Command usage
You can type different commands to use ZCrypt
Here are they : `encrypt`, `decrypt`, `settings`, `instructions`, `showError`, `manual` and finally `exit`

## Encrypt
When you want to `encrypt` a message, type encrypt and press enter.
Everything will be explained using prints as you go on this process.
At the end, the file containing the encrypted message will be saved with a name as text file.
This name is, by default, set to "Mail.txt" but this can be changed in settings.

## Decrypt
When you want to `decrypt` a message, everything is very simple you just need to type decrypt.
After that, ZCrypt will prompt the user to enter the file name.
Finally, all informations about the message will be displayed.
These information are : the date the message was created/wrote; the sender; the reciever and finally the message.
Note : these information can be saved to a text file.

## Settings
ZCrypt also offers a settings page.
In this part of the software, only 3 commands are allowed : see, set and exit
Every settings has its own number (eg : 1; 2; 3...)

When you want to see the status or value of a setting, type "see X" where X is the number of the setting you want to see.
If you want to change this value, type "set X" where is X is one more time the number assigned to the setting you want to edit.
If you want to go back to the software main page, type exit and will be able to encrypt or decrypt messages again.
Crypting or decrypting messages is not possible when you are in the settings since the commands (enrypt or decrypt) are not registered in the settings.

## Error Codes
Sometimes ZCrypt is not able to decrypt your message.
When this happens, you can type showErrors to understand why your file can't be decrypted.
When you type this command, ZCrypt returns you error codes (eg : E301; E421...) which each of them is linked to a specific reason ZCrypt could not decrypt your file.
This is usually because the file does not match ZCrypt requirements.
Here is the list of the Error Codes and their meaning :

I) Errors starting with E1XX : Operating-System-Level error
- E101 : your file does not exist, is corrupted or cannot be read (check permissions)

II) Errors starting with E2XX : File does not match basic ZCrypt requirements
- E201 : the file's length does not match the length ZCrypt expected 
- E202 : one or more lines couldn't be read (convert to string/bytes impossible due to unknow character type)

III) Errors starting with E3XX : File does not match advanced requirements of ZCrypt encryption mode
- E301 : the first line (which contains time informations) couldn't be read OR is less or more than 43 characters long
- E304 : the fourth line does not match zcrypt format requirements
- E305 : the fith line which contains the whole message couldn't be converted to an integer