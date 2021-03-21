from time import sleep
from datetime import datetime
import os
from random import *
import string

count = 0
check = 0
file_pass = False
file_test = False
stop = False
file = ''
Error_Code = list()
settings_list = list()
settings_list.append("1")
file_output = "Mail.txt"


def fileCheck() :
#All this section checks the file integrity and assings all the lines to a dynamic variable
	global file_pass
	global line1
	global line2
	global line3
	global line4
	global line5

	count = 0

	try :
		file = open(file_name, 'r+')
		file_pass = True
	except :
		Error_Code.append("")

	if file_pass == True :
		text = file.readlines()

		# Checks if the file has 5 lines
		if len(text) == 5 :
			pass
		elif len(text) > 5 or len(text) < 5 :
			file_pass = False

	#Assigns a variable name with the line number to each element (line) in the file
	if file_pass == True :
		for element in range(5) :
			if count == 0 :
				line1 = text[0]
			elif count == 1 :
				line2 = text[1]
			elif count == 2 :
				line3 = text[2]
			elif count == 3 :
				line4 = text[3]
			elif count == 4 :
				line5 = text[4]
			count += 1

		return file_pass, line1, line2, line3, line4, line5


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

	return decrypt_key, key_method

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
	#print(key_num)
	return key_num, key_bin


#All this part contains all functions used for encrypting
def encryptTime() :
	global final_time_encr
	final_time_encr = ''
	final_time_list = list()
	now = datetime.now()
	current_time = now.strftime("%d/%m/%Y %H:%M:%S")

	for element in range(len(current_time)) :
		#This try is used to skip date characters like (/ and :) that cannot be encrypted and will be removed
		try :
			test = int(current_time[element])
		except :
			if current_time[element] == '/' or current_time[element] == ':' or current_time[element] == ' ' :
				pass
			else :
				print("Error")
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
	global sender_encr
	sender_encr = ''
	check = 0
	for character in range(len(sender)) :
		
		sender_ascii = ord(sender[check])
		#If the key is a pair number
		if key_num % 2 == 0 :
			if sender_ascii - key_num >= 33 :
				sender_en = sender_ascii - key_num

			elif sender_ascii - key_num < 33 :
				cut = 0
				while sender_ascii >= 33 :
					sender_ascii -= 1
					cut += 1
				remaining_key = key_num - cut
				sender_en = 126 - remaining_key

		#If the key is an impair number
		elif key_num % 2 == 1 :
			if sender_ascii + key_num <= 126 :
				sender_en = sender_ascii + key_num

			elif sender_ascii + key_num > 126 :
				cut = 0
				while sender_ascii <= 126 :
					sender_ascii += 1
					cut += 1
				remaining_key = key_num - cut
				sender_en = 33 + remaining_key

		check += 1
		sender_encr += str(chr(sender_en))

	return sender_encr

def encryptReciever() :
	global reciever_encr
	reciever_encr = ''
	check = 0
	for character in range(len(reciever)) :		
		reciever_ascii = ord(reciever[check])
		#If the key is a pair number
		if key_num % 2 == 0 :
			if reciever_ascii - key_num >= 33 :
				reciever_en = reciever_ascii - key_num

			elif reciever_ascii - key_num < 33 :
				cut = 0
				while reciever_ascii >= 33 :
					reciever_ascii -= 1
					cut += 1
				remaining_key = key_num - cut
				reciever_en = 126 - remaining_key

		#If the key is an impair number
		elif key_num % 2 == 1 :
			if reciever_ascii + key_num <= 126 :
				reciever_en = reciever_ascii + key_num

			elif reciever_ascii + key_num > 126 :
				cut = 0
				while reciever_ascii <= 126 :
					reciever_ascii += 1
					cut += 1
				remaining_key = key_num - cut
				reciever_en = 33 + remaining_key

		check += 1
		reciever_encr += str(chr(reciever_en))

	return reciever_encr

#Main encrypt engine
def encrypt() :
	keySetup()

	check = 0
	global final_message_binary
	final_message_binary = list()

	nbr_letters = len(message_input)
	for letter in range(nbr_letters) :
		#Transforms the character in its ascii number
		current_chr = message_input[check]
		ascii_chr = ord(current_chr)

		#Spaces are encoded as is they were "~" (its ascii is 126) so to avoid errors, the programm does not support this character
		if ascii_chr == 126 :
			print("Error ! Your message contains a character that is not supported")
			break

		#If the key is a pair number
		if key_num % 2 == 0 :
			if ascii_chr - key_num >= 33 :
				ascii_encr = ascii_chr - key_num

			elif ascii_chr - key_num < 33 :
				cut = 0
				while ascii_chr >= 33 :
					ascii_chr -= 1
					cut += 1
				remaining_key = key_num - cut
				ascii_encr = 126 - remaining_key

		#If the key is an impair number
		elif key_num % 2 == 1 :
			if ascii_chr + key_num <= 126 :
				ascii_encr = ascii_chr + key_num

			elif ascii_chr + key_num > 126 :
				cut = 0
				while ascii_chr <= 126 :
					ascii_chr += 1
					cut += 1
				remaining_key = key_num - cut
				ascii_encr = 33 + remaining_key
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

	print("Your key is:", key_num)
	return final_message_binary

#Get all settings and variables and starts the writeFile function to apply changes with the variables
def prepareOutput() :
	encryptTime()
	encryptSender()
	encryptReciever()

	txt = False
	message_str = ''
	for i in range(len(final_message_binary)) :
		message_str += final_message_binary[i]
	assert(type(message_str) is str)

	for letter in range(len(file_output)) :
		if file_output[letter] == '.' and file_output[letter + 1] == 't' and file_output[letter + 2] == 'x' and file_output[letter + 1] == 't' :
			txt = True

	if txt == True :
		writeFile(final_time_encr, sender_encr, reciever_encr, key_bin, message_str)
	else :
		print("Error ! The name of the file you want to save is incorect. Please try another one !")

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


#In this part, all the function used for decrypting are defined

def dateSettings() :
	#Here, the entire line1 that contains the date is spread in different variables
	chSize = 2
	global day
	global month
	global year
	global hour
	global minutes
	global seconds
	date = line1[:(chSize * 8)]
	time = line1[(chSize * 8):]

	#Spreading the time list into the hour, minutes...
	hour = time[:4]
	min_and_sec = time[4:]
	minutes = min_and_sec[:4]
	seconds = min_and_sec[4:]

	#Spreading the date list into the days, months...
	day = date[:4]
	month = date[4:8]
	year = date[8:]

	try :
		hour_test = int(hour)
		minutes_test = int(minutes)
		seconds_test = int(seconds)
	except :
		raise AssertionError()

	decryptTime()

#Decrypts the date and time
def decryptTime() :
	global day_decrypted
	global month_decrypted
	global year_decrypted
	global hour_decrypted
	global min_decrypted
	global sec_decrypted

	#Decrypting days
	day1 = day[:2]
	day1_decrypted = int(day1) - decrypt_key
	day2 = day[2:]
	day2_decrypted = int(day2) - decrypt_key
	day_decrypted = int(str(day1_decrypted) + str(day2_decrypted))
	if len(str(day_decrypted)) == 1 :
		nbr = str(day_decrypted)[0]
		day_decrypted = str(0) + str(nbr)

	#Decrypting the month
	month1 = month[:2]
	month1_decrypted = int(month1) - decrypt_key
	month2 = month[2:]
	month2_decrypted = int(month2) - decrypt_key
	month_decrypted = int(str(month1_decrypted) + str(month2_decrypted))
	if len(str(month_decrypted)) == 1 :
		nbr = str(month_decrypted)[0]
		month_decrypted = str(0) + str(nbr)

	#Decrypting the year
	year1 = year[:2]
	year1_decrypted = int(year1) - decrypt_key
	year2 = year[2:4]
	year2_decrypted = int(year2) - decrypt_key
	year3 = year[4:6]
	year3_decrypted = int(year3) - decrypt_key
	year4 = year[6:]
	year4_decrypted = int(year4) - decrypt_key
	year_decrypted = int(str(year1_decrypted) + str(year2_decrypted) + str(year3_decrypted) + str(year4_decrypted))

	#Decrypting hour
	hour1 = hour[:2]
	hour1_decrypted = int(hour1) - decrypt_key
	hour2 = hour[2:]
	hour2_decrypted = int(hour2) - decrypt_key
	hour_decrypted = int(str(hour1_decrypted) + str(hour2_decrypted))
	if len(str(hour_decrypted)) == 1 :
		nbr = str(hour_decrypted)[0]
		hour_decrypted = str(0) + str(nbr)

	#Decrypting minutes
	min1 = minutes[:2]
	min1_decrypted = int(min1) - decrypt_key
	min2 = minutes[2:]
	min2_decrypted = int(min2) - decrypt_key
	min_decrypted = int(str(min1_decrypted) + str(min2_decrypted))
	if len(str(min_decrypted)) == 1 :
		nbr = str(min_decrypted)[0]
		min_decrypted = str(0) + str(nbr)

	#Decrypting seconds
	sec1 = seconds[:2]
	sec1_decrypted = int(sec1) - decrypt_key
	sec2 = seconds[2:]
	sec2_decrypted = int(sec2) - decrypt_key
	sec_decrypted = int(str(sec1_decrypted) + str(sec2_decrypted))
	if len(str(sec_decrypted)) == 1 :
		nbr = str(sec_decrypted)[0]
		sec_decrypted = str(0) + str(nbr)

	#print("Today is", day_decrypted, month_decrypted, year_decrypted, sep = '/')
	#print("It is currently", hour_decrypted, min_decrypted, sec_decrypted, sep = ':')
	return day_decrypted, month_decrypted, year_decrypted, hour_decrypted, min_decrypted, sec_decrypted

def decryptSender() :
	global sender_decr
	sender_encr = line2
	sender_decr = ''
	check = 0
	for character in range(len(sender_encr)) :
		sender_cras = ord(sender_encr[check])

		if key_method == 'plus' :
			if sender_cras + decrypt_key <= 126 :
				decrypted_ascii = sender_cras + decrypt_key
				
			elif sender_cras + decrypt_key > 126 :					 # Will be enabled if the decrypted ascii number is out of range of the ascii table
				cut = 0
				while sender_cras <= 126 :
					sender_cras += 1
					cut += 1
				remaining_key = decrypt_key - cut
				decrypted_ascii = 33 + remaining_key

		elif key_method == 'minus' :
			if sender_cras - decrypt_key >= 33 :
				decrypted_ascii = sender_cras - decrypt_key
				
			elif sender_cras - decrypt_key < 33 :
				cut = 0
				while sender_cras >= 33 :
					sender_cras -= 1
					cut += 1
				remaining_key = decrypt_key - cut
				decrypted_ascii = 126 - remaining_key

		sender_decr += chr(decrypted_ascii)
		check += 1

	sender_decr = sender_decr[:(len(sender_decr) - 1)]                                                  #This line removes the 0 that spaws after the name
	return sender_decr


def decryptReciever() :
	global reciever_decr
	reciever_encr = line3
	reciever_decr = ''
	check = 0
	for character in range(len(reciever_encr)) :
		reciever_cras = ord(reciever_encr[check])

		if key_method == 'plus' :
			if reciever_cras + decrypt_key <= 126 :
				decrypted_ascii = reciever_cras + decrypt_key
				
			elif reciever_cras + decrypt_key > 126 :					 # Will be enabled if the decrypted ascii number is out of range of the ascii table
				cut = 0
				while reciever_cras <= 126 :
					reciever_cras += 1
					cut += 1
				remaining_key = decrypt_key - cut
				decrypted_ascii = 33 + remaining_key

		elif key_method == 'minus' :
			if reciever_cras - decrypt_key >= 33 :
				decrypted_ascii = reciever_cras - decrypt_key
				
			elif reciever_cras - decrypt_key < 33 :
				cut = 0
				while reciever_cras >= 33 :
					reciever_cras -= 1
					cut += 1
				remaining_key = decrypt_key - cut
				decrypted_ascii = 126 - remaining_key

		reciever_decr += chr(decrypted_ascii)
		check += 1

	reciever_decr = reciever_decr[:(len(reciever_decr) - 1)]                                                  #This line removes the 0 that spaws after the name
	return reciever_decr


def decrypt() :
	keySettings()                                                                  #Decrypts the key in the file and find its method
	global final_decrypted
	final_decrypted = ''
	check = 0

	nbr_letters = int(len(line5) / 25)
	message_encr = line5.split(";")
	for letter in range(nbr_letters) :
		character = ''
		encr_character = message_encr[letter]

		last_chr = encr_character                                                  #This variable is used to not decrypt the same character and "cut" the line5 by deleting the part containing the character being decrypted


		current = 1
		for a in range(3) :
			#Transforms the binary string into an ascii number
			if current == 1:
				binary_ch1 = encr_character[:8]
				encrypted_ascii1 = int(binary_ch1, 2)

			elif current == 2 :
				a = encr_character[8:]
				binary_ch2 = a[:8]
				encrypted_ascii2 = int(binary_ch2, 2)

			elif current == 3 :
				binary_ch3 = encr_character[16:]
				encrypted_ascii3 = int(binary_ch3, 2)
			
			current += 1

		char_asciiencr = int(str(encrypted_ascii1) + str(encrypted_ascii2) + str(encrypted_ascii3))			# Joins the two ascii numbers got from the binaries
		#print("Encrypted ascii:", char_asciiencr)
		#The encrypt/decrypt method is different for pair/impair numbers
		if key_method == 'plus' :
			if char_asciiencr + decrypt_key <= 126 :
				decrypted_ascii = char_asciiencr + decrypt_key
				
			elif char_asciiencr + decrypt_key > 126 :					 # Will be enabled if the decrypted ascii number is out of range of the ascii table
				cut = 0
				while char_asciiencr <= 126 :
					char_asciiencr += 1
					cut += 1
				remaining_key = decrypt_key - cut
				decrypted_ascii = 33 + remaining_key

		elif key_method == 'minus' :
			if char_asciiencr - decrypt_key >= 33 :
				decrypted_ascii = char_asciiencr - decrypt_key
				
			elif char_asciiencr - decrypt_key < 33 :
				cut = 0
				while char_asciiencr >= 33 :
					char_asciiencr -= 1
					cut += 1
				remaining_key = decrypt_key - cut
				decrypted_ascii = 126 - remaining_key

		#Since spaces are encrypted as a "~", if the programm finds an ascii of 126 (which is the code of ~), he transoforms the ~ character into a space
		if decrypted_ascii == 126 :
			decrypted_ascii = 32

		final_decrypted += chr(decrypted_ascii)

	return final_decrypted

#This function gather all decrypted variables processed by the other functions (decryptTime, decrypt...) and prints everything in a user friendly presentation
def printDecrypted() :
	print("We finished decrypting your file !")
	print("Here is everything you need to know about it :")
	print("")
	
	print("This message was created ", end = '')
	print(day_decrypted, month_decrypted, year_decrypted, sep = '/', end = ' ')
	print("at", end = ' ')
	print(hour_decrypted, min_decrypted, sec_decrypted, sep = ':')
	print("")

	print(sender_decr, "sent it !")
	print("")

	print(reciever_decr, "should recieve it !")
	print("")

	print("And the message is :", final_decrypted)


def settings() :
	global stop
	global file_output
	stop = False

	if 'see' in settings_cmd and len(settings_cmd) == 5 :
		if settings_cmd[4] == '1' :
			print("Your encrypted messages are currently saved with the following name :", file_output)

		else :
			print("Error ! The option you tried to view does not exists or does have a number assigned to it")

	
	elif 'set' in settings_cmd and len(settings_cmd) == 5 :
		if settings_cmd[4] == '1' :
			file_output = input("Please enter the name of file you want to be saved as. Don't forget to ad (.txt) at the end ! : ")

		else :
			print("Error ! The option you tried to view does not exists or does have a number assigned to it")


	elif settings_cmd == 'exit' :
		stop = True

	else :
		print("Error ! Either this command is unknown either it does not use the needed format ! See the manual to learn more ")

	return stop


#Welcome screen
print("Welcome to ZCrypt !")
print("Here are the commands you can use : encrypt, decrypt and you can also see the user manual by typing manual")
print("If this is your first time using the program, please consider using the \"instructions\" command")
print("If you want to access the settings, type \"settings\"")
print("You can also exit the program jsut by typing \"quit\"")
last_key = 15                                                  #This line runs just once, at the programm start because the encryption module needs the last key (and there is no last key at the first time)
	

while True :
	print("")
	print("Please input a command ")
	command = input(">>> ")

	if command == "encrypt" :
		#Here, the user inputs all informations required to encrypt
		print("Ok ! Let's encrypt your message !")
		message_input = input("First, type the message you want to encrypt : ")
		sender = input("Please type your name that will be used in the file as the sender information : ")
		reciever = input("Finally, type the reciever of this message : ")

		encrypt()
		prepareOutput()


	elif command == "decrypt" :
		print("Please specify the COMPLETE name of the file with the .txt end !")
		file_name = input()
		fileCheck()
		if file_pass == True :
			print("Your file was successfully checked and no errors or file integrity violations were found. Continuing...")
			keySettings()
			dateSettings()
			decryptSender()
			decryptReciever()
			decrypt()
			printDecrypted()
		else :
			print("Error ! Either the file specified does not use the needed format for the program either it is corrupted.")
			sleep(1)
			print("Aborting...")
			sleep(1)

	elif command == "settings" :
		stop = False
		print("\n", "\n", "\n", "\n")
		print("You are now in the settings !")
		print("Here, are the options you can change :")
		print("    - 1: encrypted file name\n")

		print("If you want to see the current value of an option, type \"see\" followed by the number linked to the option")
		print("If you want to change this value, type \"set\" followed by the number linked to the option")
		print("If you want to exit this page, you can also type \"exit\"")

		while stop != True :
			settings_cmd = input(">>>")

			settings()


	elif command == "showErrors" : 
		pass

	elif command == "manual" :
		manual_file = open("Manual.txt", "r")
		manual_text = manual_file.readlines()
		for line in range(len(manual_text)) :
			print(manual_text[line])

	elif command == "instructions" :
		print("Dear User, welcome to ZCrypt !")
		print("ZCrypt was developped by Clement")
		print("This software was created in order to encrypt messages easily, send it and decrypt it quickly !")
		print("")
			
		print("If you want to encrypt a file, remeber that it will be saved in the same location of this program")
		print("It will be created with the name \"Mail.txt\"")
		print("You can always changes this name in the settings")
		print("")

		print("If you want to decrypt a file, you will need to specify its name as you launch the decrypting process")
		print("The message and the informations attached to it will be shown in this window. In a futur update, will be able to save it")
		print("")

		print("If the program says that your file has a problem and that it can't be decrypted, don't panic !")
		print("You can use the \"showErrors\" command !")
		print("")

		print("Enjoy !")

	elif command == 'quit' :
		print("Thanks for using ZCrypt ! See you soon...")
		exit()