#!/usr/env/bin python3

def main():
	XORed_value = 'kym~humr'
	username = ''

	for each_character in XORed_value:
		unicode_value = ord(each_character)
		username += chr((unicode_value - 8) ^ 4)
	
	return username 

if __name__ == '__main__':
	print(main())