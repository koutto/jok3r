###
### Command-Line Output
###
import os
import sys
from colorama import *
import platform
# if platform.system() == 'Windows':
# 	from thirdparty.colorama.win32 import *


class CLIOutput(object):

	def __init__(self, debug_enabled=True):
		self.settings_print_enabled = debug_enabled
		self.lastInLine = False
		self.rows, self.columns = (lambda x: (int(x[0]), int(x[1])))(os.popen('stty size', 'r').read().split())

	def printInLine(self, string):
		self.eraseLine()
		sys.stdout.write(string)
		sys.stdout.flush()
		self.lastInLine = True

	def eraseLine(self):
		if platform.system() == 'Windows':
			csbi = GetConsoleScreenBufferInfo()
			line = "\b" * int(csbi.dwCursorPosition.X)
			sys.stdout.write(line)
			width = csbi.dwCursorPosition.X
			csbi.dwCursorPosition.X = 0
			FillConsoleOutputCharacter(STDOUT, ' ', width, csbi.dwCursorPosition)
			sys.stdout.write(line)
			sys.stdout.flush()
		else:
			sys.stdout.write('\033[1K')
			sys.stdout.write('\033[0G')

	def boldString(self, string):
		return Style.BRIGHT + str(string) + Style.RESET_ALL

	def colorString(self, string, color):
		string = str(string)
		if color:
			if color.lower() == 'green':
				string = Fore.GREEN + string + Style.RESET_ALL
			elif color.lower() == 'red':
				string = Fore.RED + string + Style.RESET_ALL
			elif color.lower() == 'yellow':
				string = Fore.YELLOW + string + Style.RESET_ALL
		return string

	def printRaw(self, string):
		sys.stdout.write(string)

	def printGreen(self, text):
		message = Fore.GREEN + str(text) + Style.RESET_ALL
		self.printRaw(message)

	def printRed(self, text):
		message = Fore.RED + str(text) + Style.RESET_ALL
		self.printRaw(message)

	def printBright(self, text):
		message = Style.BRIGHT + text + Style.RESET_ALL
		self.printNewLine(message)

	def printNewLine(self, string, color=None):
		string = str(string)
		if color:
			string = self.colorString(string, color)

		if self.lastInLine == True:
			self.eraseLine()
		if platform.system() == 'Windows':
			sys.stdout.write(string)
			sys.stdout.flush()
			sys.stdout.write('\n')
			sys.stdout.flush()
		else:
			sys.stdout.write(string + '\n')
		sys.stdout.flush()
		self.lastInLine = False
		sys.stdout.flush()

	def printNewLineBold(self, string):
		text = Style.BRIGHT + string + Style.RESET_ALL
		self.printNewLine(text)

	def printBanner(self, banner):
		message = Style.BRIGHT + Fore.GREEN + banner + Style.RESET_ALL
		self.printNewLine(message)

	def printSettings(self, info):
		if self.settings_print_enabled:
			#message = Fore.WHITE + Back.BLACK + Style.BRIGHT + '[DEBUG] ' + Style.NORMAL + info.strip() + Style.RESET_ALL
			message = Style.BRIGHT + '[SETTINGS] ' + Style.NORMAL + info.strip() + Style.RESET_ALL
			self.printNewLine(message)

	def printError(self, reason):
		message = Style.BRIGHT + Fore.WHITE + Back.RED + '[!] ' + reason.strip() + Style.RESET_ALL
		self.printNewLine(message)

	def printWarning(self, reason):
		message = Style.BRIGHT + Fore.YELLOW + '[!] ' + Style.NORMAL + reason.strip() + Style.RESET_ALL
		self.printNewLine(message)

	def printSuccess(self, reason):
		message = Style.BRIGHT + Fore.GREEN + '[+] ' + Style.NORMAL + reason.strip() + Style.RESET_ALL
		self.printNewLine(message)

	def printFail(self, reason):
		message = Style.BRIGHT + Fore.RED + '[!] ' + Style.NORMAL + reason.strip() + Style.RESET_ALL
		self.printNewLine(message)

	def printInfo(self, info):
		message = Style.BRIGHT + "[~] " + Style.RESET_ALL + info.strip() 
		self.printNewLine(message)

	def printPrompt(self, question):
		message = Style.BRIGHT + "[?] " + Style.RESET_ALL + question.strip() 
		self.printRaw(message)

	def printNotice(self, info):
		message = Fore.GREY + info.strip() + Style.RESET_ALL
		self.printNewLine(message)

	def printTitle0(self, title):
		message  = Style.BRIGHT + Fore.GREEN 
		message += '================================================================================\n'
		message += '   ' + title + '\n'
		message += '================================================================================\n'
		message += Style.RESET_ALL
		self.printNewLine(message)

	def printTitle1(self, title):
		message = Style.BRIGHT + Fore.YELLOW + title + Style.RESET_ALL
		self.printNewLine(message)

	def printTitle2(self, title):
		message = Style.BRIGHT + title + Style.RESET_ALL
		self.printNewLine(message)

	def printBeginCmd(self, cmd):
		message  = '\n'
		message += Fore.WHITE + Back.BLACK + Style.BRIGHT
		message += ' ' * self.columns + '\n'	
		message += 'cmd> {0}'.format(cmd) + ' ' * (self.columns - (len('cmd> {0}'.format(cmd)) % self.columns)) + '\n'
		message += ' ' * self.columns + '\n'	
		message += Style.RESET_ALL
		self.printNewLine(message)

	def printEndCmd(self):
		message  = '\n'
		message += Fore.WHITE + Back.BLACK + Style.BRIGHT
		message += ' ' * self.columns + '\n'	
		message += ' ' * self.columns + '\n'	
		message += Style.RESET_ALL
		self.printNewLine(message)
