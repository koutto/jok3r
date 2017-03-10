###
### Process Launcher
###
import subprocess

class ProcessLauncher(object):

	def __init__(self, command, output, output_file=None):
		self.command 		= command.strip()
		self.output 		= output
		self.output_file 	= output_file

	def createSubprocess(self, cmd):
		"""
		Subprocess creation
		"""
		try:
			if self.output_file is not None:
				#subprocess.Popen(cmd, shell=True, stdout=self.output_file, stderr=subprocess.STDOUT)
				subprocess.call(cmd, shell=True, stdout=self.output_file, stderr=subprocess.STDOUT)
			else:
				#subprocess.Popen(cmd, shell=True)
				subprocess.call(cmd, shell=True)
		except Exception as e:
			self.output.printError('Error when trying to run command: {0}'.format(e))


	def start(self):
		"""
		Start process in current window
		"""
		print self.command
		self.createSubprocess(self.command)


	def startInNewWindow(self, title=None):
		"""
		Start process in new terminal
		   gnome-terminal is used. 
		   Might be adapted for other platforms (xterm...)
		"""
		cmd =  'gnome-terminal '
		if title is not None:
			cmd += '--title="{0}" '.format(title.replace('"', '\\"'))
		cmd += '--geometry=140x80 '
		cmd += '--command="bash -c \'{0}; exec bash\'"'.format(self.command)
		self.createSubprocess(cmd)


	def startInNewTab(self):
		"""
		Start process in new tab in current terminal session
		   Use a dirty hack to open tab (https://gist.github.com/Raboo/5361942)
		"""
		cmd =  'WID=$(xprop -root | grep "_NET_ACTIVE_WINDOW(WINDOW)"| awk \'{print $5}\');'
		cmd += 'xdotool windowfocus $WID;'
		cmd += 'xdotool key ctrl+shift+t;'
		cmd += 'xdotool type "{0}";'.format(self.command)
		cmd += 'xdotool key Return'
		self.createSubprocess(cmd)
		# TOTEST: Stdout ?