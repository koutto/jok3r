###
### Controller > ToolsRunner
###
from lib.utils.CLIUtils import CLIUtils
from lib.utils.FileUtils import FileUtils

class ToolsRunner(object):

	def __init__(self, arguments, settings, output):
		self.settings     = settings
		self.arguments    = arguments
		self.output       = output


	def run(self):
		self.output.printTitle0('Target Summary:')
		self.arguments.target.printSummary(self.output)

		self.output.printTitle0('Configuration:')
		self.arguments.printSummary(self.output)

		# Single tool mode
		if self.arguments.args.single_tool:
			self.runSingleTool()  

		# Normal mode
		else:    
			self.runToolboxAgainstService()


	def runSingleTool(self):
		"""
		Only run one tool
		"""
		service = self.arguments.args.service
		self.output.printInfo('Selected mode: Run single tool against service {0}'.format(service))
   
		tool = self.settings.toolbox.searchInToolboxForService(self.arguments.args.single_tool, service)
		if not tool:
			sys.exit(0)

		output_file = FileUtils.absolute_path(FileUtils.concat_path(self.arguments.args.output_dir, tool.name + '.txt'))
		output_dir  = FileUtils.absolute_path(FileUtils.concat_path(self.arguments.args.output_dir, tool.name))
		print
		self.output.printTitle1('   ' + tool.name)
		try:
			tool.runTool(self.settings, 
						 self.output, 
						 self.arguments.args.output_dir,
						 self.arguments.target, 
						 self.arguments.specific,
						 ignore_specific=self.arguments.args.ignore_specific,
						 auto_yes=self.arguments.args.auto_yes)
		except KeyboardInterrupt, SystemExit:
			print
			self.output.printError('Tool execution aborted')


	def runToolboxAgainstService(self):
		"""
		Run the tools from the toolbox that target the service chosen by the user.
		Categories selection is taken into account.
		"""
		service = self.arguments.args.service
		for cat in self.arguments.selected_tools_categories:
			print
			self.output.printTitle0('Tools Category - {0}'.format(cat))
			if not self.settings.toolbox.tools[service][cat]:
				self.output.printInfo('No tool to run in this category')
				continue

			if not self.arguments.args.auto_yes:
				self.output.printPrompt('Run tools in this category ? [Y/n]')
				if not CLIUtils.promptYesNo(self.output, default='Y'):
					self.output.printWarning('Category skipped.')
					continue

			output_dir = FileUtils.concat_path(self.arguments.args.output_dir, cat)
			if not FileUtils.create_directory(output_dir):
				self.output.printFail('Impossible to create output subdir "{0}"'.format(subdir))
				sys.exit(0)
			self.output.printInfo('Output subdir "{0}" created'.format(output_dir))
			for tool in self.settings.toolbox.tools[service][cat]:
				print
				self.output.printTitle1('   ' + tool.name)

				try:
					tool.runTool(self.settings,
								 self.output, 
								 output_dir,
								 self.arguments.target,
								 self.arguments.specific,
								 ignore_specific=self.arguments.args.ignore_specific,
								 auto_yes=self.arguments.args.auto_yes)
				except KeyboardInterrupt, SystemExit:
					print
					self.output.printError('Tool execution aborted')
				print		


