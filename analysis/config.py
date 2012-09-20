import ConfigParser

def loadData():
	data = { }
	config = ConfigParser.ConfigParser()
	config.read('app.config')
	
	for sect in config.sections():
		
		data[sect] = { }
		
		for opt in config.options(sect):
			data[sect][opt] = config.get (sect, opt)
			
	return data

