import json
import tweepy
import config
import urllib
import urllib2
import hashlib
import urlparse
import webbrowser
import BaseHTTPServer

code_fb = ''
data = config.loadData()

class RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

	def do_GET(self):
		global code_fb
		self.send_response(200)
		self.send_header("Content-type", "text/html")
		self.end_headers()
		#https://www.facebook.com/dialog/oauth?client_id=346589735369619&redirect_uri=http://127.0.0.1:8080&scope=email,read_stream
		code_fb = urlparse.parse_qs(urlparse.urlparse(self.path).query).get('code')[0]
		
	
class FacebookAutentification:
	
	def __init__(self, user):
		self.data = config.loadData()
		self.user = hashlib.md5(user.upper()).hexdigest()
		self.token_fb = ''
		self.code = ''
		self.url = ''
		
	def is_verificated_user(self):
		
		jsn = self.__get_json()
		self.url = 'https://www.facebook.com/dialog/oauth?client_id=%s&redirect_uri=http://127.0.0.1:8080/&scope=email,read_stream,publish_stream' % (self.data['application']['facebook_consumer_key'])
								
		return self.user in jsn
		
	def update_token(self):
		self.__get_token()
		
	def __get_token(self):
		
		webbrowser.open(self.url, new = 2)
		
		httpd = BaseHTTPServer.HTTPServer(('127.0.0.1', 8080), RequestHandler)
		httpd.handle_request()
		
		self.code = code_fb
		self.__get_updated_token()
		
	def __get_updated_token(self):
		args = { 'client_id' : data['application']['facebook_consumer_key'], 'redirect_uri' : 'http://127.0.0.1:8080/' , 'client_secret' : data['application']['facebook_consumer_secret'], 'code' : self.code}
		self.token_fb = urlparse.parse_qs((urllib2.urlopen('https://graph.facebook.com/oauth/access_token?' + urllib.urlencode(args))).read())['access_token'][0]
	
	def save_user(self):
		self.__get_token()
		jsn = {}
		
		if code_fb != '':
			jsn[self.user] = {}
			jsn[self.user]['keys'] = {}
			writer = open(self.data['db']['filename_facebook'], 'w')
			writer.write (json.dumps(jsn, indent = 4, sort_keys = True))
			writer.close()

	def get_access_token(self):
		return self.token_fb
		
	def __get_json(self):
		return json.load(open(self.data['db']['filename_facebook']))
		

class TwitterAutentification:
	
	def __init__(self, user, consumer_key, consumer_secret):
		self.auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
		usr = tweepy.API(self.auth).get_user(screen_name=user)
		self.user = str(usr.id)
		self.url = ''
		self.data = config.loadData()
		self.dt = { }
	
	def is_verificated_user(self):

		reader = open (self.data['db']['filename_twitter'], 'r')
		users = json.load(reader)
		reader.close()
		hashuser = hashlib.md5(self.user).hexdigest()
		
		found = hashuser in users
		
		if found:
			self.dt = { 'key': users[hashuser]['consumer_key'], 'secret':  users[hashuser]['consumer_secret']}
		
		return found
		
	def save_verificated_user (self):
		reader = open (self.data['db']['filename_twitter'], 'r')
		users = json.load(reader)
		reader.close()
		
		users[hashlib.md5(self.user).hexdigest()] = { 'consumer_key' : self.dt['key'], 'consumer_secret' : self.dt['secret'] }
		
		writer = open (self.data['db']['filename_twitter'], 'w')
		writer.write (json.dumps(users, indent = 4, sort_keys = True))
		writer.close()
	
	def get_autenticate_url(self):
		return self.auth.get_authorization_url()
	
	def set_pin(self, pin):
		self.auth.get_access_token(pin)
		self.dt = { 'key': self.auth.access_token.key, 'secret': self.auth.access_token.secret }
		
	def get_user_tokens(self):
		return self.dt
			
	def get_api(self):
		self.auth.set_access_token(self.dt['key'], self.dt['secret'])
		return tweepy.API(self.auth)
