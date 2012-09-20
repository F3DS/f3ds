import json
import config
import urllib
import urllib2
from httplib2 import Http
from autentification import FacebookAutentification as fb

data = config.loadData()

class FacebookSpider:
	
	def __init__(self, username):
		
		self.facebook = fb(username)
		
		if not self.facebook.is_verificated_user():
			self.facebook.save_user()
		else:
			self.facebook.update_token()
		
		self.user_token = self.facebook.get_access_token()
		self.id = self.__get_my_id()
		print self.id
		
	def __get_my_id(self):
		me = json.load(urllib2.urlopen('https://graph.facebook.com/me?access_token=%s' % self.user_token))
		return me['id']
	
	def __get_walls_messages_by_me(self, peers):
		
		itr = {}
		
		for peer in peers:
			wall = json.load(urllib2.urlopen('https://graph.facebook.com/%s/feed?limit=200&access_token=%s' % (peer, self.user_token)))
				
			itr[peer] = 0
					
			for post in wall['data']:
				if post['from']['id'] == self.id:
					itr[peer] += 1
					
				if post['comments']['count'] > 0:
					for cmt in post['comments']['data']:
						if cmt['from']['id'] == self.id:
							itr[peer] += 1
							
			if itr[peer] == 0:
				itr[peer] = -1
		
		return itr

	def __get_walls_messages_to_me(self):
		wall = json.load(urllib2.urlopen('https://graph.facebook.com/me/feed?limit=200&access_token=%s' % self.user_token))
		itr = {}
				
		for post in wall['data']:
			if post['from']['id'] != self.id:
				if post['from']['id'] in itr:
					itr[post['from']['id']] += 1
				else:
					itr[post['from']['id']] = 1
			
			if post['comments']['count'] > 0:
				for cmt in post['comments']['data']:
					if cmt['from']['id'] != self.id:
						if cmt['from']['id'] in itr:
							itr[cmt['from']['id']] += 1
						else:
							itr[cmt['from']['id']] = 1
							
		return itr
		
	def spider_facebook_peers(self):
		
		itr = {}
		to_me = self.__get_walls_messages_to_me()
		by_me = self.__get_walls_messages_by_me(to_me)

		for peer in to_me:
			itr[peer] = min(to_me[peer], by_me[peer])
			
		return itr
		
	def refresh_api(self):
		print "Refreshing"
		self.facebook.update_token()
		self.user_token = self.facebook.get_access_token()
		
	def get_my_wall(self):
		return json.load(urllib2.urlopen('https://graph.facebook.com/me/feed?limit=40&access_token=%s' % self.user_token))
		
	def get_wall(self, user):
		return json.load(urllib2.urlopen('https://graph.facebook.com/%s/feed?limit=5&access_token=%s' % (user, self.user_token)))
	
	def public_in_my_wall(self, msg):
		print "Sending"
		http = Http()
		args = { 'message' : msg, 'access_token' : self.user_token }
		r, cont = http.request('https://graph.facebook.com/me/feed', 'POST', urllib.urlencode(args))
		print r
		
	def public_in_friend_wall(self, peer, msg):
		http = Http()
		args = { 'message' : msg, 'access_token' : self.user_token }
		r, cont = http.request('https://graph.facebook.com/%s/feed' % peer, 'POST', urllib.urlencode(args))
