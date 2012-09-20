import time
import config

data = config.loadData()

class TwitterSpider():
	
	def __init__(self, api):
		self.twitter = api
		
	def __api_call(self, method):
		
		if self.twitter.rate_limit_status()['remaining_hits'] == 0:
			print "Sleeping"
			time.sleep((self.twitter.rate_limit_status()['reset_time_in_seconds'] - time.mktime(time.localtime())) + 5)
			
		return getattr(self.twitter, method)
	
	def __mentions_by_me(self, peer_interaction):
		for tweet in self.__api_call('user_timeline')(count=data['social']['update_number']):	
			for st in tweet.text.split(' '):
				if st.startswith('@'):
					try:
						user_id = (self.__api_call('get_user')(screen_name=st[1:])).id
						if user_id in peer_interaction['mentions_by_me']:
							peer_interaction['mentions_by_me'][user_id] = peer_interaction['mentions_by_me'][user_id] + 1
					except Exception, e:
						print e
						
	def __mentions_to_me(self, peer_interaction):
		for tweet in self.__api_call('mentions')(count=data['social']['update_number']):
			user_id = tweet.author.id
			
			if user_id in peer_interaction['mentions_to_me']:
				peer_interaction['mentions_to_me'][user_id] = peer_interaction['mentions_to_me'][user_id] + 1
							
	def __retweets_of_me(self, peer_interaction):
		
		for rted in self.__api_call('retweets_of_me')(count=data['social']['update_number']):
			retweets = self.__api_call('retweets')(id=rted.id)
			for rt in retweets:
				if rt.author.id in peer_interaction['retweets_of_me']:
					peer_interaction['retweets_of_me'][rt.author.id] = peer_interaction['retweets_of_me'][rt.author.id] + 1
				
	def __retweeted_by_me(self, peer_interaction):
		
		for retweets in self.__api_call('retweeted_by_me')(count=data['social']['update_number']):
			if hasattr (retweets, 'retweeted_status'):
				author = retweets.retweeted_status.author.id
				if author in peer_interaction['retweeted_by_me']:
					peer_interaction['retweeted_by_me'][author] = peer_interaction['retweeted_by_me'][author] + 1
					
	def __dm_to_me(self, peer_interaction):
		
		for dms in self.__api_call('direct_messages')(count=data['social']['update_number']):
			if dms.sender.id in peer_interaction['dm_to_me']:
				peer_interaction['dm_to_me'][dms.sender.id] = peer_interaction['dm_to_me'][dms.sender.id] + 1
				
	def __dm_by_me(self, peer_interaction):
		
		for dms in self.__api_call('sent_direct_messages')(count=data['social']['update_number']):
			if dms.recipient.id in peer_interaction['dm_by_me']:
				peer_interaction['dm_by_me'][dms.recipient.id] = peer_interaction['dm_by_me'][dms.recipient.id] + 1	
			
	def __spider(self, peer_interaction):
		self.__retweets_of_me(peer_interaction)
		self.__retweeted_by_me(peer_interaction)
		self.__dm_to_me(peer_interaction)
		self.__dm_by_me(peer_interaction)
		self.__mentions_by_me(peer_interaction)
		self.__mentions_to_me(peer_interaction)

	def __get_friends(self, user = None):
		
		following = None
		followers = None
		
		if user == None:
			following = frozenset(self.__api_call('friends_ids')())
			followers = frozenset(self.__api_call('followers_ids')())
		else:
			following = frozenset(self.__api_call('friends_ids')(id=user))
			followers = frozenset(self.__api_call('followers_ids')(id=user))
		
		return following & followers
		
	def spider_twitter_indirect_peers(self):
		friends = self.__get_friends()
		indirect_friends = { }
		cache = { }
		
		for friend in friends:			
			indirect_friends[friend] = { }
			
			rindfriend = frozenset(self.__get_friends(user=friend)) - frozenset(friends)
			
			for ind in rindfriend:
				indirect_friends[friend][ind] = 0
					
			for rts in self.__api_call('retweeted_by_user')(user_id=friend, count=150):
				try:
					if hasattr (rts, 'retweeted_status'):
						uid = rts.retweeted_status.author.id
						if uid in indirect_friends[friend]:
							indirect_friends[friend][uid] += 1
						
				except Exception, e:
					print "Soy", e
					
			for active in indirect_friends[friend]:
				if indirect_friends[friend][active] != 0:
					if active not in cache:
						try:
							cache[active] = self.__api_call('retweeted_by_user')(user_id=active, count=200)
						except Exception, e:
							print e
					
					tinter = 0
					
					if active in cache:
						for rts in cache[active]:
							try:
								if hasattr (rts, 'retweeted_status'):
									uid = rts.retweeted_status.author.id
									if uid == friend:
										indirect_friends[friend][active] += 1
										
							except Exception, e:
								print e
								
						indirect_friends[friend][active] = min(indirect_friends[friend][active], tinter)
						
						if indirect_friends[friend][active] == 0:
							indirect_friends[friend][active] = -1
										
		return indirect_friends
	
	def spider_twitter_peers(self):
	
		#print repr(twitter.me().__dict__)
		peer_interaction = { }
		peer_interaction['retweeted_by_me'] = { }
		peer_interaction['retweets_of_me'] = { }
		peer_interaction['dm_to_me'] = { }
		peer_interaction['dm_by_me'] = { }
		peer_interaction['mentions_to_me'] = { }
		peer_interaction['mentions_by_me'] = { }
		
		
		friends = self.__get_friends()
		
		for user in friends:
			for interaction in peer_interaction:
				peer_interaction[interaction][user] = 0

		self.__spider(peer_interaction)
		return peer_interaction
		
	def send_direct_message (self, to, msg):
		self.__api_call('send_direct_message')(user_id=to, text=msg)
		
	def get_direct_messages (self, n):
		return self.__api_call('direct_messages')(count=n)
		
	def destroy_dm (self, id_dm):
		self.__api_call('destroy_direct_message')(id_dm)
		
