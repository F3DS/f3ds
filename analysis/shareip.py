import re
import rsa
import time
import json
import tweepy
import config
import urllib2
import hashlib
import binascii
import threading
import mailspider
import sqlalchemy
import twitterspider
import facebookspider
import socialdistance
from sqlalchemy.orm import create_session
from sqlalchemy.ext.declarative import declarative_base

data = config.loadData()

db = sqlalchemy.create_engine(data['db']['mysql_connection'])
metadata = sqlalchemy.MetaData(db)
Base = declarative_base()

class SocialPeer(Base):
	__table__ = sqlalchemy.Table('socialpeers', metadata, autoload=True)

def get_ip():
	return urllib2.urlopen(data['social']['url_get_ip']).read()

def get_message(user):
	return ("Hi %s: My current IP is: %s. This is an automated message from SocialCollab." % (user, get_ip()))

class ShareIpFacebook:

	def __init__(self, user_email):
		self.mutex = threading.Lock()
		self.mutex.acquire()
		self.user = hashlib.md5(user_email.upper()).hexdigest()
		self.session = create_session(bind=db)
		self.fbspider = facebookspider.FacebookSpider(user_email)
		self.jsn = json.load(open(data['db']['filename_facebook'], 'r'))
		self.mkeys = None

		if 'public' not in self.jsn[self.user]['keys']:
			self.mkeys = self.__generate_keys()
			self.jsn[self.user]['keys'] = { 'public': self.mkeys[0].save_pkcs1(format='PEM'), 'private' : self.mkeys[1].save_pkcs1(format='PEM')}
			writer = open(data['db']['filename_facebook'], 'w')
			writer.write (json.dumps(self.jsn, indent = 4, sort_keys = True))
			writer.close()
		else:
			self.mkeys = (self.__import_public_key(self.jsn[self.user]['keys']['public']) , self.__import_private_key(self.jsn[self.user]['keys']['private']))

		self.mutex.release()

	def __import_public_key(self, dt):
		return (rsa.newkeys(512)[0]).load_pkcs1(dt, format='PEM')

	def __import_private_key(self, dt):
		return rsa.newkeys(512)[1].load_pkcs1(dt, format='PEM')

	def __generate_keys(self):
		return rsa.newkeys(512)

	def __crypt_ip(self, key):
		pubkey = self.__import_public_key(key)
		return binascii.hexlify(rsa.encrypt(get_ip(), pubkey))

	def __decrypt_ip(self, inf):
		return rsa.decrypt (binascii.a2b_hex(inf), self.mkeys[1])

	def __share_ip(self):

		while True:
                        self.share_public_key()
			self.mutex.acquire()
			self.fbspider.refresh_api()
			self.jsn = json.load(open(data['db']['filename_facebook'], 'r'))
			social_distance = socialdistance.calculate_social_distance(self.fbspider.spider_facebook_peers(), facebook=True)
			#peers = [{ 'id' : 711736710, 'key' : '-----BEGIN RSA PUBLIC KEY-----\nMEgCQQCGLar9k9EN6W0x86ccXrr491f3v7G2pEzI7AQWg649Cv1SxYuts36Aresf\nBEM+yL75n74Z7dkeqBJwo4IRwoQ7AgMBAAE=\n-----END RSA PUBLIC KEY-----\n'}]
			peers = {}

			if 'key_peers' in self.jsn[self.user]:
				peers = self.jsn[self.user]['key_peers']

			for peer in peers:
				if peer['id'] in social_distance and social_distance[peer['id']] < float(data['social']['social_distace_allowed']):
					fpeer = self.session.query(SocialPeer).filter_by(id_peer=peer['id']).all()
					if len(fpeer) == 0:
						us = SocialPeer()
						us.id_peer = peer['id']
						us.social_distance = social_distance[peer['id']]
						us.ip = ''
						us.source = 'facebook'
						self.session.merge(us)
						self.session.flush()
					else:
						fpeer[0].us.social_distance = social_distance[peer['id']]
						self.session.merge(fpeer[0])
						self.session.flush()

					msg = 'Hi %s: My current IP is: %s. This is an automated message from SocialCollab.' % (peer['id'], self.__crypt_ip(peer['key']))
					self.fbspider.public_in_friend_wall(peer['id'], msg)

			self.mutex.release()
			time.sleep(float(data['social']['time_send_dm']))

	def __read_ip(self):

		while True:
			self.mutex.acquire()
			self.fbspider.refresh_api()
			wall = self.fbspider.get_my_wall()

			for post in wall['data']:
				if 'message' in post:
					mtch = re.match(r'Hi (.*): My current IP is: (.*). This (.*).', str(post['message']))
					if mtch != None:
						groups = mtch.groups()
						if len(groups) == 3:
							peer = SocialPeer()
							peer.id_peer = post['from']['id']
							peer.ip = self.__decrypt_ip(groups[1])
							peer.source = 'facebook'
							peer.social_distance = -1

							fpeer = self.session.query(SocialPeer).filter_by(id_peer=post['from']['id']).all()
							if len(fpeer) > 0:
								peer.social_distance = fpeer[0].social_distance

							self.session.merge(peer)
							self.session.flush()

			self.mutex.release()
			time.sleep(float(data['social']['time_send_dm']))

	def __get_public_keys(self):

		while True:
			self.mutex.acquire()
			self.fbspider.refresh_api()
			peers = socialdistance.calculate_social_distance(self.fbspider.spider_facebook_peers(), facebook=True)
			kys = []

			for peer in peers:
				for post in self.fbspider.get_wall(peer)['data']:
					if 'message' in post:
						try:
							mtch = re.match(r'My public key is: (.*)', str(post['message']))

							if mtch != None:
								kys.append({'id' : post['from']['id'], 'key' : post['message'][18:]})
								print kys
						except Exception, e: print e

			self.jsn = json.load(open(data['db']['filename_facebook'], 'r'))

			added = []

			for k in kys:
				for t in k:
					added.append(t)

			if 'key_peers' in self.jsn[self.user]:
				for peer in self.jsn['key_peers']:
					if user not in added:
						kys.append(peer)

			self.jsn[self.user]['key_peers'] = kys
			writer = open(data['db']['filename_facebook'], 'w')
			writer.write (json.dumps(self.jsn, indent = 4, sort_keys = True))
			writer.close()
			self.mutex.release()
			time.sleep(float(data['social']['time_read_public_key']))

	def share_public_key(self):
		self.fbspider.public_in_my_wall('My public key is: ' + self.mkeys[0].save_pkcs1(format='PEM'))

	def run(self):
		threading.Thread(target=self.__get_public_keys).start()
		threading.Thread(target=self.__read_ip).start()
		threading.Thread(target=self.__share_ip).start()


class ShareIpTwitter:

	def __init__(self, user_screen_name):
		self.twitter = None
		self.tspider = None
		self.mutex = threading.Lock()
		self.session = create_session(bind=db)
		self.__autentificate (user_screen_name)

	def __autentificate(self, user_screen_name):

		autent = TwitterAutentification(user_screen_name, data['application']['twitter_consumer_key'], data['application']['twitter_consumer_secret'])

		if not autent.is_verificated_user():
			print autent.get_autenticate_url()
			autent.set_pin(raw_input('Ingrese Pin: '))
			autent.save_verificated_user()

		self.twitter = autent.get_api()
		self.tspider = twitterspider.TwitterSpider(self.twitter)

	def __send_dms(self):

		while True:
			self.mutex.acquire()

			peer_itr = self.tspider.spider_twitter_peers()
			social_distances = socialdistance.calculate_social_distance(peer_itr, twitter=True)

			for user in social_distances:
				if social_distances[user] < float(data['social']['social_distace_allowed']):
					fpeer = self.session.query(SocialPeer).filter_by(id_peer=user).all()
					if len(fpeer) == 0:
						us = SocialPeer()
						us.id_peer = user
						us.social_distance = social_distances[user]
						us.ip = ''
						us.source = 'twitter'
						self.session.merge(us)
						self.session.flush()
					else:
						fpeer[0].us.social_distance = social_distances[user]
						self.session.merge(fpeer[0])
						self.session.flush()

					if social_distances[user] != -1:
						try:
							self.tspider.send_direct_message(user, get_message(user))
						except Exception, e:
							print "This message has been sent"

			self.mutex.release()
			time.sleep(float(data['social']['time_send_dm']))

	def __read_dms(self):
		while True:
			self.mutex.acquire()

			for dms in self.tspider.get_direct_messages(50):
				mtch = re.match(r'Hi (.*): My current IP is: (.*). This (.*).', dms.text, re.M|re.I)

				if mtch != None:
					groups = mtch.groups()
					if len(groups) == 3:
						peer = SocialPeer()
						peer.id_peer = str(dms.sender.id)
						peer.ip = groups[1]
						peer.source = 'twitter'
						peer.social_distance = -1

						fpeer = self.session.query(SocialPeer).filter_by(id_peer=dms.sender.id).all()
						if len(fpeer) > 0:
							peer.social_distance = fpeer[0].social_distance

						self.session.merge(peer)
						self.session.flush()
						self.tspider.destroy_dm(dms.id)

			self.mutex.release()
			time.sleep(float(data['social']['time_read_dm']))

	def run(self):
		threading.Thread(target=self.__read_dms).start()
		threading.Thread(target=self.__send_dms).start()


class ShareIpMail:

	def __init__(self, user, password):
		self.mspider = mailspider.MailSpider(user, password)
		self.mutex = threading.Lock()
		self.session = create_session(bind=db)

	def __send_email(self):
		while True:
			self.mutex.acquire()

			peer_itr = self.mspider.get_mail_peers()
			social_distances = socialdistance.calculate_social_distance(peer_itr, email=True)

			for user in social_distances:

				if social_distances[user] < float(data['social']['social_distace_allowed']):
					fpeer = self.session.query(SocialPeer).filter_by(id_peer=user).all()
					if len(fpeer) == 0:
						us = SocialPeer()
						us.id_peer = user
						us.social_distance = social_distances[user]
						us.ip = ''
						us.source = 'email'
						self.session.merge(us)
						self.session.flush()
					else:
						fpeer[0].us.social_distance = social_distances[user]
						self.session.merge(fpeer[0])
						self.session.flush()

					if social_distances[user] != -1:
						try:
							self.mspider.send_email(user, get_message(user))
						except Exception, e:
							print e

			self.mutex.release()
			time.sleep(float(data['social']['time_send_dm']))

	def __read_emails(self):
		while True:
			self.mutex.acquire()

			dt = self.mspider.get_emails_recieved()
			addrs = dt[0]
			emails = dt[1]

			for pair in zip(addrs, emails):

				mtch = re.match(r'Hi (.*): My current IP is: (.*). This (.*).', str(pair[1]))

				if mtch != None:
					groups = mtch.groups()
					print groups
					if len(groups) == 3:
						peer = SocialPeer()
						peer.id_peer = pair[0]
						peer.ip = groups[1]
						peer.source = 'email'
						peer.social_distance = -1

						fpeer = self.session.query(SocialPeer).filter_by(id_peer=pair[0]).all()
						if len(fpeer) > 0:
							peer.social_distance = fpeer[0].social_distance

						self.session.merge(peer)
						self.session.flush()

			self.mutex.release()
			time.sleep(float(data['social']['time_read_dm']))

	def run(self):
		threading.Thread(target=self.__read_email).start()
		threading.Thread(target=self.__send_email).start()

