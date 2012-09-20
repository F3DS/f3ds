import email
import config
import string
import rfc822
import imaplib
import smtplib
import datetime
import StringIO
import email.utils
from email.mime.text import MIMEText

configt = config.loadData()

class MailSpider():
	
	def __init__(self, user, password):
		self.user = user
		self.passwd = password
		
		try:
			self.mail = imaplib.IMAP4_SSL(configt['social']['imap_server'], configt['social']['imap_port'])
			self.mail.login(user, password)
		except Exception, e:
			print e

	def __del__(self):
		self.mail.logout()
		
	def __parse_email(self, raw_addres):
		return string.lower(email.utils.parseaddr(raw_addres)[1])
	
	def __get_body(self, content):
		
		payload = ''
		
		for part in content.walk():
			if part.get_content_maintype() == 'multipart' or part.get_content_subtype() != 'plain':
				continue
			
			payload += part.get_payload()
		  
		return payload.strip()
	
	def __get_mails(self, folder, criteria):
		
		self.mail.select(folder)
		
		months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'June', 'July', 'Aug', 'Sept', 'Oct', 'Nov', 'Dec']
		dt = (datetime.date.today() - datetime.timedelta(1 * 365 / 12)).isoformat().split('-')
		
		resp, items = self.mail.search(None, ('(SINCE "%s-%s-%s")' % (dt[2], months[int(dt[1]) - 1], dt[0])))
		mails_ids = string.split(items[0])
		addrs = []
		messages = []

		for id in mails_ids:	
			resp, data = self.mail.fetch(id, "(RFC822)")
			message = rfc822.Message(StringIO.StringIO(data[0][1]))
			
			for i, j in message.items():
				
				if string.upper(i) == string.upper(criteria):
					addrs.append(self.__parse_email(j))
					messages.append(self.__get_body(email.message_from_string(data[0][1])))
		
		return (addrs, messages)
		
	def __get_mails_by_me(self):
		return self.__get_mails(configt['social']['sent_fonder'], 'to')
		
	def __get_mails_to_me(self):
		return self.__get_mails(configt['social']['inbox_folder'], 'from')
		
	def get_emails_recieved(self):
		return self.__get_mails_to_me()
		
	def send_email(self, to, msg):
		message = MIMEText(msg)
		message['From'] = self.user
		message['To'] = to
		message['Subject'] = 'Social Scan'
		
		smtp = smtplib.SMTP(configt['social']['smtp_server'], configt['social']['smtp_port'])
		smtp.ehlo()
		smtp.starttls()
		smtp.ehlo()
		smtp.login(self.user, self.passwd)
		smtp.sendmail(self.user, [to], message.as_string())
		smtp.quit()
		
	def get_mail_peers(self):
		
		peer_interaction = { }
		to_me = { }
		
		for addr in self.__get_mails_by_me()[0]:
			if addr in peer_interaction:
				peer_interaction[addr] += 1
			else:
				peer_interaction[addr] = 1
				
		for addr in self.__get_mails_to_me()[0]:
			if addr in to_me:
				to_me[addr] += 1
			else:
				to_me[addr] = 1
				
		for peer in peer_interaction:
			if peer in to_me:
				t = min(peer_interaction[peer], to_me[peer])
				peer_interaction[peer] = t if t >= 0 else -1
			else:
				peer_interaction[peer] = -1
	
		return peer_interaction
