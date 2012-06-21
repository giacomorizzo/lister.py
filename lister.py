#!/usr/bin/env python2

#	This program is free software: you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import tweepy
import pickle
import argparse

parser = argparse.ArgumentParser(description='lister.py will find new twitter friends suggestions for you!')
parser.add_argument('-u', '--user', action="store", type=str, dest="username", help="Your Twitter username", nargs='?', required=True)
parser.add_argument('-l', '--list', action="store", type=str, dest="twitter_list", help="The Twitter list that will be analyzed", nargs='?')
parser.add_argument('-m', '--minimum', action="store", type=int, dest="minimum", help="Minimum number of list members in common to show up in the results", nargs='?', default=5)
parser.add_argument('-f', '--file', action="store", type=str, dest="caching_file", help="If specified, lister.py will read and save results from/to this file", nargs='?', default='')
parser.add_argument('-i', '--auth-file', action="store", type=str, dest="auth_file", help="API Authentication file", nargs='?', default="lister.auth")
parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1')
results = parser.parse_args()

crossed = {}
if results.caching_file:
	try:
		# Do we have cached list results?
		cachefile = open(results.caching_file, 'r') 
		crossed = dict(pickle.load(cachefile))
		cachefile.close()
		print "Cached iteration results loaded."
	except:
		# The specified file is currently empty. Will use it as output file only...
		pass

if not len(crossed):
	# No items loaded from the cache file
	
	# Twitter application identifier for lister.py
	consumer_token = 'QkpCmcrR1QanvrEC1DlxbA'
	consumer_secret = 'jH2NwcHfqlmftQ5PqJq0Naj2JbXAV4mkpEeb8MesA'

	auth = tweepy.OAuthHandler(consumer_token, consumer_secret)

	authparm = {}
	try:
		# Let's try to read cached authentications parameters
		filehandler = open(results.auth_file, 'r') 
		authparm = dict(pickle.load(filehandler))
		filehandler.close()
	except:
		# No file...
		pass

	# Do we have authentication tokens?
	if not set(['auth_token', 'auth_secret']).issubset(authparm.keys()):
		# No... asking the user to authenticate us.

		auth_url = auth.get_authorization_url()
		print 'Please authorize: ' + auth_url
		verifier = raw_input('PIN: ').strip()

		# Gathering tokens from Twitter using the PIN
		auth.get_access_token(verifier)
		authparm['auth_token'] = auth.access_token.key
		authparm['auth_secret'] = auth.access_token.secret

		# Caching authentication tokens for next iterations...
		cachefile = open(results.auth_file, 'w') 
		pickle.dump(authparm, cachefile) 
		cachefile.close()	

	print "Authenticating agains Twitter APIs..."
	auth.set_access_token(authparm['auth_token'], authparm['auth_secret'])
	api = tweepy.API(auth)

	if not api.verify_credentials():
		# Something went wrong here...
		print "Error: could not verify your credentials!"
		sys.exit(1)

	if not results.twitter_list:
		counter = 1
		menu = []
		for tw_list in api.lists():
			menu.append(tw_list.name)
			print "%d) %s" % (counter, tw_list.name)
			counter += 1
		if counter == 1:
			print "No lists found on your Twitter account!"
			sys.exit(1)
		else:
			results.twitter_list = menu[int(raw_input('Choose a list to analyze: ').strip())-1]
	
	print "Gathering friends of %s's '%s' list members..." % (results.username, results.twitter_list)

	for user in api.list_members(results.username, results.twitter_list):
		sys.stdout.write("\tLoading %s's friends: " % user.screen_name)
		sys.stdout.flush()

		users = 0
		cursor = tweepy.Cursor(api.friends, id=user.screen_name)
		for follows in cursor.items():
			users += 1
			if follows.screen_name in crossed.keys():
				crossed[follows.screen_name] += 1
			else:
				crossed[follows.screen_name] = 1

		sys.stdout.write("%d users fetched\n" % users)
		sys.stdout.flush()

	print "Removing %s's friends:" % results.username
	cursor = tweepy.Cursor(api.friends, id=results.username)
	for following in cursor.items():
		if following.screen_name in crossed.keys():
			print '\tremoving {0:20}\t({1} list members in common)'.format(following.screen_name, crossed[following.screen_name])
			del crossed[following.screen_name]

	print "Removing yourself..."
	if results.username in crossed.keys():
		del crossed[results.username]

	if results.caching_file:
		# Caching results
		cachefile = open(results.caching_file, 'w')
		pickle.dump(crossed, cachefile) 
		cachefile.close()	
		print "Results saved in file %s" % results.caching_file

print "== Suggested friends with at least %d list members in common ==" % results.minimum
for key, value in sorted(crossed.iteritems(), key=lambda (k,v): (v,k)):
	if value >= results.minimum:
		print '{0:20}\t{1:3}\thttps://twitter.com/{0}'.format(key, value)
