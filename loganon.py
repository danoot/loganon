#!/usr/bin/python

import re
import sys
import hashlib
import glob
import os

## globals ##
''' we use these to store mappings from source-> dest. This keeps them constant, if they've existed beforem
and is computationally less expensive than hashing everything every time. It also doesn't matter, you don't
need to use them if you don't want to. Your computer is fast and the hashing is deterministic.'''

translatable = {}
url_transtable = {}
ip_transtable = {}

## anonymising functions ##
''' feel free to roll your own, especially if you're using this as a translation/transformation tool
rather than an anonymiser per se. These should give you some idea how the thing works, though.'''

def default(s):
	''' take a string, return a hash of the string. not reversible, but repeatable. '''

	try:
		return translatable[s]
	except KeyError:
		translatable[s] = hashlib.sha1(s).hexdigest()
		return translatable[s]

def url(s):
	''' takes a URL and returns host+a hash of everything else. Useful for rough demographics stuff
	without being able to see all the specific urls people have visited. Keep in mind that if you use
	this on internal URLs you will expose least part of them, which you might not want to do. Or maybe
	you don't care. I don't know. Defaults back to default() if it can't run on this string.'''
	try:
		return url_transtable[s]
	except KeyError:
		i = s.find('/',8)
		if i == -1:
			return default(s)
		host = s[0:i+1]
		url = hashlib.sha1(s[i+1:]).hexdigest()
		url_transtable[s] = host + url
		return url_transtable[s]


def ip(s):
	''' takes an IP and maps it into a (usually) different valid IP.
	Please note that this function is collision prone and non-uniform, and so  shouldn't be used if you need to keep
	your data in exactly the same relationship to itself, right? defaults back to default() if this isn't an ip.'''
	try:
		return ip_transtable[s]
	except KeyError:
		try:
			a,b,c,d = s.split('.')
		except:
			return default(s)
		a = (int(a)**5)%255
		b = (int(b)**5)%255
		c = (int(c)**5)%255
		d = (int(d)**5)%255
		ip_transtable[s]="%s.%s.%s.%s" % (a,b,c,d)
		return ip_transtable[s]

## Configuration Section ##
''' look this stuff isn't very pretty but I tried to do this with conf files and importa and nah
so: just make sure your regex matches your file patterns and your functions match your attributes.
'''

filepath = "/var/log/radius/radius.log*"
# filepath can be a specific file or a glob that expands out to bunch of stuff

attributes = ('login','ip')
# attributes isn't strictly necessary but it makes it easier to keep track of things

functions = dict((k,default) for k in attributes)
# a dict of functions, where each one is the function you want to put an attribute through. You know?
# defaults to, uh, default. override things like so:
functions['ip'] = ip


regex = re.compile(".*\[(?P<%s>.*)\].* cli (?P<%s>[0-9.]+).*" % attributes)
# careful with that regex, Eugene. Like, if you miss a line it might not get anonymised properly.
# this one is for pulling otu usernames and client IPs from a radius server's logs.



for fname in glob.glob(filepath):
	#skip previously anonned files I guess:
	if fname[-5:] == '_anon':
		print 'skipping %s' % fname
		continue
	anon = "%s_anon" % fname
	if not os.path.exists(anon) or (os.path.getmtime(fname) > os.path.getmtime(anon)):
		#if you already did this one, skip it. Unless the source file has changed.
		with open(fname) as f:
			with open(anon,'w') as a:
				for line in f:
					m = regex.search(line)
					if not m:
						#careful with this, if your regex breaks for some reason you might dump un-anon'd lines.
						#consider just continue unless there's other things you need.
						a.write(line)
						continue
					groups = m.groupdict()
					for k,v in groups.iteritems():
						# replace each value (matched text) with the function for the type of the value
						# giving us, at the end, a translated string.
						line = line.replace(v,functions[k](v))
					a.write(line)






