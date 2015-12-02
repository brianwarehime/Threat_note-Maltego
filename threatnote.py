#!/usr/bin/env python

import requests
import json
import urllib
from MaltegoTransform import *

host = "http://localhost:8888"

me = MaltegoTransform()
me.parseArguments(sys.argv)
t_type = sys.argv[1]
indicator = sys.argv[2]

if t_type == "relationships":
	try:
		uri = "/api/v1/relationships/"
		r = requests.get(host+uri+indicator)
		rels = json.loads(r.text)

		for rel in rels['relationships']:
			ent = me.addEntity("maltego."+rels['relationships'][rel],str(rel))
	except:
		pass

if t_type == "getcampaign":
	try:
		uri = "/api/v1/ip_indicator/"
		r = requests.get(host+uri+indicator)
		rels = json.loads(r.text)
		ent = me.addEntity("threatnote.Campaign",str(rels['indicator'][0]['campaign']))
	except:
		pass

if t_type == "getcampaignindicators":
	try:
		uri = "/api/v1/campaigns/"
		indicator = urllib.quote(indicator)
		r = requests.get(host+uri+indicator)
		rels = json.loads(r.text)
		for ind in rels['campaigns']:
			if ind['type'] == "IPv4":
				ent = me.addEntity("maltego.IPv4Address",str(ind['object']))
			else:
				ent = me.addEntity("maltego."+ind['type'],str(ind['object']))
	except:
		pass


me.returnOutput()

