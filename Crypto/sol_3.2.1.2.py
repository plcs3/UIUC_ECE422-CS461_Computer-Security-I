import sys
from urllib import quote
from pymd5 import md5, padding

with open(sys.argv[1]) as query_file, open(sys.argv[2]) as command3_file, open(sys.argv[3], 'w') as output:
	orig_query = query_file.read().strip()
	params = orig_query.split('&')
	token_param = params[0].split('=')

	x = command3_file.read().strip()

	h = md5(state=token_param[1].decode("hex"), count=512)
	h.update(x)
	
	new_token = h.hexdigest()
	new_query = token_param[0] + '=' + new_token + '&'.join(params[1:]) + x
	output.write(new_query)
