class Server:

	def __init__(self, url, n, e):
		self.url = url
		self.n = n
		self.e = e

	def equal(self, other_server):
		self.url = other_server.url
		self.n = other_server.n
		self.e = other_server.e