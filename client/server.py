class Server:

	def __init__(self, url, n, e):
		self.url = url
		self.n = n
		self.e = e

	def equal(self, other_server):
		return self.url == other_server.url and self.n = other_server.n and self.e = other_server.e