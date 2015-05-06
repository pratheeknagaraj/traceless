class Conversation:

	def __init__(self, my_user, other_user, read_slot_id, write_slot_id, 
				 read_nonce, read_slot_sig):
		self.read_nonce = read_nonce
		self.read_slot_sig = read_slot_sig
		__init__(my_user, other_user, read_slot, write_slot)

	def __init__(self, my_user, other_user, read_slot_id, write_slot_id):
		self.my_user = my_user
		self.other_user = other_user
		self.messages = []
		self.read_slot_id = read_slot_id
		self.write_slot_id = write_slot_id

	def add_read_text(self, text):
		self.messages.append( (self.other_user, text) )

	def add_write_text(self, text):
		self.messages.append( (self.my_user, text) )

	def update_read_slot(self, read_slot):
		self.read_slot = read_slot

	def update_write_slot(self, write_slot):
		self.write_slot = write_slot

	def get_conversation(self):
		return self.__str__()

	def __str__(self):
		out = "=== Conversation with " + self.other_user.username + " ===\n"
		for message in self.messages:
			user = message[0]
			text = message[1]
			out += "\t" + user.username + " - " + text + "\n"
		return out

	def __repr__(self):
		return self.__str__()