from . import new_conversations

@new_conversations.route('/')
def hello_world():
    return "hello world"
