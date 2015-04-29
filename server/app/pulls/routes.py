from . import pulls

@pulls.route('/')
def hello_world():
    return "hello world"
