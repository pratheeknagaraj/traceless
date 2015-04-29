from . import pushes

@pushes.route('/')
def hello_world():
    return "hello world"

@new_users.route('/reserve>', methods=['POST'])
