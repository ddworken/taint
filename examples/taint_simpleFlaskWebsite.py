from taint import taint, sanitize, sink
from flask import Flask, request
app = Flask(__name__)

@app.route('/')
def main() -> str:
    return greetingStr(getName(request))

@taint
def getName(request):
    return request.args.get('user')

@sink
def greetingStr(username):
    return 'Hello %s!' % username 
