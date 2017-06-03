from taint import taint, sanitize, sink
import os

def myInput():
    return input("Enter dir: ")

def mySanitize(input):
    return input.replace('`', 'BACKTICK')

def mySink(data):
    os.system('ls ' + data)

tMyInput = taint()(myInput)
tMySanitize = sanitize()(mySanitize)
tMySink = sink()(mySink)

if __name__ == '__main__':
    tMySink(tMySanitize(tMyInput()))
    tMySink(tMyInput())
