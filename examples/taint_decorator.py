from taint import taint, sanitize, sink
import os

@taint()
def myInput():
    return input("Enter dir: ")

@sanitize()
def mySanitize(input):
    return input.replace('`', 'BACKTICK')

@sink()
def mySink(data):
    os.system('ls ' + data)

if __name__ == '__main__':
    i = myInput()
    s = mySanitize(i)
    mySink(s)
    mySink(mySanitize(myInput()))
    mySink(myInput())
