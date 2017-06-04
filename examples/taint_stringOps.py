from taint import taint, sanitize, sink

@taint()
def myInput() -> str:
    return "word1 word2"

@sanitize()
def mySanitize(input: str) -> str:
    return input.replace(' ', '_')

@sink()
def mySink(data: str):
    print("DATA=%s" % data)

if __name__ == '__main__':
    data = myInput()
    i = data.find(' ')
    mySink(data[i:])
    mySink(mySanitize(data[i:]))
