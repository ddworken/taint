from taint import taint, sanitize, sink

class MyTaintableObject():
    def __init__(self, data):
        self.data = data

@taint()
def taintedObjectSource() -> MyTaintableObject:
    return MyTaintableObject("TAINTED")

def untaintedObjectSource() -> MyTaintableObject:
    return MyTaintableObject("UNTAINTED")

@sanitize()
def sanitizer(obj: MyTaintableObject) -> MyTaintableObject:
    return obj

@sink()
def out(obj: MyTaintableObject) -> None:
    print(obj.data)

out(sanitizer(taintedObjectSource()))
out(taintedObjectSource())
