#!/bin/python

from taint import taint, sanitize, sink, Tainted, Untainted, TaintedData, UntaintedData
#from taint import TaintedData as Tainted
#from taint import UntaintedData as Untainted
#from taint import Tainted as TaintedIdentity
#from taint import Untainted as UntaintedIdentity
from subprocess import CalledProcessError, check_output
from typing import get_type_hints

def testArithOperators():
    u = UntaintedData(2)
    t = TaintedData(4)
    assert isinstance(u+3, UntaintedData)
    assert isinstance(3+u, UntaintedData)
    assert isinstance(u+t, TaintedData)
    assert isinstance(t+u, TaintedData)
    assert isinstance(t+t, TaintedData)
    assert isinstance(u+u, UntaintedData)
    assert (u+3).data == 5
    assert (3+u).data == 5
    assert (t+u).data == 6
    assert (u+t).data == 6

    assert isinstance(u*3, UntaintedData)
    assert isinstance(u*t, TaintedData)
    assert isinstance(t*u, TaintedData)
    assert isinstance(t*t, TaintedData)
    assert isinstance(u*u, UntaintedData)
    assert (u*t).data == 8
    assert (t*u).data == 8
    assert (u*"Test").data == "TestTest"
    assert ("Test"*u).data == "TestTest"
    assert (t*"Test").data == "TestTestTestTest"
    assert ("Test"*t).data == "TestTestTestTest"
    assert isinstance(u*'T', UntaintedData)
    assert isinstance('T'*u, UntaintedData)
    assert isinstance('T'*t, TaintedData)
    assert isinstance(t*'T', TaintedData)

    assert (u-t).data == -2
    assert (t-u).data == 2
    assert (u/t).data == 0.5
    assert (t/u).data == 2
    assert (u//t).data == 0
    assert (t//u).data == 2

    assert (t%u).data == 0
    assert (u%t).data == 2
    assert divmod(u, t).data == (0,2)
    assert divmod(t, u).data == (2, 0)
    assert (u**t).data == 16
    assert (t**u).data == 16
    assert (u>>t).data == 2>>4
    assert (t>>u).data == 4>>2
    assert (u<<t).data == 2<<4
    assert (t<<u).data == 4<<2
    assert (t & u).data == (4 & 2)
    assert (u & t).data == (2 & 4)
    assert (t | u).data == (4 | 2)
    assert (u | t).data == (2 | 4)
    assert (t ^ u).data == 4 ^ 2
    assert (u ^ t).data == 2 ^ 4

def testMiscBuiltins():
    u = UntaintedData(2)
    t = TaintedData(4)
    assert hash(u) == u.__hash__() == hash(2) == int(2).__hash__()
    assert hash(t) == t.__hash__() == hash(4) == int(4).__hash__()
    u = UntaintedData("ab")
    t = TaintedData("abcd")
    assert u.__len__() == len(u) == len("ab") == 2
    assert t.__len__() == len(t) == len("abcd") == 4
    u = UntaintedData(-2/3)
    t = UntaintedData(-1E100)
    assert abs(u) == u.__abs__() == abs(-2/3) == 2/3
    assert abs(t) == t.__abs__() == abs(-1E100) == 1E100
    assert int(u) == u.__int__() == int(-2/3) == 0
    assert int(t) == t.__int__() == int(-1E100) == -1E100
    assert float(u) == u.__float__() == float(-2/3) == -2/3
    assert float(t) == t.__float__() == float(-1E100) == -1E100
    assert list(iter(UntaintedData(range(5)))) == list(UntaintedData(range(5)).__iter__()) == list(iter(range(5))) == list(range(5).__iter__())
    assert list(iter(TaintedData(range(5)))) == list(TaintedData(range(5)).__iter__()) == list(iter(range(5))) == list(range(5).__iter__())
    
def testTaintSpreadingViaArith():
    t = TaintedData(4)
    u = UntaintedData(2)
    assert isinstance(t, TaintedData)
    assert isinstance(u, UntaintedData)
    g = 5
    assert not isinstance(g, TaintedData)
    g = g * t
    assert isinstance(g, TaintedData)
    g = g - u
    assert isinstance(g, TaintedData)

def testTaintSpreadingViaFunctions():
    t = TaintedData(4)
    assert isinstance(t, TaintedData)
    simpleLambda = lambda d: d
    assert isinstance(simpleLambda(t), TaintedData)
    def func(arg):
        return arg*2-1
    assert isinstance(func(t), TaintedData)
    def tupleFunc1(arg1, arg2):
        return arg2, arg1
    u = UntaintedData(2)
    assert isinstance(u, UntaintedData)
    res1, res2 = tupleFunc1(t, u)
    assert isinstance(res1, UntaintedData)
    assert isinstance(res2, TaintedData)
    def tupleFunc2(arg1, arg2, arg3):
        return arg3, arg2*arg1, arg1
    res1, res2, res3 = tupleFunc2(t, u, "A")
    assert not isinstance(res1, TaintedData)
    assert isinstance(res1, str)
    assert isinstance(res2, TaintedData)
    assert isinstance(res3, TaintedData)

def testTaintDecorator():
    @taint(useOrig=True)
    def taintedSourceOrig():
        return "Tainted str"

    @taint()
    def taintedSourceIdentity():
        return "Tainted str"
    
    def untaintedSource():
        return "Untainted str"

    assert isinstance(taintedSourceOrig(), TaintedData)  # compile time
    assert isinstance(taintedSourceIdentity(), str)  # run time
    assert not isinstance(untaintedSource(), TaintedData)
    assert isinstance(untaintedSource(), str)

def testSanitizeDecorator():
    @sanitize(useOrig=True)
    def taggedSanitizeOrig(data):
        return data.replace(' ', '_')

    @sanitize()
    def taggedSanitizeIdentity(data):
        return data.replace(' ', '_')
    
    def untaggedSanitize(data):
        return data.replace(' ', '_')

    assert isinstance(taggedSanitizeOrig(TaintedData(" ")), UntaintedData)
    assert isinstance(taggedSanitizeOrig(UntaintedData(" ")), UntaintedData)
    assert isinstance(taggedSanitizeOrig(" "), UntaintedData)
    assert isinstance(taggedSanitizeIdentity(" "), str)
    print(untaggedSanitize(TaintedData(" ")))
    assert isinstance(untaggedSanitize(TaintedData(" ")), TaintedData)
    assert isinstance(untaggedSanitize(UntaintedData(" ")), UntaintedData)
    assert isinstance(untaggedSanitize(" "), str)
    assert len(list(get_type_hints(taggedSanitizeOrig).values())) == 2
    assert str(get_type_hints(untaggedSanitize)) == "{}"
    
def testSinkDecorator():
    @sink()
    def taggedSink(data):
        return str(type(data))

    def untaggedSink(data):
        return str(type(data))

    assert "int" in taggedSink(TaintedData(2))
    assert "Tainted" in untaggedSink(TaintedData(2))
    assert len(list(get_type_hints(taggedSink).values())) == 2
    assert str(get_type_hints(untaggedSink)) == "{}"
    
def testEquality():
    u2 = Untainted(2)
    u4 = Untainted(4)
    t2 = Tainted(2)
    t4 = Tainted(4)
    assert u2 == u2 == Untainted(2) == 2 == t2 == t2 == Tainted(2)
    assert u4 == u4 == Untainted(4) == 4 == t4 == t4 == Tainted(4)
    assert u2 != u4 != t2 != t4
    assert u2 < u4
    assert t2 < t4
    assert u2 < t4
    assert t2 < u4
    assert u2 <= t2 <= u4 <= t4
    assert u2 <= u2
    assert u4 <= u4
    assert t2 <= t2
    assert t4 <= t4
    assert u4 > u2
    assert u4 > t2
    assert t4 > t2
    assert t4 > u2
    assert t4 >= u4 >= t2 >= u2
    assert u2 >= u2
    assert u4 >= u4
    assert t2 >= t2
    assert t4 >= t4

def testTaintBoxGen():
    u = UntaintedData("str1")
    t = TaintedData("str2")
    assert u._taintBoxGen(t)[1] == "str2"
    assert u._taintBoxGen(t)[0]("example").data == "example"
    assert u._taintBoxGen(u)[1] == "str1"
    assert u._taintBoxGen(u)[0]("example").data == "example"
    assert u._taintBoxGen("other")[1] == "other"
    assert u._taintBoxGen("other")[0]("example").data == "example"

def testMypyExamples():
    mypyErrorString1 = b"error: Argument 1 to \"%s\" has incompatible type TaintedData[Any]; expected UntaintedData[Any]"
    mypyErrorString2 = b"error: Argument 1 has incompatible type TaintedData[Any]; expected UntaintedData[Any]"

    try:
        check_output(['mypy', 'examples/taint_decorator.py'])
        assert False  # mypy should have an exit code of 1
    except CalledProcessError as e:
        assert mypyErrorString1 % b'mySink' in e.output
    try:
        check_output(['mypy', 'examples/taint_higherOrderedFunctions.py'])
        assert False  # mypy should have an exit code of 1
    except CalledProcessError as e:
        assert mypyErrorString2 in e.output
    try:
        check_output(['mypy', 'examples/taint_simpleFlaskWebsite.py'])
        assert False  # mypy should have an exit code of 1
    except CalledProcessError as e:
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"*10)
        print(mypyErrorString1 % b'greetingStr')
        print(e.output)
        assert mypyErrorString1 % b'greetingStr' in e.output

if __name__ == '__main__':
    print(type(Tainted))
