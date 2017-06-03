#!/bin/python3

from typing import Any, Callable, Dict, Generic, List, overload, Tuple, TypeVar, Union, TYPE_CHECKING
from types import MethodType

T = TypeVar('T')

class TaintTrackingBox(Generic[T]):
    def __init__(self, data: T) -> None:
        self.data = data

    DEBUG = False

    # List of binary operators that do not go through __getattr__
    # TODO: This list is likely incomplete
    binaryOps = [('__add__', '__radd__'),
                 ('__sub__', '__rsub__'),
                 ('__mul__', '__rmul__'),
                 ('__truediv__', '__rtruediv__'),
                 ('__floordiv__', '__rfloordiv__'),
                 ('__mod__', '__rmod__'),
                 ('__divmod__', '__rdivmod__'),
                 ('__pow__', '__rpow__'),
                 ('__lshift__', '__rlshift__'),
                 ('__rshift__', '__rrshift__'),
                 ('__and__', '__rand__'),
                 ('__or__', '__ror__'),
                 ('__xor__', '__rxor__'),
                 '__lt__',
                 '__le__',
                 '__eq__',
                 '__ne__',
                 '__gt__',
                 '__ge__']
                 
    for op in binaryOps:
        if isinstance(op, tuple):
            name, revName = op
            # Note that these are boxed
            exec("def %s(self, other: 'Union[T, UntaintedOrig[T], TaintedOrig[T]]') -> 'Union[Untainted[T], Tainted[T]]':\n\tboxer, val = self._taintBoxGen(other)\n\tfirst=self.data.%s(val)\n\tif first != NotImplemented:\n\t\treturn boxer(first)\n\telse:\n\t\treturn boxer(val.%s(self.data))" % (name, name, name))
            exec("def %s(self, other: 'Union[T, UntaintedOrig[T], TaintedOrig[T]]') -> 'Union[Untainted[T], Tainted[T]]':\n\treturn self.%s(other)" % (revName, name))
        else:
            # Note that these are not boxed
            exec("def %s(self, other: 'Union[T, UntaintedOrig[T], TaintedOrig[T]]') -> 'Union[Untainted[T], Tainted[T]]':\n\t_, val = self._taintBoxGen(other)\n\treturn self.data.%s(val)" % (op, op))

    # List of unary operators that do not go through __getattr__
    # TODO: This list is likely incomplete
    unaryOps = ['__len__',
                '__hash__',
                '__abs__',
                '__int__',
                '__float__',
                '__iter__']

    for name in unaryOps:
        # Note that these are not boxed
        exec("def %s(self) -> 'Union[UntaintedOrig[T], TaintedOrig[T]]':\n\treturn self.data.%s()" % (name, name))
        
    def _taintBoxGen(self, data: 'Union[T, UntaintedData[T], TaintedData[T]]') -> 'Tuple[Callable[[T], Union[UntaintedData[T], TaintedData[T]]], T]':
        raise NotImplementedError()
        
    def __getattr__(self, attr):
        res = eval("self.data."+attr)
        def inner(*args, **kwargs):
            fRes = res(*args, **kwargs)
            return self._taintBoxGen(self)[0](fRes)
        if callable(res):
            return inner
        else:
            return res
        
class UntaintedData(TaintTrackingBox[T]):
    def __init__(self, data: T) -> None:
        self.data = data

    def _taintBoxGen(self, data: 'Union[T, UntaintedData[T], TaintedData[T]]') -> 'Tuple[Callable[[T], Union[UntaintedData[T], TaintedData[T]]], T]':
        if isinstance(data, TaintedData):
            return lambda d: TaintedData(d), data.data
        else:
            if isinstance(data, UntaintedData):
                return lambda d: UntaintedData(d), data.data
            else:
                return lambda d: UntaintedData(d), data

    __str__ = __repr__ = lambda self: "Untainted data source: " + str(self.data)  # type: ignore
    # Ignore the type because otherwise it complains that object doesn't have a data attribute

class TaintedData(TaintTrackingBox[T]):
    def __init__(self, data: T) -> None:
        self.data = data

    def _taintBoxGen(self, data: 'Union[T, UntaintedData[T], TaintedData[T]]') -> 'Tuple[Callable[[T], Union[UntaintedData[T], TaintedData[T]]], T]':
        if isinstance(data, TaintedData):
            return lambda d: TaintedData(d), data.data
        else:
            if isinstance(data, UntaintedData):
                return lambda d: TaintedData(d), data.data
            else:
                return lambda d: TaintedData(d), data

    __str__ = __repr__ = lambda self: "Tainted data source!"

if TYPE_CHECKING:
    Tainted = TaintedData
    Untainted = UntaintedData
else:
    class IdentityClass:
        def __call__(self, x):
            return x
        def __getitem__(self, x):
            return self
    Tainted = Untainted = IdentityClass()

def taint(*args, **kwargs) -> Callable[[Callable[..., T]], Callable[..., Tainted[T]]]:
    if 'useOrig' in kwargs.keys() and kwargs['useOrig']:
        box = TaintedData
    else:
        box = Tainted
    def taintDecorator(func: Callable[..., T]) -> Callable[..., Tainted[T]]:
        """Decorate a function to specify it as a tainted data source"""
        def inner(*args: Any, **kwargs: Any) -> Tainted[T]:
            res = func(*args, **kwargs)
            return box(res)
        return inner
    return taintDecorator

def sanitize(*args, **kwargs) -> Callable[[Callable[[T], T]], Callable[[Union[Tainted[T], Untainted[T], T]], Untainted[T]]]:
    if 'useOrig' in kwargs.keys() and kwargs['useOrig']:
        box = UntaintedData
    else:
        box = Untainted
    def sanitizeDecorator(func: Callable[[T], T]) -> Callable[[Union[Tainted[T], Untainted[T], T]], Untainted[T]]:
        """Decorate a function to specify that given tainted data it returns untainted data"""
        def inner(data: Union[Tainted[T], Untainted[T], T]) -> Untainted[T]:
            if isinstance(data, TaintedData) or isinstance(data, UntaintedData):
                res = func(data.data)
            else:
                res = func(data)
            return box(res)
        return inner
    return sanitizeDecorator

V = TypeVar('V')

def sink() -> Callable[[Callable[[T], V]], Callable[[Untainted[T]], V]]:
    def sinkDecorator(func: Callable[[T], V]) -> Callable[[Untainted[T]], V]:
        """Decorate a function to specify it as a sink sensitive to tainted data"""
        def inner(data: Untainted[T]) -> V:
            if isinstance(data, TaintedData) or isinstance(data, UntaintedData):
                return func(data.data)
            else:
                return func(data)  # type: ignore
                # ignore b/c we say for type checking that this only accepts an Untainted
                # but in reality run time leads to it getting other data
        return inner
    return sinkDecorator

if __name__ == '__main__':
    assert Tainted(2) == 2 and type(Tainted(2)) == type(2)
    assert Untainted("a") == "a" and type(Untainted("a")) == type("a")
    print("Import taint to get started!")
