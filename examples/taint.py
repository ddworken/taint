#!/bin/python3

from typing import Any, Callable, Generic, overload, Tuple, TypeVar, Union

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
            exec("def %s(self, other: 'Union[T, Untainted[T], Tainted[T]]') -> 'Union[Untainted[T], Tainted[T]]':\n\tboxer, val = self._taintBoxGen(other)\n\tfirst=self.data.%s(val)\n\tif first != NotImplemented:\n\t\treturn boxer(first)\n\telse:\n\t\treturn boxer(val.%s(self.data))" % (name, name, name))
            exec("def %s(self, other: 'Union[T, Untainted[T], Tainted[T]]') -> 'Union[Untainted[T], Tainted[T]]':\n\treturn self.%s(other)" % (revName, name))
        else:
            # Note that these are not boxed
            exec("def %s(self, other: 'Union[T, Untainted[T], Tainted[T]]') -> 'Union[Untainted[T], Tainted[T]]':\n\t_, val = self._taintBoxGen(other)\n\treturn self.data.%s(val)" % (op, op))

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
        exec("def %s(self) -> 'Union[Untainted[T], Tainted[T]]':\n\treturn self.data.%s()" % (name, name))
        
    def _taintBoxGen(self, data: 'Union[T, Untainted[T], Tainted[T]]') -> 'Tuple[Callable[[T], Union[Untainted[T], Tainted[T]]], T]':
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
        
class Untainted(TaintTrackingBox[T]):
    def __init__(self, data: T) -> None:
        self.data = data

    def _taintBoxGen(self, data: 'Union[T, Untainted[T], Tainted[T]]') -> 'Tuple[Callable[[T], Union[Untainted[T], Tainted[T]]], T]':
        if isinstance(data, Tainted):
            return lambda d: Tainted(d), data.data
        else:
            if isinstance(data, Untainted):
                return lambda d: Untainted(d), data.data
            else:
                return lambda d: Untainted(d), data

    __str__ = __repr__ = lambda self: "Untainted data source: " + str(self.data)

class Tainted(TaintTrackingBox[T]):
    def __init__(self, data: T) -> None:
        self.data = data

    def _taintBoxGen(self, data: 'Union[T, Untainted[T], Tainted[T]]') -> 'Tuple[Callable[[T], Union[Untainted[T], Tainted[T]]], T]':
        if isinstance(data, Tainted):
            return lambda d: Tainted(d), data.data
        else:
            if isinstance(data, Untainted):
                return lambda d: Tainted(d), data.data
            else:
                return lambda d: Tainted(d), data

    __str__ = __repr__ = lambda self: "Tainted data source!"

def taint(func: Callable[..., T]) -> Callable[..., Tainted[T]]:
    """Decorate a function to specify it as a tainted data source"""
    def inner(*args: Any, **kwargs: Any) -> Tainted[T]:
        res = func(*args, **kwargs)
        return Tainted(res)
    return inner

def sanitize(func: Callable[[T], T]) -> Callable[[Union[Tainted[T], Untainted[T], T]], Union[Untainted[T], T]]:
    """Decorate a function to specify that given tainted data it returns untainted data"""
    def inner(data: Union[Tainted[T], Untainted[T], T]) -> Union[Untainted[T], T]:
        if isinstance(data, Tainted) or isinstance(data, Untainted):
            res = func(data.data)
        else:
            res = func(data)
        return Untainted(res)
    return inner

V = TypeVar('V')

def sink(func: Callable[[T], V]) -> Callable[[Untainted[T]], V]:
    """Decorate a function to specify it as a sink sensitive to tainted data"""
    def inner(data: Untainted[T]) -> V:
        return func(data.data)
    return inner

