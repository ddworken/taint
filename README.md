# taint: Compile time taint analysis for python using mypy

### Status: WIP

## Intro

taint is an experiment in implementing compile time taint analysis based off of type annotations and mypy. There are three key decorators built in to taint: ```@taint```, ```@sanitize```, and ```@sink```. The ```@taint``` decorator should be used to decorate functions that return tainted data. The ```@sanitize``` decorator should be used to decorate functions that given tainted data return untainted data. The ```@sink``` decorator should be used to decorate functions that should never be fed tainted data. 

When mypy is run against this code: 

``` python
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
```

it throws an error: 

```
examples/taint_simpleFlaskWebsite.py:7: error: Argument 1 to "greetingStr" has incompatible type Tainted[Any]; expected Untainted[Any]
```

## Limitations

There are currently a number of ways of bypassing taint's tracking listed below from most to least likely to accidentally happen:

In python, ```str.join(data)``` requires that data be a list of strings (it does not call ```__str__``` on each object). This means that ''.join(Tainted(data)) returns untainted data.

Implicit flows aka:

```
var = Tainted("str")
if var == "str":
   var = "str"
```