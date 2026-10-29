"""Validated read-only profile extension points; no eval, write services or scripts."""
import ast, json, math, operator, re
from pathlib import Path

OPS={ast.Add:operator.add,ast.Sub:operator.sub,ast.Mult:operator.mul,ast.Div:operator.truediv,
     ast.BitAnd:operator.and_,ast.BitOr:operator.or_,ast.LShift:operator.lshift,ast.RShift:operator.rshift}

def formula(text,data):
    if not isinstance(text,str) or len(text)>300 or len(data)>64:raise ValueError('Formula limit exceeded')
    tree=ast.parse(text,mode='eval')
    if len(list(ast.walk(tree)))>100:raise ValueError('Formula too complex')
    def read(node):
        if isinstance(node,ast.Expression):return read(node.body)
        if isinstance(node,ast.Constant) and type(node.value) in (int,float) and abs(node.value)<=16777216:return node.value
        if isinstance(node,ast.Name) and re.fullmatch('[A-Z]',node.id):
            index=ord(node.id)-65
            if index>=len(data):raise ValueError('Missing response bytes')
            return data[index]
        if isinstance(node,ast.UnaryOp) and isinstance(node.op,ast.USub):return -read(node.operand)
        if isinstance(node,ast.BinOp) and type(node.op) in OPS:
            a,b=read(node.left),read(node.right)
            if isinstance(node.op,(ast.LShift,ast.RShift)) and (type(b)!=int or not 0<=b<=32):raise ValueError('Invalid bit shift')
            value=OPS[type(node.op)](a,b)
            if not math.isfinite(value) or abs(value)>1e15:raise ValueError('Formula output out of bounds')
            return value
        raise ValueError('Unsupported formula operation')
    return read(tree)

def validate(profile):
    required=('id','applicability','source','license','verification','commands')
    if not all(profile.get(k) for k in required):raise ValueError('Profile needs identity, applicability, source, license and verification')
    if not re.fullmatch('[a-zA-Z0-9_.-]{1,80}',profile['id']):raise ValueError('Invalid profile ID')
    if len(profile['commands'])>256:raise ValueError('Profile too large')
    for cmd in profile['commands']:
        if not re.fullmatch(r'(?:01|02|09)[0-9A-F]{2}(?:00)?|22[0-9A-F]{4}',cmd.get('request','')):
            raise ValueError('Only documented read services 01/02/09/22 are allowed')
        if not re.fullmatch(r'[0-9A-F]{3}|[0-9A-F]{8}',cmd.get('header','')):raise ValueError('Explicit ECU header required')
        if not isinstance(cmd.get('bytes'),int) or not 1<=cmd['bytes']<=64:raise ValueError('Invalid response length')
        formula(cmd['formula'],bytes([1])*cmd['bytes'])
        if not cmd.get('unit') or not cmd.get('name'):raise ValueError('Units and names required')
    return profile

def load(path):return validate(json.loads(Path(path).read_text()))
