import pyaml, yaml

from .util import PY3

from textwrap import wrap

from pyaml import UnsafePrettyYAMLDumper

def represent_stringish(dumper, data):
    data = unicode(data) # read the comment above

    style = dumper.pyaml_string_val_style
    if not style:
        style = 'plain'

        multiline = wrap(data, width=dumper.best_width)
        if "\n" not in data.strip() and len(multiline) > len(data.splitlines()):
            style = ">"

        elif '\n' not in data and ('@' in data or '{' in data or '}' in data):
            style = "'"

        elif '\n' in data or not data or data == '-' or data[0] in '!&*[?':
            style = "|"

    return yaml.representer.ScalarNode('tag:yaml.org,2002:str', data, style=style)

if PY3:
    unicode = str
for str_type in {bytes, unicode}:
    UnsafePrettyYAMLDumper.add_representer(
        str_type, represent_stringish )

