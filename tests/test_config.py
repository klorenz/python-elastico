from elastico.config_factory import ConfigFactory
from elastico.config import Config
from textwrap import dedent
from os.path import dirname

def test_config():
    cfg = Config({'foo': 'bar', 'x': {'a': 'b'}})
    assert cfg['foo'] == 'bar'
    assert cfg.get('foo') == 'bar'
    assert cfg.get('x.a') == 'b'

def test_format_value():
    assert Config({"a": "b"}).format_value("{a}") == "b"
    assert Config({"a": "b"}).format_value({"x": "{a}"}) == {"x": "b"}
    assert Config({"a": "b"}).format_value(["{a}", "c"]) == ["b", "c"]

def test_read_config_dir(tmpdir):
    tmpdir.join("f1.yml").write(dedent("""
        id: 1
        a1: b1
        b1: c1
    """))

    tmpdir.join("f2.yml").write(dedent("""
        id: 2
        a2: b2
        b2: c2
        ---
        id: 3
        a3: b3
        b3: c3
    """))

    config = Config().update_from_dir(tmpdir.strpath, 'docs')

    config['docs'].sort(key = lambda x: x['id'] )

    assert config['docs'][0]['a1'] == 'b1'
    assert config['docs'][2]['a3'] == 'b3'


def test_read_config_dir_recursive(tmpdir):
    tmpdir.join("f1.yml").write(dedent("""
        id: 1
        a1: b1
        b1: c1
    """))

    tmpdir.mkdir('subdir').join("f2.yml").write(dedent("""
        id: 2
        a2: b2
        b2: c2
        ---
        id: 3
        a3: b3
        b3: c3
    """))

    config = Config().update_from_dir(tmpdir.strpath, 'docs', recursive=True)

    config['docs'].sort(key = lambda x: x['id'] )

    assert config['docs'][0]['a1'] == 'b1'
    assert config['docs'][2]['a3'] == 'b3'


def test_config_includes(tmpdir):
    f1 = tmpdir.join('f1.yml')
    f1.write(dedent('''
        a1: b1
        a2: b2
        include:
        - f2.yml
        - directory: d1
          append: d1_items
        - directory: d2
          update: d2_item

        d2_item:
          k1: v1
          k2: v2
    '''))
    f2 = tmpdir.join('f2.yml')
    f2.write(dedent('''
        a2: some_other_value
        a3: b3
    '''))
    d1 = tmpdir.mkdir('d1')
    f3 = d1.join('d1_1.yml')
    f3.write(dedent('''
        item1: value1
        ---
        item2: value2
    '''))
    f4 = d1.join('d1_2.yml')
    f4.write(dedent('''
        item3: value3
    '''))
    d2 = tmpdir.mkdir('d2')
    d3_file = d2.mkdir('d3').join('d3_file.yml')
    d3_file.write(dedent('''
        item5: value5
    '''))

    d2_2 = d2.join('d2_2.yml')
    d2_2.write(dedent('''
        item1: value1
        include:
        - d3/d3_file.yml
    '''))

    d2_1 = d2.join('d2_1.yml')
    d2_1.write(dedent('''
        item1: value2
        k1: value1
    '''))

    config_factory = ConfigFactory(f1.strpath)
    config = config_factory.create(arg1='val1')
    assert config._dir == dirname(f1.strpath)
    assert config._file == f1.strpath

    expected_files = set([d2_1.strpath, d2_2.strpath, d3_file.strpath])
    assert config['d2_item']._files == expected_files


    assert config == {'a1': 'b1',
         'a2': 'some_other_value',
         'a3': 'b3',
         'arguments': {'arg1': 'val1'},
         'd1_items': [{'item1': 'value1'},
                      {'item2': 'value2'},
                      {'item3': 'value3'}],
         'd2_item': {'include': ['d3/d3_file.yml'],
                     'item1': 'value1',
                     'item5': 'value5',
                     'k1': 'value1',
                     'k2': 'v2'},
         'include': ['f2.yml',
                     {'append': 'd1_items', 'directory': 'd1'},
                     {'directory': 'd2', 'update': 'd2_item'}]}


def test_config_factory_file(tmpdir):
    f1 = tmpdir.join('f1.yml')
    f1.write(dedent("""
        a1: b1
    """))

    config_factory = ConfigFactory(f1.strpath)
    cfg = config_factory.create()
    assert cfg['a1'] == 'b1'

    cfg = config_factory.create(x='y')
    assert cfg['arguments']['x'] == 'y'
    assert cfg.get('arguments.x') == 'y'
    assert 'arguments.x' in cfg

