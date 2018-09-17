from elastico.util import (to_dt, dt_isoformat, read_config_dir,
    get_config_value, format_value, start_of_day, end_of_day)
from textwrap import dedent

def test_dt_isoformat():
    dt = to_dt('2018-01-01T01:01:01Z')
    assert dt_isoformat(dt, ' ', 'seconds')  == '2018-01-01 01:01:01Z'
    assert dt_isoformat(dt, ' ', 'minutes')  == '2018-01-01 01:01Z'
    assert dt_isoformat(dt, ' ', 'hours')  == '2018-01-01 01Z'

def test_start_of_day():
    dt = to_dt('2018-01-01T01:01:01Z')
    start = start_of_day(dt)
    assert dt_isoformat(start, ' ', 'seconds') == '2018-01-01 00:00:00Z'

def test_end_of_day():
    dt = to_dt('2018-01-01T01:01:01Z')
    end = end_of_day(dt)
    assert dt_isoformat(end, ' ', 'seconds') == '2018-01-01 23:59:59Z'

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

    config = {}

    read_config_dir(tmpdir.strpath, config, 'docs', recursive=False)

    ####

    import pprint
    pprint.pprint(config)

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

    config = {}

    read_config_dir(tmpdir.strpath, config, 'docs', recursive=True)

    config['docs'].sort(key = lambda x: x['id'] )

    assert config['docs'][0]['a1'] == 'b1'
    assert config['docs'][2]['a3'] == 'b3'


def test_format_value():
    assert format_value({"a": "b"}, "{a}") == "b"
    assert format_value({"a": "b"}, {"x": "{a}"}) == {"x": "b"}
    assert format_value({"a": "b"}, ["{a}", "c"]) == ["b", "c"]

    #assert format_value({"c": "b"}, ["{a}", "c"]) -> exception


def test_get_config_value():
    assert get_config_value({'foo': {'bar': 2}}, 'foo.bar') == 2


