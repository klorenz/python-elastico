from elastico.formatter import ElasticoFormatter

def test_elastico_formatter():
    f = ElasticoFormatter()
    assert f.format("test: {foo}", foo='hello') == "test: hello"
    assert f.format("{foo:.2gb}GB", foo=10000000000) == "10.00GB"
    assert f.format("{foo:gb}GB", foo=10000000000) == "10.000000GB"

    assert f.format("{foo:.2mb}MB", foo=12345123) == "12.35MB"
    assert f.format("{foo:mb}MB", foo=10000000) == "10.000000MB"
