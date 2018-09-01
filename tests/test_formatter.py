from elastico.formatter import ElasticoFormatter

def test_elastico_formatter():
    f = ElasticoFormatter()
    assert f.format("test: {foo}", foo='hello') == "test: hello"
    assert f.format("GB: {foo:.2gb}", foo=10000000000) == "GB: 10.00GB"
    assert f.format("GB: {foo:gb}", foo=10000000000) == "GB: 10.000000GB"

    assert f.format("MB: {foo:.2mb}", foo=12345123) == "MB: 12.35MB"
    assert f.format("MB: {foo:gb}", foo=10000000000) == "MB: 10.000000GB"
