from elastico.util import to_dt, dt_isoformat

def test_dt_isoformat():
    dt = to_dt('2018-01-01T01:01:01')
    assert dt_isoformat(dt, ' ', 'seconds')  == '2018-01-01 01:01:01'
    assert dt_isoformat(dt, ' ', 'minutes')  == '2018-01-01 01:01'
    assert dt_isoformat(dt, ' ', 'hours')  == '2018-01-01 01'
    
