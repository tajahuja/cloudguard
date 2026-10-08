from streamlit.testing.v1 import AppTest
from cloudguard.config import ROOT


def test_dashboard_environments_filters_and_details():
    dashboard = AppTest.from_file(str(ROOT/'dashboard/app.py')).run(timeout=30)
    assert not dashboard.exception
    assert len(dashboard.metric) == 7
    assert dashboard.metric[0].value == '46/100'
    assert dashboard.metric[2].value == '20'
    dashboard.selectbox(key='finding').select_index(1).run(timeout=30)
    assert not dashboard.exception
    dashboard.multiselect(key='severity_filter').set_value(['CRITICAL']).run(timeout=30)
    assert not dashboard.exception
    dashboard.multiselect(key='severity_filter').set_value([]).run(timeout=30)
    assert not dashboard.exception
    assert any('No findings match' in item.value for item in dashboard.info)
    dashboard.selectbox(key='environment').select('secure').run(timeout=30)
    assert dashboard.metric[2].value == '0'
    assert not dashboard.exception
    dashboard.selectbox(key='environment').select('enterprise').run(timeout=30)
    assert dashboard.metric[1].value == '40'
    assert not dashboard.exception
