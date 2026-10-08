import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import pandas as pd
import streamlit as st
from cloudguard.config import ROOT
from cloudguard.engine import assess
from cloudguard.ingestion.loader import load_environment
from cloudguard.reporting.render import html_report, markdown_report
from dashboard.charts import bars

st.set_page_config(page_title='CloudGuard',page_icon='☁️',layout='wide')
st.markdown("""<style>
.block-container{max-width:1550px;padding-top:2.5rem}
[data-testid="stMetric"]{background:#11221c;border:1px solid #305041;border-top:3px solid #52e0b5;padding:14px;border-radius:8px}
[data-testid="stMetricValue"]{font-variant-numeric:tabular-nums;font-size:clamp(1.3rem,2.5vw,2.2rem);overflow:visible;white-space:normal}
[data-testid="stMetricLabel"] p{white-space:normal}
@media(max-width:850px){[data-testid="stHorizontalBlock"]{flex-wrap:wrap}
[data-testid="stHorizontalBlock"]>[data-testid="stColumn"]{min-width:min(100%,210px);flex:1 1 210px}}
</style>""",unsafe_allow_html=True)
st.title('CloudGuard')
st.caption('Cloud configuration → explainable risk → prioritized remediation • Synthetic local assessment')
with st.sidebar:
    st.header('Assessment workspace')
    selected=st.selectbox('Environment',['startup','secure','vulnerable','enterprise'],key='environment')
    st.caption('Read-only local files. No AWS connection is made.')
    st.link_button('LinkedIn','https://www.linkedin.com/in/tajahuja9/',use_container_width=True)
    st.link_button('GitHub profile','https://github.com/tajahuja',use_container_width=True)
try:
    environment=load_environment(ROOT/f'environments/environment_{selected}.json')
    assessment=assess(environment)
except (OSError,ValueError):
    st.error('Cannot load this environment. Run python -m cloudguard generate and verify the schema.')
    st.stop()
st.subheader(assessment.environment_name)
counts={level:sum(f.severity==level for f in assessment.findings) for level in ['CRITICAL','HIGH','MEDIUM','LOW']}
labels=['Cloud Security Score','Total Resources','Total Findings','Critical Findings','High Findings','Medium Findings','Low Findings']
values=[f'{assessment.security_score}/100',f'{assessment.resource_count:,}',f'{len(assessment.findings):,}',
        str(counts['CRITICAL']),str(counts['HIGH']),str(counts['MEDIUM']),str(counts['LOW'])]
for column,label,value in zip(st.columns(4),labels[:4],values[:4]):
    column.metric(label,value)
for column,label,value in zip(st.columns(3),labels[4:],values[4:]):
    column.metric(label,value)
st.write(assessment.summary)
with st.expander('How the educational score works'):
    st.write('Security score = 100 − ceiling(mean highest unresolved finding risk per resource). '
             'Resources without findings contribute zero. This inventory-normalized heuristic can dilute '
             'isolated critical risks: always review critical findings alongside the score. '
             'It is not a compliance rating or proof of security.')
all_findings=pd.DataFrame([f.model_dump(mode='json') for f in assessment.findings])
if assessment.findings:
    left,right=st.columns(2)
    with left:
        st.subheader('Findings by severity')
        data=pd.DataFrame({'Severity':list(counts),'Findings':list(counts.values())})
        st.altair_chart(bars(data,'Severity','Findings'),use_container_width=True)
        st.subheader('Risk by resource type (maximum finding risk)')
        data=all_findings.groupby('resource_type',as_index=False)['risk_score'].max()
        st.altair_chart(bars(data,'resource_type','risk_score'),use_container_width=True)
        st.subheader('Top security rules triggered')
        data=all_findings['rule_id'].value_counts().head(10).rename_axis('Rule').reset_index(name='Findings')
        st.altair_chart(bars(data,'Rule','Findings'),use_container_width=True)
    with right:
        st.subheader('Findings by category')
        data=all_findings['category'].value_counts().rename_axis('Category').reset_index(name='Findings')
        st.altair_chart(bars(data,'Category','Findings'),use_container_width=True)
        st.subheader('Highest-risk resources')
        data=pd.DataFrame({'Resource':list(assessment.resource_risks),'Risk':list(assessment.resource_risks.values())})
        st.altair_chart(bars(data.sort_values('Risk',ascending=False).head(10),'Resource','Risk'),use_container_width=True)
else:
    st.success('No implemented rule triggered on this supplied snapshot. This does not establish complete security.')
st.subheader('Prioritized remediation queue')
if assessment.findings:
    columns=st.columns(4)
    levels=columns[0].multiselect('Severity',list(counts),default=list(counts),key='severity_filter')
    kinds=columns[1].multiselect('Resource type',sorted(all_findings.resource_type.unique()),
                                 default=sorted(all_findings.resource_type.unique()))
    categories=columns[2].multiselect('Rule category',sorted(all_findings.category.unique()),
                                     default=sorted(all_findings.category.unique()))
    statuses=columns[3].multiselect('Status',['OPEN','ACCEPTED','RESOLVED'],default=['OPEN'])
    visible=[f for f in assessment.findings if f.severity in levels and f.resource_type in kinds
             and f.category in categories and f.status in statuses]
    if visible:
        st.dataframe(pd.DataFrame([f.model_dump(mode='json') for f in visible])[
            ['finding_id','severity','risk_score','resource_name','category','title','status']],
            hide_index=True,use_container_width=True)
        choices={f'{f.finding_id} • {f.title} • {f.resource_name}':f for f in visible}
        choice=st.selectbox('Inspect finding',list(choices),key='finding')
        finding=choices[choice]
        st.subheader(finding.title)
        st.write(f'**{finding.severity} · {finding.risk_score}/100 · {finding.resource_type}/{finding.resource_name}**')
        st.write(finding.description)
        tabs=st.tabs(['Evidence','Risk reasoning','Remediation'])
        with tabs[0]:
            st.json(finding.evidence)
            st.write('Security impact:',finding.security_impact)
            st.write('Hypothetical scenario:',finding.attack_scenario)
        with tabs[1]:
            for reason in finding.risk_reasons:
                st.write(reason)
            st.write('Framework concept:',', '.join(finding.framework_mapping))
            for reference in finding.references:
                st.link_button('Read authoritative guidance',reference)
        with tabs[2]:
            st.write(finding.remediation.urgency)
            for step in finding.remediation.steps:
                st.write('• '+step)
            st.write('Principle:',finding.remediation.principle)
            st.write('Recommended configuration:',finding.remediation.recommended_configuration)
            for step in finding.remediation.verification_steps:
                st.write('Verify: '+step)
    else:
        st.info('No findings match these filters. Clear a filter to expand the queue.')
left,right=st.columns(2)
left.download_button('Download HTML assessment',html_report(assessment),
                     file_name=f'cloudguard-{selected}.html',mime='text/html')
right.download_button('Download Markdown assessment',markdown_report(assessment),
                      file_name=f'cloudguard-{selected}.md',mime='text/markdown')
st.caption('Configuration findings are not confirmed incidents. Remediation is guidance only; no infrastructure is changed.')
