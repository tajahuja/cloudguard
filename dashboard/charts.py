import altair as alt
import pandas as pd

def bars(frame: pd.DataFrame, label: str, value: str):
    chart=alt.Chart(frame).mark_bar(color='#52e0b5',cornerRadiusEnd=4).encode(
        y=alt.Y(f'{label}:N',sort='-x',title=None,axis=alt.Axis(labelLimit=260)),
        x=alt.X(f'{value}:Q',scale=alt.Scale(zero=True),axis=alt.Axis(format='d',tickMinStep=1)),
        tooltip=[label,alt.Tooltip(f'{value}:Q',format='d')])
    return (chart.properties(height=max(220,min(420,len(frame)*38)),
                             padding={'left':20,'right':20,'top':10,'bottom':15})
            .configure_axis(labelColor='#c9e4d5',titleColor='#c9e4d5',gridColor='#2a4035')
            .configure_view(strokeOpacity=0))
