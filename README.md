# Crowdstrike querying detections

The main goal is to summarize the detections by host, maintaining only the last occurrence for that detection showing the sum of threats by host.

For this I'm using [FalconPy](https://github.com/CrowdStrike/falconpy), a Python library provided by [Crowdstrike](https://www.crowdstrike.com/) and Pandas.

## Requirements

`conda 23.11.0`<br/>
`Python 3.11.5`<br/>
`pandas 2.0.3`<br/>
`crowdstrike-falconpy 1.4.0`<br/>

I recommend using miniconda to prepare the environment once it has several libraries to use if need, but you can prepare the environment individualy (In this case is need install jupyter-notebook)





