# Crowdstrike querying detections

The main goal is to summarize the detections by hostname and quantity of detections from these hosts, maintaining only the last occurrence for that detection and show the sum for that file by host.

For this I'm using [FalconPy](https://github.com/CrowdStrike/falconpy), a Python library provided by [Crowdstrike](https://www.crowdstrike.com/) and Pandas.

## Requirements

`conda 23.11.0`
`Python 3.11.5`
`pandas 2.0.3`
`crowdstrike-falconpy 1.4.0`

I recommend using miniconda to prepare the environment once it has several libraries to use if need, but you can prepare the environment individualy (In this case is need install jupyter-notebook)





