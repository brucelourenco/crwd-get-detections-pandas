# Crowdstrike Querying Detections - DEPRECATED 

*I'm working to make new scripts using the new /alerts set of endpoints since /detects was announced to be decommissioned in Apr/2025.*
#

This Python script uses the FalconPy SDK to interact with the CrowdStrike Falcon Platform's APIs and retrieve detection data. The data is then processed and exported to an Excel file for further analysis.

The main goal is to summarize the detections by host, maintaining only the last occurrence for that detection showing the sum of threats by host.

## Features

- Retrieves detection data from the Falcon Platform
- Filters and sorts detections based on specific criteria
- Adjusts detection timestamps to a specific timezone
- Populates a pandas DataFrame with the detection data
- Exports the DataFrame to an Excel file

## Requirements

- Python 3.10+
- FalconPy SDK
- pandas
- dateutil
- pytz

## Usage

1. Clone this repository.
2. Install the required Python packages using pip:<br/>
`conda 23.11.0`<br/>
`python 3.11.5`<br/>
`pandas 2.0.3`<br/>
`crowdstrike-falconpy 1.4.0`<br/>
1. Create a `CONFIGFILE` with the path to your CrowdStrike API credentials.
2. Now you can run your script from the command line like this: `python crwd_get_detections --config /path/to/config.ini --o /path/to/output.xlsx --start_date 2024-01-01 --end_date 2024-01-03`.
3. And you can get help on the command line arguments like this: `python crwd_get_detections -h`.
```python
python crwd_get_detections
```
## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Like this project? Give it a ⭐!
