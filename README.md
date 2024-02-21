# Crowdstrike Querying Detections

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
3. Replace the `CONFIGFILE` variable in the script with the path to your CrowdStrike API credentials file.
4. Replace the `file_name` variable in the main function with the path where you want the Excel file to be saved.
5. Run the script.
```python
python crwd_get_detections
```
## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Like this project? Give it a ⭐!
