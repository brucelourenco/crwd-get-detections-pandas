import argparse
import configparser

import pandas as pd
import pytz
from dateutil import parser
from falconpy import Detects

# Set pandas display options
pd.set_option("display.max_rows", None)
pd.set_option("display.max_columns", None)
pd.set_option("display.width", None)
pd.set_option("max_colwidth", 5000)

CONFIGFILE = "/YOUR/PATH_TO/KEY.ini"

# Mapping for ptd values to actions
PTD_ACTIONS = {
    0: "Detection Only",
    16: "Process Killed",
    128: "File Quarantined",
    272: "Detection Only",
    512: "Process Killed",
    768: "Detection Only",
    1024: "Operation Blocked",
    1280: "Detection Only",
    2048: "Process Blocked",
    2176: "File Quarantined",
    2304: "Detection Only",
    4096: "Registry Operation Blocked",
    4112: "Registry Operation Blocked",
    4638: "Detection Only",
    32768: "File system operation blocked",
    8208: "Process Killed - Parent process killed",
    2099200: "Process Blocked - Response action applied",
}


def get_credentials(configfile):
    cfg = configparser.ConfigParser()
    with open(configfile, "r") as f:
        cfg.read_file(f)
    return cfg.get("CLIENT_ID", "CLIENT_ID"), cfg.get("CLIENT_SECRET", "CLIENT_SECRET")


def get_falcon_instance(configfile):
    client_id, client_secret = get_credentials(configfile)
    return Detects(client_id=client_id, client_secret=client_secret)


def get_detection_ids(falcon, start_date, end_date):
    response = falcon.query_detects(
        limit=9999,
        filter=f"last_behavior:>='{start_date}'+last_behavior:<='{end_date}'+max_severity_displayname:!'Informational'",
        sort="last_behavior",
    )
    if response["status_code"] == 200:
        return response["body"]["resources"]
    else:
        print(response["body"]["errors"])
        return []


def get_detection_details(falcon, id_detections):
    indexes = [1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 9999]
    output = [
        id_detections[prev:index] for prev, index in zip([0] + indexes[:-1], indexes)
    ]
    full_list = []
    for ids in output:
        detects = falcon.get_detect_summaries(ids=ids, sort="last_behavior")
        full_list.extend(detects["body"]["resources"])
    return full_list


def adjust_datetime(detections):
    local_timezone = pytz.timezone("Brazil/East")
    for detection in detections:
        detect_last_behavior = parser.parse(detection["last_behavior"])
        local_datetime = detect_last_behavior.replace(tzinfo=pytz.utc)
        local_datetime = local_datetime.astimezone(local_timezone)
        detection["last_behavior"] = str(local_datetime)[:-6]
    return detections


def populate_dataframe(detections):
    df = pd.DataFrame(
        columns=[
            "SEVERITY",
            "HOSTNAME",
            "TYPE",
            "OS",
            "LAST_DETECTION",
            "USERNAME",
            "FILENAME",
            "CMD",
            "IOC",
            "ACTION",
            "DESCRIPTION",
        ]
    )
    for i, detection in enumerate(detections):
        behavior = detection["behaviors"][0]
        ptd = behavior["pattern_disposition"]
        action = PTD_ACTIONS.get(ptd, "Cant get action. Check the event")
        df.loc[i] = [
            detection["max_severity_displayname"],
            detection["device"]["hostname"],
            detection["device"]["product_type_desc"],
            detection["device"]["os_version"],
            detection["last_behavior"],
            behavior["user_name"],
            behavior["filename"],
            behavior["cmdline"],
            behavior["ioc_description"],
            action,
            behavior["description"],
        ]
    return df


def main():
    """
    Process the detections and generate an Excel file with the results.

    This function takes command line arguments, such as the path to the configuration file,
    the output file name, the start and end dates for the last_behavior filter. It then
    retrieves the detection details, adjusts the datetime, populates a dataframe, performs
    value counts, sorting, dropping duplicates, and merging. Finally, it saves the merged
    dataframe to an Excel file.

    Args:
        --configfile (str): Path to the configuration file.
        --file_name (str): Path to the output file.
        --start_date (str): Start date for the last_behavior filter.
        --end_date (str): End date for the last_behavior filter.

    Returns:
        None
    """
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('--config', required=True, help='Path to the configuration file')
    parser.add_argument('--o', required=True, help='Path to the output file')
    parser.add_argument('--start_date', required=True, help='Start date for the last_behavior filter')
    parser.add_argument('--end_date', required=True, help='End date for the last_behavior filter')

    args = parser.parse_args()

    falcon = get_falcon_instance(args.configfile)
    id_detections = get_detection_ids(falcon, args.start_date, args.end_date)
    detections = get_detection_details(falcon, id_detections)
    detections = adjust_datetime(detections)
    df = populate_dataframe(detections)
    df_count = df.value_counts(
        ["HOSTNAME", "FILENAME"], dropna=True, sort=True
    ).reset_index()
    df_count.columns = ["HOSTNAME", "FILENAME", "COUNT"]
    sorted_df = df.sort_values(by=["HOSTNAME", "LAST_DETECTION"], ascending=False)
    df_droped = sorted_df.drop_duplicates(subset=["HOSTNAME", "FILENAME"], keep="first")
    df_merged = pd.merge(df_droped, df_count, on=["HOSTNAME", "FILENAME"])
    df_merged.to_excel(args.file_name)


if __name__ == "__main__":
    main()
