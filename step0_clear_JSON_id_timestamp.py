# Loop through all of the JSON dictionaries to find timestamp and ID, then remove them from the dictionary
# This is to make the JSON files smaller and easier to work with

import json
import glob
import os


def remove_irrelevant_items(data):
    irrelevant_keys = ['AlertID', 'AlertTimestamp', 'Affected_Device', 'Affected_User', 'event_id', 'event_timestamp', 
                        'event_time', 'endpoint_id', 'host', 'Hostname', 'IP', 'OS', 'User', 'destination_port', 'destination_ip', 
                        "MachineId", "AlertId", "TimestampUtc", "creationTimeUtc", "eventTime", "id", "detect_id",
                        "detection_id", "device_id", "policy_id", "customer_id", "customer_name", "detection_time",
                        "ProcessID", "ParentProcessID", "AffectedEntities", "ExtendedProperties", "StartTime", "EndTime", 
                        "indicator_value", "DeviceName", "DeviceId", "OsPlatform", "affected_account_sid",
                        "OsVersion", "ProcessCreationTime", "ComputerName", "event_type_id", "event_source_id", "event_source", "product_version", 
                        "sensor_version", "user_name", "ioc", "src_ip", "os_version", "timestamp", "user_name", "parent_process_id",
                        "MD5Hash", "ParentProcessId", "image_digest", "host_info", "event_hash", "machine",
                        "AffectedFilePath", "HostName", "ContainerImageName","remote_ip", "target", "additionalData", "initiator", 
                        "RuleId", "ProcessParentStartTime", "ProcessStartTime", "operating_system", "DetectionID", "EventHash", 
                        "OperatingSystem", "ip", "timestamp", "rule_id", "AlertTimestampUtc", "src_port", "file_path", "ProcessParentName", "ProcessName",
                        "ContainerRuntime", "FilePath", "ip_address", "os", "EventId", "Hash", "SourceIp", "md5_hash", "sha256_hash", 
                        "SourcePort", "DestinationIp", "SHA256Hash", "ProcessPid", "ParentProcessPid", "event_url", "process_path", 
                        "source_process_pid", "DataTTL", "DetectionTime", "LastUpdateTime", "Start", "FileHash", "End", "metadata",
                        "CreationTime", "OSVersion", "OSPlatform", "control_name", "DestinationIp", "AlertLink", "MachineDomainName",
                        "SourceIp", "SourcePort", "resource_id", "file_sha256", "file_size", "parent_process_id", "URL", "threat",
                        "ProcessCommandLine", "event_Timestamp", "timestamp", "Affected_Hostname", "CommandLine", "process_command_line",
                        "AffectedHostname", "user_id", "machine_id", "local_port", "protocol", "Path", "SourceIP", "ParentProcessCommandLine",
                        "Affected_Hostname", "Timestamp", "affected_entities", "RemovableMediaAccessedTime", "event_details", "file_path", "file_info",
                        "RemovableMediaCapacity", "RemovableMediaSerialNumber", "AffectedFileSize", "ProcessPath", "ParentProcessPath", "destination",
                        "Domain_Controller_IP", "Alert_Source", "device_external_ip", "MACAddress",
                        "pid", "UserName", "ParentProcessCreationTime", "RemoteIP", "RemotePort", "RuleID",
                        "TargetDevice", "TargetDeviceId", "TargetOsPlatform", "TargetOsVersion", "TargetUserName",
                        "Endpoint_ID", "Endpoint_Name", "Endpoint_IP", "EndpointName", "EndpointIP",
                        "ProcessParentID", "sensor_id", "device_os_version", "device_os", "device_name", "event_version",
                        "user", "process_pid", "parent_process_pid", "MachineName", "Value",
                        "ArtifactPath", "EventTime", "timestamp_utc", 
                        "AlertTimestamps", "modified_time", "original_hash", "current_hash", "source_ip", "source_port",
                        "destination_ip", "destination_port", "file_hash", "process_hash", "parent_process_hash",
                        "container_id", "value_data", "registry_key", "sha1_hash",
                        "process_id", "computer_name", "endpoint", "AlertDetails",
                        "command_line", "local_address", "remote_address", "remote_port",
                        "local_networks", "remote_networks", "technique_id", 
                        "subtechnique_id", "logged_on_user", "Product", "product", "IOC",
                        "ProcessHash", "Process_ID",
                        "ParentProcessID", "SourceIPAddress", "DestinationIPAddress",
                        'IPAddress', 'DestinationIP', 'DestinationPort', 'process_id', 
                        'src', 'process_tree', 'ppid', 'username', 'start_time', 'EndpointID', 'value',
                        'process_sha256', 'parent_process_sha256', 'process_start_time', 'process_end_time', 'host_details', 
                        'SHA256', 'hostname', 'local_ip', 'public_ip', 'affected_hosts', 'ProcessId', 'alert_time', 
                        ]

    if isinstance(data, dict):
        for key in irrelevant_keys:
            if key in data:
                del data[key]
            elif 'event' in data and key in data['event']:
                del data['event'][key]

        for key, value in data.items():
            if isinstance(value, dict):
                data[key] = remove_irrelevant_items(value)
            elif isinstance(value, list):
                for i in range(len(value)):
                    if isinstance(value[i], dict):
                        value[i] = remove_irrelevant_items(value[i])

    return data


# Search for JSON files and process them
json_files = glob.glob('All/*.json')

# Loop through each JSON file
for file_path in json_files:
    with open(file_path, 'r') as json_file:
        data = json.load(json_file)

    # Remove irrelevant items
    data = remove_irrelevant_items(data)

    # specify output file path
    output_file_path = os.path.join('All_Output', os.path.splitext(os.path.basename(file_path))[0] + '_output.json')

    # create 'All_Output' directory if it does not exist
    if not os.path.exists('All_Output'):
        os.makedirs('All_Output')

    # write the updated JSON data to the output file
    with open(output_file_path, 'w') as json_file:
        json.dump(data, json_file)