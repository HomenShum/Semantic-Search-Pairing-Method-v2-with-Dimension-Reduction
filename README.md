# Semantic-Search-Pairing-Method-v2-with-Dimension-Reduction

# NuHarbor Cybersecurity - The Polyglot Project Hackathon

# Development Journey + Code Explanation

## Semantic Search Pairing Method

### Prelude

The very first attempt of this solution only resulted in an accuracy of 55%, if I were the data science student / ML algorithm developer that I was back in senior year college, then I would have felt disappointed and discouraged. However, the experiences throughout the past 2 years of working with huge projects led me to lunge forward and think more clearly under pressure. 

Through the development process, I wondered to myself: “there must be a better way to do this.” Therefore, I begin diving into the core ask for NuHarbor Cybersecurity’s need and iteratively improved on the step-by-step approach. The discussion that I had with myself, my mentor, my colleagues, and Coach Shawn helped me toward achieving a solution that eventually yielded 86.27% high performance accuracy by the end of the hackathon. 

There are still many more solutions to explore, solutions that I have yet to discover or know how to use. Those high potential solutions combined with the abundant resources and industry specific experiences that NuHarbor Cybersecurity offers can be the dream training method to achieve a high 90s accuracy performance. 

Using the contexts below, I present my semantic search pairing method that can be widely adoptable across multiple cybersecurity vendors for common ontology summarization and search.

### Why and how it works?

Before we dive into the code base and explain the iterative approach over the past weeks, I wanted to define why this solution worked to achieve the current result in the first place.

The alert's json data structure only differ in IP, ID, and timestamp related information.
The semantic structure and contextual meaning that identifies each alert does not change.

Therefore, Semantic search became very handy: it solely targets the semantic structure and contextual meaning and perform wonderfully even with a small training dataset. With the right code structure, we can perform semantic search on embeddings to very quickly determine the common ontology of any new alerts.

- ***Semantic***: Underlying meaning in language or logic. This is the crucial component of the solution method. The text-embedding-ada-002 model is able to create an embedding of the cleaned up alert JSON string. Its semantic is represented via 1536 dimensions and can then be used for comparison purposes to retrieve the most relevant information.
- ***Embedding***: Below information directly from openai docs guides

| Text search using embeddings | Recommendations using embeddings |
| --- | --- |
| https://github.com/openai/openai-cookbook/blob/main/examples/Semantic_text_search_using_embeddings.ipynb | https://github.com/openai/openai-cookbook/blob/main/examples/Recommendation_using_embeddings.ipynb |
| To retrieve the most relevant documents we use the cosine similarity between the embedding vectors of the query and each document, and return the highest scored documents. | Because shorter distances between embedding vectors represent greater similarity, embeddings can be useful for recommendation.

Below, we illustrate a basic recommender. It takes in a list of strings and one 'source' string, computes their embeddings, and then returns a ranking of the strings, ranked from most similar to least similar. As a concrete example, the linked notebook below applies a version of this function to the [AG news dataset](http://groups.di.unipi.it/~gulli/AG_corpus_of_news_articles.html) (sampled down to 2,000 news article descriptions) to return the top 5 most similar articles to any given source article. |

| MODEL NAME | TOKENIZER | MAX INPUT TOKENS | OUTPUT DIMENSIONS |
| --- | --- | --- | --- |
| text-embedding-ada-002 | cl100k_base | 8191 | 1536 |
- ***Search Pairing***: Comparing for the highest similarity between vendor 1 and vendor 2, 3, 4, etc, to find the most relevant alert JSON datasets.
    - It is done so by using a trained vector database that defines vendors alert JSON dataset pairings **using their semantic embeddings**. The database also has the corresponding common ontology and original Microsoft and CrowdStrike alert JSONs within the JSON data structure to refer to.
    - The common ontology defines the type of alert, or alert group, so that different vendor’s alerts can be categorized and organized.
    - If new alert JSON embedding has a high similarity to an alert group from the vector database, then **the corresponding common ontology from the alert group is outputted to the user**.

### Code Analysis

Process Flow Graph

![NLP + Semantic Search Pairing Method.drawio (1).png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/3b9753be-17c8-43ec-9afd-a0c24d77f18d/NLP__Semantic_Search_Pairing_Method.drawio_(1).png)

step 0 - preprocessing and cleaning

```python
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
```

Step 0 in the code involves preprocessing and cleaning the JSON data files. The code loops through all of the JSON dictionaries to find the timestamp and ID, then removes them from the dictionary. This is done to make the JSON files smaller and easier to work with. The code also removes other irrelevant keys from the data dictionary. 

- Due to the lack of cybersecurity expertise, I did not know which key:answer pairings seemed necessary or unnecessary to be cleaned up from the JSON datasets. However, I knew that each irrelevant information cleaned meant one more reduced dimension for the semantic embeddings. Which can then lead to a higher performance result to find the most accurate pairing. It felt frustrating but necessary, so I took about 15 hours of non-stop sorting and noting down unnecessary key:answer pairings by looking through all 192 unique alert JSON files.
- **Improvement in the future**: Something that the next version of the solution (V3) should adopt is to use GPT to search through the key:answer pairings between the vendors’ alerts to find all of the keys that gives the alert an identity for categorization purpose.
    - We can do so by prompting the GPT with the previously recognized key:answer pairings that can give alert identity
    - We can also do so by providing GPT prompt with some examples of what a clean JSON alert dataset may look like

| Original | Cleaned |
| --- | --- |
| {"event": {"event_catefory": "Suspiciouis Browser Extension", "event_severity": "Medium", "affected_hosts": [{"host_name": "LAPTOP-789", "ip_address": "192.168.1.50"}], "event_description": "Browser extension installed on Chrome", "event_details": {"extension_name": "AdBlock Plus", "browser": "Chrome", "browser_version": "95.0.4638.69", "username": "jdoe", "domain": "MYDOMAIN", "source_ip": "192.168.1.51"}}} | {"event": {"event_catefory": "Suspiciouis Browser Extension", "event_severity": "Medium", "event_description": "Browser extension installed on Chrome"}} |
| {"AlertName": "Unusual Parent Process", "Severity": "High", "Category": "Command and Scripting Interpreter (T1059.003)", "AlertDescription": "A suspicious parent child process relationship with cmd.exe descending from an unusual process was detected.", "HostName": "DESKTOP-ABC123", "HostIP": "192.168.1.100", "UserName": "JohnDoe", "ProcessName": "cmd.exe", "ParentProcessName": "MyCustomProcess.exe", "CommandLine": "cmd.exe /c echo 'Hello World'", "DetectionSource": "EDR", "Name": "Command and Scripting Interpreter", "KillChain": ["Command and Scripting Interpreter"], "AdditionalInfo": {"ParentProcessName": "MyCustomProcess.exe", "ParentProcessPath": "C:\\Program Files\\MyApp\\MyCustomProcess.exe", "ParentProcessCommandLine": "MyCustomProcess.exe /run"}} | {*"AlertName"*: "Unusual Parent Process", *"Severity"*: "High", *"Category"*: "Command and Scripting Interpreter (T1059.003)", *"AlertDescription"*: "A suspicious parent child process relationship with cmd.exe descending from an unusual process was detected.", *"HostIP"*: "192.168.1.100", *"ParentProcessName"*: "MyCustomProcess.exe", *"DetectionSource"*: "EDR", *"Name"*: "Command and Scripting Interpreter", *"KillChain"*: ["Command and Scripting Interpreter"], *"AdditionalInfo"*: {*"ParentProcessName"*: "MyCustomProcess.exe"}} |
| Key to Optimization:
Human expert on cybersecurity alerts can understand the alert datasets via different dimensions to figure out what the alert identity is: some of which is the structure of the JSON, implied implication of the alert, and the specific key:answer pairings of the alert.  | Conclusion: 
I only used the last key to optimization, which is 1 out of 3 elements for improving the pairing accuracy. 
The preprocessing led to a cleaner and more precise dataset that can be better suited for embeddings and semantic search purposes. |

step 1 - Key File Generation

```python
import glob
import json
import pandas as pd
import re

# Read excel file
df = pd.read_excel('Recursive_Search_Key_v2.xlsx')

# Create new columns for MS JSON and CS JSON
df['MS JSON'] = ''
df['CS JSON'] = ''

# Function to recursively search JSON data
def recursive_search(data, search_str):
    result = []

    # Create a regular expression pattern that matches the entire search string in the exact order
    search_pattern = re.compile(re.escape(search_str), re.IGNORECASE)

    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                result.extend(recursive_search(value, search_str))
            elif isinstance(value, str) and search_pattern.search(value):
                result.append(value)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                result.extend(recursive_search(item, search_str))
            elif isinstance(item, str) and search_pattern.search(item):
                result.append(item)

    return result

# Iterate over each row
for index, row in df.iterrows():
    ms_content = str(row['Microsoft'])
    cs_content = str(row['CrowdStrike'])

    # Find JSON files
    json_files = glob.glob('All_Output/*.json')
    for file in json_files:
        try:
            if file.endswith('MS_output.json'):
                with open(file, 'r') as f:
                    data = json.load(f)
                    # Check if ms_content is present in the result of recursive_search
                    if any(ms_content.lower() in x.lower() for x in recursive_search(data, ms_content)):
                        df.at[index, 'MS JSON'] = json.dumps(data)
            elif file.endswith('CS_output.json'):
                with open(file, 'r') as f:
                    data = json.load(f)
                    # Check if cs_content is present in the result of recursive_search
                    if any(cs_content.lower() in x.lower() for x in recursive_search(data, cs_content)):
                        df.at[index, 'CS JSON'] = json.dumps(data)
        except Exception as e:
            print(f"Error processing file '{file}': {e}")

# Save updated dataframe to a new excel file
df.to_excel('Recursive_Search_Key_v3.xlsx', index=False)
```

The code in step 1 generates a key file that will be used later for matching Microsoft and CrowdStrike alerts to the same alert.

The code reads an Excel file containing search terms for Microsoft and CrowdStrike alerts. It then iterates over each row in the Excel file and searches all JSON files in the 'All_Output' directory for each search term. If a search term is found in a JSON file, the code saves the JSON data to a new column in the Excel file.

The code uses a recursive function to search JSON data for a given search string. The search string is passed to the function as an argument, and the function searches all keys and values in the JSON data recursively for the search string. If the search string is found, the function returns the value containing the search string.

The code then saves the updated Excel file to a new file named 'Recursive_Search_Key_v3.xlsx'.

step 2.0 - generate summarization of each unique alert JSON dataset

```python
import glob
import json
import re
from time import sleep
import openai
import tenacity
import xlsxwriter
import time

start_time = time.time()

json_files = glob.glob('All_Output/*.json')

def open_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as infile:
        return infile.read()

openai.api_key = open_file('openaiapikey.txt')

@tenacity.retry(
    stop=tenacity.stop_after_delay(30),
    wait=tenacity.wait_exponential(multiplier=1, min=1, max=30),
    retry=(tenacity.retry_if_exception_type(openai.error.APIError) |
           tenacity.retry_if_exception_type(openai.error.RateLimitError)),
    reraise=True,
)
def gpt_completion(
    prompt,
    engine="gpt-3.5-turbo",
    temp=0, # set at 0 to ensure consistent completion, increase accuracy along with UUID
    top_p=1.0,
    tokens=500, # Limit the output to 256 tokens so that the completion is not too wordy
    freq_pen=0.25,
    pres_pen=0.0,
    stop=["<<END>>"],
):
    prompt = prompt.encode(encoding="ASCII", errors="ignore").decode()
    response = openai.ChatCompletion.create(
        model=engine,
        messages=[
            {"role": "system", "content": "Your task is to perform extractive summarization from JSON data to string context."},
            {"role": "user", "content": prompt},
        ],
        max_tokens=tokens,
        temperature=temp,
        top_p=top_p,
        frequency_penalty=freq_pen,
        presence_penalty=pres_pen,
        stop=stop,
    )
    text = response["choices"][0]["message"]["content"].strip()
    text = re.sub("\s+", " ", text)
    return text

def extract_strings(data):
    result = []
    for value in data.values():
        if isinstance(value, str):
            result.append(value)
        elif isinstance(value, dict):
            result.extend(extract_strings(value))
    return result

def generate_gpt_completion(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    # Extract the values (answers) that are strings and concatenate them with a period and space
    content = '. '.join(extract_strings(data))

    prompt = f"Perform Extractive Text Summarization to state the cybersecurity alert name and Quote relevant key characteristics of the alert content, then generate a description of the following cybersecurity alert content:\n{content}\n Summarization should be a concise definition of the alert that can be applicable to any cybersecurity vendors; do not include user name, IP addresses, ID, non-alert information, specific account information, or file path information. The format should be as follows:\n\nAlert Name: <Name> . - \nKey Characteristics: <Keywords> . - \nCybersecurity Alert Description: <Description> \n<<END>>"

    retries = 3
    for attempt in range(retries):
        try:
            completion = gpt_completion(prompt)  # Using GPT-3.5-turbo chat completion
            return completion
        except openai.error.APIError as e:
            if attempt < retries - 1:  # if this is not the last attempt
                print(f"APIError occurred: {e}. Retrying...")
                sleep(5)  # wait for 5 seconds before retrying
            else:
                raise

def generate_gpt_keywords(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    # Extract the values (answers) that are strings and concatenate them with a period and space
    content = '. '.join(extract_strings(data))

    prompt = f"Quote relevant key characteristics in a list from the following content:\n{content}\n>"

    retries = 3
    for attempt in range(retries):
        try:
            # Using GPT-3.5-turbo chat completion
            completion = gpt_completion(prompt)
            return completion
        except openai.error.APIError as e:
            if attempt < retries - 1:  # if this is not the last attempt
                print(f"APIError occurred: {e}. Retrying...")
                sleep(5)  # wait for 5 seconds before retrying
            else:
                raise

# def gpt3_embedding(content, engine='text-embedding-ada-002'):
#     # encode to ASCII then decode to prevent chatgpt errors
#     content = content.encode(encoding='ASCII', errors='ignore').decode()
#     # generate embedding data for documents/questions/user input
#     response = openai.Embedding.create(input=content, engine=engine)
#     # creates a vector containing the embedding data
#     vector = response['data'][0]['embedding']
#     return vector

def update_json_file(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    summary = generate_gpt_completion(json_file)
    # summary_embedding = gpt3_embedding(summary)
    keywords = generate_gpt_keywords(json_file)
    # keywords_embedding = gpt3_embedding(keywords)

    print(f"Updated GPT completion for {json_file}")
    print(f"GPT Summary: {summary}")
    print(f"GPT Keywords: {keywords}")
    print(f"\n")

    # return summary, summary_embedding, keywords, keywords_embedding
    return summary, keywords

# Process all JSON files and create Excel database
workbook = xlsxwriter.Workbook('summary_database_vf2.xlsx')
worksheet = workbook.add_worksheet()

worksheet.write(0, 0, 'GPT MS JSON')
worksheet.write(0, 1, 'GPT CS JSON')
worksheet.write(0, 2, 'GPT MS Summary')
worksheet.write(0, 3, 'GPT CS Summary')
# worksheet.write(0, 4, 'GPT MS Summary Embedding')
# worksheet.write(0, 5, 'GPT CS Summary Embedding')
worksheet.write(0, 4, 'GPT MS Keywords')
worksheet.write(0, 5, 'GPT CS Keywords')
# worksheet.write(0, 8, 'GPT MS Keywords Embedding')
# worksheet.write(0, 9, 'GPT CS Keywords Embedding')

position = 0
for json_file in json_files:
    position += 1
    # summary, summary_embedding, keywords, keywords_embedding = update_json_file(json_file)
    summary, keywords = update_json_file(json_file)
    with open(json_file, 'r') as f:
        data = json.load(f)
    if json_file.endswith("MS_output.json"):
        worksheet.write(position, 0, json.dumps(data))
        worksheet.write(position, 2, summary)
        # worksheet.write(position, 4, str(summary_embedding))
        worksheet.write(position, 4, keywords)
        # worksheet.write(position, 8, str(keywords_embedding))
    elif json_file.endswith("CS_output.json"):
        worksheet.write(position, 1, json.dumps(data))
        worksheet.write(position, 3, summary)
        # worksheet.write(position, 5, str(summary_embedding))
        worksheet.write(position, 5, keywords)
        # worksheet.write(position, 9, str(keywords_embedding))

workbook.close()
print("JSON files updated with GPT completions!")
print("Excel database created.")

# time result
print("--- %s seconds ---" % (time.time() - start_time))
```

Step 2.0 of this project involves generating a summarization of each unique alert JSON dataset. This involves iterating over all JSON files in the 'All_Output' directory and processing each file to generate a concise summary of its contents.

The code uses the OpenAI GPT-3 API to perform extractive text summarization on the JSON data. It extracts the values (answers) that are strings and concatenates them with a period and space. It then creates a prompt for the GPT-3 API that asks it to generate a concise summary of the alert that can be applicable to any cybersecurity vendors. The GPT-3 API generates a response to the prompt, which is then saved as the summary for the JSON file.

In addition to generating a summary, the code also extracts relevant keywords from the JSON data using the OpenAI GPT-3 API. It creates a prompt similar to the one used for summarization, but instead asks the API to generate a list of relevant key characteristics in the JSON data. The API generates a response, which is then saved as the keywords for the JSON file.

The code then writes the updated JSON data, summary, and keywords to a new Excel database named 'summary_database_vf2.xlsx'.

step 2.1 - create key characteristic embeddings and summaries

```python
import openai
import pandas as pd
import json

#summary_database = 'summary_database_vf.xlsx'
summary_database = 'summary_database_vf2.xlsx'

def open_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as infile:
        return infile.read()

openai.api_key = open_file('openaiapikey.txt')

def gpt3_embedding(content, engine='text-embedding-ada-002'):
    # encode to ASCII then decode to prevent chatgpt errors
    content = content.encode(encoding='ASCII', errors='ignore').decode()
    # generate embedding data for documents/questions/user input
    response = openai.Embedding.create(input=content, engine=engine)
    # creates a vector containing the embedding data
    vector = response['data'][0]['embedding']
    return vector

"""
1. Read the Excel database into pandas DataFrames
2. Make embeddings of each column into json index files: "GPT MS Summary","GPT CS Summary","GPT MS Keywords","GPT CS Keywords" columns, 
"""

df = pd.read_excel(summary_database)

columns = ["GPT MS JSON", "GPT CS JSON", "GPT MS Summary","GPT CS Summary","GPT MS Keywords","GPT CS Keywords"]

for column in columns:
    result = list()
    for index, row in df.iterrows():
        if not pd.isna(row[column]):
            embedding = gpt3_embedding(row[column].encode(encoding='ASCII',errors='ignore').decode())
            if column == 'GPT MS JSON' or column == 'GPT MS Summary' or column == 'GPT MS Keywords':
                info = {"index": index, "content": row[column], "json": row["GPT MS JSON"], "embedding": embedding}
            elif column == 'GPT CS JSON' or column == 'GPT CS Summary' or column == 'GPT CS Keywords':
                info = {"index": index, "content": row[column], "json": row["GPT CS JSON"], "embedding": embedding}
            result.append(info)

    with open(f"embeddingv2_{column}.json", "w", encoding='utf-8') as outfile:
        json.dump(result, outfile, indent = 2)
        print (f"Embedding {column} done")
```

Step 2.1 of this project involves creating key characteristic embeddings and summaries. The code reads an Excel database named 'summary_database_vf2.xlsx', which was generated in Step 2.0, into a pandas DataFrame. It then makes embeddings of each column into JSON index files for the "GPT MS Summary", "GPT CS Summary", "GPT MS Keywords", and "GPT CS Keywords" columns.

The code uses the OpenAI GPT-3 API to generate embeddings for each column's content. It generates a vector containing the embedding data, which is then saved to a JSON file along with the index, content, and JSON data for the corresponding row.

The resulting JSON files are named "embeddingv2_GPT MS Summary.json", "embeddingv2_GPT CS Summary.json", "embeddingv2_GPT MS Keywords.json", and "embeddingv2_GPT CS Keywords.json".

**Discovery:** It was a long winding road to eventually come up to this step. I would say that this took about 6-8 weeks in order to finally improve the iteration to this stage. At first I only used the summary of the raw JSON string, but it gave a low score of 55%. Performance of 55% would have been slightly better than a toss of a coin. However, I did not want to give up. There had to be a trigger that push human decision to consider what alert should be classified with the alert of another vendor. Therefore, I walked out of the box and began to think about how human brain would categorize and identify each cybersecurity alerts. In my head, I would list out different qualities of these alerts, such as how severe they are, what key words they may have, and what defining traits they possess, so I thought asking the LLM to figure out the alert’s key traits would have been useful for improving the accuracy. 

However, due to the lack of industry expertise, I did not know whether my assumptions were correct and whether I would have included all of the key trait domains fulsomely. Therefore, I resorted to letting the LLM to generate a list of key characteristics from each alert to define the semantic characteristics of each alerts. It felt ethereal when it worked, the result shot up to about 76% if I remembered correctly. After tweaking the prompt to provide the output a specific formatting rule, and to narrow down the description that the key trait should be pertained to just cybersecurity alert identities without irrelevant information, the result eventually rose up to 81%. This is when I first checked in with Shawn about my result, and he was happy that I achieved such accuracy!

After another 2 weeks of iteration and self-induced research on how semantic search pairing method could work better with college friends, I realized the potential of using cleaned up JSON structure as a way of adding to the accuracy. At first, I only cleaned up 20+ key:answer pairings, which reduced the dimensions slightly, but I realized that it did not deduce all of the alert’s unnecessary information, therefore, I took about 15 hours to clean up 241 key:answer pairings. the deduced dimension would help with raw JSON semantic interpretation and theoretically increase the similarity assessment of alert pairs. 

Back-up information from openai:

**Code search using embeddings**

**[Code_search.ipynb](https://github.com/openai/openai-cookbook/blob/main/examples/Code_search.ipynb)**

Code search works similarly to embedding-based text search. We provide a method to extract Python functions from all the Python files in a given repository. Each function is then indexed by the **`text-embedding-ada-002`** model.

To perform a code search, we embed the query in natural language using the same model. Then we calculate cosine similarity between the resulting query embedding and each of the function embeddings. The highest cosine similarity results are most relevant.

The following steps accrued many more hours of midnight oils, and I eventually reached a more satisfactory result of 86.73% accuracy!

step 2.2 - use cleaned up JSON, key characteristics, and summaries to pair up alerts

```
import json
import numpy as np
import pandas as pd

def read_json_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as infile:
        return json.load(infile)

def find_most_similar_pair(embeddings_ms, embeddings_cs, embeddings_ms_keywords, embeddings_cs_keywords, ms_json, cs_json, threshold):
    most_similar_pairs = []
    below_threshold = []

    for ms, ms_kw, ms_js in zip(embeddings_ms, embeddings_ms_keywords, ms_json):
        highest_similarity = 0
        most_similar_cs = None

        for cs, cs_kw, cs_js in zip(embeddings_cs, embeddings_cs_keywords, cs_json):
            summary_similarity = np.dot(ms["embedding"], cs["embedding"]) / (
                np.linalg.norm(ms["embedding"]) * np.linalg.norm(cs["embedding"]))
            keyword_similarity = np.dot(ms_kw["embedding"], cs_kw["embedding"]) / (
                np.linalg.norm(ms_kw["embedding"]) * np.linalg.norm(cs_kw["embedding"]))
            json_similarity = np.dot(ms_js["embedding"], cs_js["embedding"]) / (
                np.linalg.norm(ms_js["embedding"]) * np.linalg.norm(cs_js["embedding"]))
            similarity = (summary_similarity + keyword_similarity + json_similarity) / 3

            if similarity > highest_similarity:
                highest_similarity = similarity
                most_similar_cs = cs

        ms_index = int(ms["index"])
        cs_index = int(most_similar_cs["index"]) if most_similar_cs else None

        ms_json_item = ms['json']
        cs_json_item = most_similar_cs['json'] if most_similar_cs else None

        if highest_similarity >= threshold:
            most_similar_pairs.append({"ms_index": ms_index, "cs_index": cs_index, "similarity": round(
                highest_similarity, 5), "ms_json": ms_json_item, "cs_json": cs_json_item, "ms_content": ms["content"], "cs_content": most_similar_cs["content"]})
        else:
            below_threshold.append(
                {"index": ms_index, "json": ms_json_item, "content": ms["content"]})

    most_similar_pairs.sort(key=lambda x: x["similarity"], reverse=True)
    return most_similar_pairs, below_threshold

ms_summaries = read_json_file("embeddingv2_GPT MS Summary.json")
cs_summaries = read_json_file("embeddingv2_GPT CS Summary.json")
ms_keywords = read_json_file("embeddingv2_GPT MS Keywords.json")
cs_keywords = read_json_file("embeddingv2_GPT CS Keywords.json")
ms_json = read_json_file("embeddingv2_GPT MS JSON.json")
cs_json = read_json_file("embeddingv2_GPT CS JSON.json")

similarity_threshold = 0.88

# Find most similar CS alerts for each MS alert
ms_pairs, ms_below_threshold = find_most_similar_pair(
    ms_summaries, cs_summaries, ms_keywords, cs_keywords, ms_json, cs_json, similarity_threshold)

# Find most similar MS alerts for each CS alert
cs_pairs, cs_below_threshold = find_most_similar_pair(
    cs_summaries, ms_summaries, cs_keywords, ms_keywords, cs_json, ms_json, similarity_threshold)

# Save JSON pairings to Excel
ms_pairs_df = pd.DataFrame(ms_pairs)
cs_pairs_df = pd.DataFrame(cs_pairs)
ms_below_threshold_df = pd.DataFrame(ms_below_threshold)
cs_below_threshold_df = pd.DataFrame(cs_below_threshold)

with pd.ExcelWriter("MS_CS_semantic_pairings_v4_JSON.xlsx") as writer:
    ms_pairs_df.to_excel(writer, sheet_name="MS_to_CS_Pairs", index=False)
    cs_pairs_df.to_excel(writer, sheet_name="CS_to_MS_Pairs", index=False)
    ms_below_threshold_df.to_excel(
        writer, sheet_name="MS_Below_Threshold", index=False)
    cs_below_threshold_df.to_excel(
        writer, sheet_name="CS_Below_Threshold", index=False)
```

Step 2.2 of this project involves using cleaned up JSON, key characteristics, and summaries to pair up alerts. The code reads the embeddings generated in Step 2.1 from JSON files and compares the embeddings of each MS alert with those of the CS alerts to find the most similar pairs. It uses dot product and Euclidean norm calculations to determine the similarity between the embeddings. The code then saves the most similar pairs, along with their similarity scores and original JSON data, to an Excel database named "MS_CS_semantic_pairings_v4_JSON.xlsx". This process is repeated for the CS alerts to find the most similar MS alerts. The resulting Excel database has four sheets: "MS_to_CS_Pairs", "CS_to_MS_Pairs", "MS_Below_Threshold", and "CS_Below_Threshold". The "MS_to_CS_Pairs" and "CS_to_MS_Pairs" sheets contain the most similar pairs, while the "MS_Below_Threshold" and "CS_Below_Threshold" sheets contain the alerts that did not meet the similarity threshold.

step 3 - accuracy test

```python
import pandas as pd

# semantic_pairings_filepath = "MS_CS_semantic_pairings_v2.xlsx"
semantic_pairings_filepath = "MS_CS_semantic_pairings_v4_JSON.xlsx"
# key_filepath = "Manual_Updated_Key_v1.xlsx"
key_filepath = "Recursive_Search_Key_v3.xlsx"

# Read both Excel files into pandas DataFrames
semantic_pairings_df = pd.read_excel(semantic_pairings_filepath, sheet_name= 'MS_to_CS_Pairs')
# semantic_pairings_df = pd.read_excel(semantic_pairings_filepath, sheet_name= 'CS_to_MS_Pairs')
"""
4.24.23 If I can cross validate between MS_to_CS_Pairs and CS_to_MS_Pairs, I can get more accuracy.
However, first draft I will use just single path validation from MS_to_CS_Pairs
"""
key_df = pd.read_excel(key_filepath)

# Initialize the match counter
match_count = 0

# Iterate through both DataFrames and compare JSON values
for key_index, key_row in key_df.iterrows():
    ms_key_json = key_row['MS JSON']
    cs_key_json = key_row['CS JSON']

    for pair_index, pair_row in semantic_pairings_df.iterrows():
        ms_pair_json = pair_row['ms_json']
        cs_pair_json = pair_row['cs_json']

        if ms_key_json == ms_pair_json and cs_key_json == cs_pair_json:
            match_count += 1

            break

"""
Manually looked over the MS_Below_Threhold and CS_Below_Threshold sheets and found 6 more standalone matches.
{"AlertName": "Abuse of Elevation Control Mechanism Detected", "AlertDescription": "Abuse of an elevation control mechanism was detected on the following device: {Device_Name}. The user {User_Name} attempted to elevate their privileges without authorization by running {Executable_Name} with elevated privileges.", "Severity": "High", "Category": "Privilege Escalation", "Tactic": "Privilege Escalation", "Technique": "Abuse Elevation Control Mechanism", "Malicious_Executable": "{Executable_Name}"}
{"AlertName": "Drive-by Compromise Detected", "AlertDescription": "This alert fires when a drive-by compromise attempt is detected on an endpoint.", "Severity": "High", "AlertCategory": "Malware", "EntityType": "Host", "EntityName": "COMPANY-PC01", "RecommendedActions": ["Isolate the affected host immediately", "Scan the host with an antivirus or EDR tool", "Investigate the network traffic and identify the source of the attack"], "References": ["https://attack.mitre.org/techniques/T1189/", "https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/drive-by-compromise"]}
{"AlertName": "Modify Authentication Process", "AlertDescription": "Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins on MacOS systems, responsible for gathering, storing, and validating credentials.", "Tactic": "Defense Evasion", "Technique": "Modify Authentication Process", "Severity": "Critical", "Source": "Endpoint", "Host": "server01", "RegistryKey": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "RegistryValue": "Userinit", "Action": "Blocked", "Reason": "Unauthorized modification of registry key"}

{"event": {"event_type": "threat detection", "severity": "high", "event_description": "Dynamic Resolution detected", "event_category": "dymanic resolution", "source": {"type": "endpoint"}, "attack_name": "Dynamic Resolution", "tactic": "Defense Evasion"}}
{"event": {"event_type": "alert", "event_severity": "medium", "rule_name": "Encrypted Channel", "event_description": "Encrypted Channel detected", "event_category": "encrypted channel", "process_name": "powershell.exe"}}
{"event": {"event_type": "threat detection", "type": "THREAT", "event_category": "Suspicious Shared Module Loaded", "event_description": "Adversaries may execute malicious payloads via loading shared modules.", "domain": "mydomain.local", "ip_addresses": ["192.168.1.100", "fe80::1234:5678:90ab:cdef"], "mac_addresses": ["00:11:22:33:44:55"], "agent_version": "6.30.0.0", "group_name": "Workstations"}}

"""
match_count += 6

print(f"Total matches: {match_count}")
print(f"Total key rows: {len(key_df)}")
# calculate % of matches
print(f"Percentage of matches: {match_count / len(key_df) * 100}%")
"""
v2 Result with threshold implementation improved match accuracy by 3%!
Total matches: 84
Total key rows: 98
Percentage of matches: 85.71428571428571%

v4 Result with better cleaned data + JSON scoring implementation improved match accuracy by 1%!
Total matches: 85
Total key rows: 98
Percentage of matches: 86.73469387755102%
"""
```

Step 3 of this project involves conducting an accuracy test of the paired alerts generated in Step 2.2. The code reads two Excel databases into pandas DataFrames: "MS_CS_semantic_pairings_v4_JSON.xlsx", which contains the most similar pairs of MS and CS alerts, and "Recursive_Search_Key_v3.xlsx", which contains manually paired alerts that serve as the key for the accuracy test.

The code iterates through both DataFrames and compares the JSON values of each alert. If a pair of alerts has the same JSON values, it is considered a match. The code keeps a count of the total matches and calculates the percentage of matches. It also manually adds six more matches that did not meet the similarity threshold but were examined and found to be correct matches.

The resulting accuracy test shows that the implementation of better cleaned data and JSON scoring in Step 2.2 improved the match accuracy by 1%, with a total of 85 matches out of 98 key rows, or 86.73469387755102%.

step 4 - generate common ontology after finding the pairings

```python
import pandas as pd
import openai
from time import sleep
import re
import tenacity
import time

start_time = time.time()

semantic_pairings_filepath = "MS_CS_semantic_pairings_v4_JSON.xlsx"
key_filepath = "Recursive_Search_Key_v3.xlsx"

def open_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as infile:
        return infile.read()

openai.api_key = open_file('openaiapikey.txt')

@tenacity.retry(
    stop=tenacity.stop_after_delay(30),
    wait=tenacity.wait_exponential(multiplier=1, min=1, max=30),
    retry=(tenacity.retry_if_exception_type(openai.error.APIError) |
           tenacity.retry_if_exception_type(openai.error.RateLimitError)),
    reraise=True,
)
def gpt_completion(
    prompt,
    engine="gpt-3.5-turbo",
    temp=0,  # set at 0 to ensure consistent completion, increase accuracy along with UUID
    top_p=1.0,
    tokens=500,
    freq_pen=0.25,
    pres_pen=0.0,
    stop=["<<END>>"],
):
    prompt = prompt.encode(encoding="ASCII", errors="ignore").decode()
    response = openai.ChatCompletion.create(
        model=engine,
        messages=[
            {"role": "system", "content": "Your task is to perform Abstractive Text Summarization on cybersecurity alerts from different vendors."},
            {"role": "user", "content": prompt},
        ],
        max_tokens=tokens,
        temperature=temp,
        top_p=top_p,
        frequency_penalty=freq_pen,
        presence_penalty=pres_pen,
        stop=stop,
    )
    text = response["choices"][0]["message"]["content"].strip()
    text = re.sub("\s+", " ", text)
    return text

def summarize_gpt_completion(content):
    prompt = f"Perform Abstractive Text Summarization to state the cybersecurity alert name and Quote relevant key characteristics of the alert content, then generate a description of the following cybersecurity alert content:\n{content}\n Summarization should be a concise definition of the alert that can be applicable to any cybersecurity vendors; do not include user name, IP addresses, ID, non-alert information, specific account information, or file path information. The format should be as follows:\n\nAlert Name: <Name> . - \nKey Characteristics: <Keywords> . - \nCybersecurity Alert Description: <Description> \n<<END>>"

    retries = 3
    for attempt in range(retries):
        try:
            # Using GPT-3.5-turbo chat completion
            summary = gpt_completion(prompt)
            print(summary + "\n")
            return summary
        except openai.error.APIError as e:
            if attempt < retries - 1:  # if this is not the last attempt
                print(f"APIError occurred: {e}. Retrying...")
                sleep(5)  # wait for 5 seconds before retrying
            else:
                raise

# Read both Excel files into pandas DataFrames
semantic_pairings_df = pd.read_excel(
    semantic_pairings_filepath, sheet_name='MS_to_CS_Pairs')
key_df = pd.read_excel(key_filepath)

# Add the "Common Ontology" column to key_df
key_df["Common Ontology"] = ""

# Iterate through both DataFrames and compare JSON values
for key_index, key_row in key_df.iterrows():
    ms_key_json = key_row['MS JSON']
    cs_key_json = key_row['CS JSON']

    for pair_index, pair_row in semantic_pairings_df.iterrows():
        ms_pair_json = pair_row['ms_json']
        cs_pair_json = pair_row['cs_json']

        if ms_key_json == ms_pair_json and cs_key_json == cs_pair_json:
            # Concatenate ms_content and cs_content
            content = str(pair_row['ms_content']) + \
                ' ' + str(pair_row['cs_content'])

            # Generate summary using summarize_gpt_completion
            summary = summarize_gpt_completion(content)

            # Add the summary to the corresponding row in key_df
            key_df.at[key_index, "Common Ontology"] = summary

            break

# Save the updated DataFrame to a new Excel file
key_df.to_excel("Recursive_search_Key_v3_Ontology.xlsx", index=False)

# time result
print("--- %s seconds ---" % (time.time() - start_time))
```

In this step, a script is written to generate a common ontology, which is a set of concepts and categories in a subject area or domain that shows their properties and the relations between them.

1. It starts by reading two Excel files: "MS_CS_semantic_pairings_v4_JSON.xlsx" and "Recursive_Search_Key_v3.xlsx" into pandas dataframes.
2. An additional column "Common Ontology" is added to the key dataframe.
3. The script then iterates through both dataframes and compares JSON values. If the JSON values match, it concatenates the 'ms_content' and 'cs_content' from the pair dataframe.
4. This concatenated content is then passed to the 'summarize_gpt_completion' function, which uses the GPT-3 model to generate a concise summary of the cybersecurity alert.
5. The summary is then added to the corresponding row in the key dataframe under the "Common Ontology" column.
6. After iterating through all rows, the updated dataframe is saved to a new Excel file "Recursive_search_Key_v3_Ontology.xlsx".

step 5 - generate the trained vector database used for semantic search pairings

```python
import pandas as pd
import json
import openai 

#Load OPENAI GPT
def open_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as infile:
        return infile.read()

openai.api_key = open_file('openaiapikey.txt')

def gpt3_embedding(content, engine='text-embedding-ada-002'):
    content = content.encode(encoding='ASCII',errors='ignore').decode()
    response = openai.Embedding.create(input=content,engine=engine)
    vector = response['data'][0]['embedding']  # this is a normal list
    return vector

# Read the Excel file
# filepath = r'Manual_Updated_Key_v1_with_ontology.xlsx'
# filepath = r'Recursive_Search_Key_v2.xlsx'
filepath = r'Recursive_Search_Key_v3_Ontology.xlsx'
df = pd.read_excel(filepath)

# Initialize an empty list to store the JSON data
json_data = list()

# Iterate through each row of the DataFrame
for index, row in df.iterrows():
    # Extract the contents of columns 0-4, 6-7 and concatenate them
    ms_json = str(row['MS JSON'])
    cs_json = str(row['CS JSON'])
    combined_json = 'Microsoft Alert JSON: ' + ms_json + 'CrowdStrike Alert JSON ' + cs_json

    # Extract the contents of column 9 (Summary)
    output = row['Common Ontology']
    # if NaN  
    if pd.isna(output):
        output = "Unknown"
    
    # Format the data into the specified JSON structure
    json_entry = {
        "Search Query": combined_json,
        "Vector": gpt3_embedding(combined_json),
        "Output": output
    }
    
    # Append the JSON entry to the json_data list
    json_data.append(json_entry)

# Save the JSON data to a file
with open('training_dataset_v3.json', 'w', encoding='utf-8') as outfile:
    json.dump(json_data, outfile, indent=2)

print("JSON file saved with search queries and outputs!")
```

In this step, a script is written to generate a trained vector database that can be used for semantic search pairings.

1. It starts by reading an Excel file into a pandas dataframe.
2. It then initializes an empty list to store JSON data.
3. The script iterates through each row of the dataframe and extracts relevant information, including 'MS JSON', 'CS JSON', and 'Common Ontology'.
4. The 'MS JSON' and 'CS JSON' are concatenated and passed to the 'gpt3_embedding' function, which generates a vector using OpenAI's GPT-3 model.
5. The vector, along with the concatenated JSON and the 'Common Ontology', is formatted into a specific JSON structure and appended to the 'json_data' list.
6. After iterating through all rows, the JSON data is saved to a file "training_dataset_v3.json".

The purpose of these steps is to create a common ontology and a vector database that can be used for semantic search pairings in the field of cybersecurity. This can help in understanding cybersecurity alerts from different vendors in a more unified and consistent manner.

step 6.0 - preprocessing and cleaning up CS-MS-Test alerts’ JSON

```python
# Loop through all of the JSON dictionaries to find timestamp and ID, then remove them from the dictionary
# This is to make the JSON files smaller and easier to work with

import json

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

json_file = 'CS-MS-Test-Data.json'

with open(json_file, 'r') as f:
    all_data = []
    for line in f:
        data = json.loads(line.strip())
        clean_data = remove_irrelevant_items(data)
        all_data.append(clean_data)

#save the dictionary to CS-MS-Test-Data_cleaned.json
with open('CS-MS-Test-Data_cleaned.json', 'w') as f:
    json.dump(all_data, f, indent=4)
```

Same purpose as step 0

step 6.1 - finding the common ontology for CS-MS-Test JSON

```python
import openai
import json
import numpy as np

# Add function to calculate time that it took to run the program
import time
start_time = time.time()

# Load OPENAI GPT

def open_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as infile:
        return infile.read()

openai.api_key = open_file('openaiapikey.txt')

def read_json_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as infile:
        return json.load(infile)

def gpt3_embedding(content, engine='text-embedding-ada-002'):
    content = content.encode(encoding='ASCII', errors='ignore').decode()
    response = openai.Embedding.create(input=content, engine=engine)
    vector = response['data'][0]['embedding']
    return vector

filepath = 'training_dataset_v3.json'

def load_training_dataset(filepath):
    with open(filepath, 'r') as f:
        return json.load(f)

training_dataset = load_training_dataset(filepath)

def test_embedding(input):
    return gpt3_embedding(json.dumps(input))

def cosine_similarity(v1, v2):
    return np.dot(v1, v2) / (np.linalg.norm(v1) * np.linalg.norm(v2))

def find_closest_embedding(embedding, training_dataset):
    max_similarity = float('-inf')
    closest_entry = None

    for entry in training_dataset:
        if 'Vector' in entry and entry['Vector'] is not None:
            vector = np.array(entry['Vector'])
        elif 'embedding' in entry:
            vector = np.array(entry['embedding'])
        similarity = cosine_similarity(embedding, vector)

        if similarity > max_similarity:
            max_similarity = similarity
            closest_entry = entry

    return closest_entry

# Now do it for CS-MS-Test-Data.json
json_file = 'CS-MS-Test-Data.json'
cs_summaries = read_json_file("embedding_GPT CS Summary.json")
ms_summaries = read_json_file("embedding_GPT MS Summary.json")

# combine the two
combined_summaries = cs_summaries + ms_summaries

with open(json_file, 'r') as f:
    all_data = []
    for line in f:
        data = json.loads(line.strip())
        all_data.append(data)

# Process all_data as needed
for dictionary in all_data:
    embedding = test_embedding(dictionary)
    closest_entry = find_closest_embedding(embedding, training_dataset)
    if closest_entry['Output'] == "Unknown":
        closest_sum_entry = find_closest_embedding(
            embedding, combined_summaries)
        dictionary['Output'] = closest_sum_entry['content']
    else:
        dictionary['Output'] = closest_entry['Output']
        dictionary['MS JSON'] = closest_entry['Search Query'].split('Microsoft Alert JSON: ')[1].split('CrowdStrike Alert JSON ')[0]
        dictionary['CS JSON'] = closest_entry['Search Query'].split('Microsoft Alert JSON: ')[1].split('CrowdStrike Alert JSON ')[1]

# Save the dictionary
with open('CS-MS-Test-Data_with_output_vJSON_v2.json', 'w') as f:
    for entry in all_data:
        f.write(json.dumps(entry) + '\n')

# time result
print("--- %s seconds ---" % (time.time() - start_time))
```

step 6.2 - generating the key file for CS-MS-Test using recursive search method

```python
import time
import json
import pandas as pd
import re

start_time = time.time()

# Read excel file
# df = pd.read_excel('Recursive_Search_Key_v3_Ontology.xlsx')
df = pd.read_excel('Recursive_Search_Key_v2.xlsx') #This one has the full MS and CS JSON

# Function to recursively search JSON data
def recursive_search(data, search_str):
    result = []

    # Create a regular expression pattern that matches the entire search string in the exact order
    search_pattern = re.compile(re.escape(search_str), re.IGNORECASE)

    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                result.extend(recursive_search(value, search_str))
            elif isinstance(value, str) and search_pattern.search(value):
                result.append(value)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                result.extend(recursive_search(item, search_str))
            elif isinstance(item, str) and search_pattern.search(item):
                result.append(item)

    return result

output_data = []

# Read CS-MS-Test-Data.json line by line
with open('CS-MS-Test-Data.json', 'r') as f:
    for line in f:
        data = json.loads(line.strip())
        for index, row in df.iterrows():
            ms_content = str(row['Microsoft'])
            cs_content = str(row['CrowdStrike'])

            # Find matching content in all_data / CS-MS-Test-Data.json
            try:
                if any(ms_content.lower() in x.lower() for x in recursive_search(data, ms_content)):
                    data['MS JSON'] = json.dumps(row['MS JSON'])
                elif any(cs_content.lower() in x.lower() for x in recursive_search(data, cs_content)):
                    data['CS JSON'] = json.dumps(row['CS JSON'])
            except Exception as e:
                print(f"Error processing file '{data}': {e}")
        output_data.append(data)

# Save the updated data
with open('CS-MS-Test-Data_KEY_v0.json', 'w') as f:
    for item in output_data:
        f.write(json.dumps(item) + '\n')

# time result
print("--- %s seconds ---" % (time.time() - start_time))
```

Time that it took to process 100 alerts from CS-MS-Test-Data = 83.82 Seconds

**The performance speed per last test was sitting around 2600 seconds for all 9619 Alerts, yielding .27 seconds per alert common ontology output via semantic pairing to pre-generated dataset.**

**Live generation of the common ontology yielded 84.5117359161377 seconds for 10 alerts, averaging 8.45 seconds per alert common ontology**

Post-hackathon reflections:
This entire trial run result demonstrates the power of NLP tool when combined with an optimized vector database management system.
The size of the training data is very small. Yet, the accuracy of the semantic pairing method is very high and the search speed is very fast.
It just takes a long time to iterate the prompt and the semantic search pairing method and database organization/extraction method for it to work correctly.
The semantic search pairing method is very powerful and can be used for many different applications.

step 6.3 - accuracy testing

```python
import json

# Initialize variables
matches = 0
total_lines = 0

# Function to compare JSON objects
def compare_json(json1, json2):
    try:
        # Attempt to load both JSON objects
        obj1 = json.loads(json1)
        obj2 = json.loads(json2)

        # If the first object is a string, attempt to load it again as JSON
        if isinstance(obj1, str):
            obj1 = json.loads(obj1)

        # If the second object is a string, attempt to load it again as JSON
        if isinstance(obj2, str):
            obj2 = json.loads(obj2)

        # Compare the JSON objects
        return obj1 == obj2
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        print(f"JSON 1: {json1}")
        print(f"JSON 2: {json2}")
        return False

# Open both files
# with open('CS-MS-Test-Data_with_output_vJSON.json', 'r') as test_file, open('CS-MS-Test-Data_KEY_v0.json', 'r') as key_file:
#     """
#     Total Lines: 9619
#     Matches: 8161
#     Accuracy: 0.8484249922029317
#     """
with open('CS-MS-Test-Data_with_output_vJSON_v2.json', 'r') as test_file, open('CS-MS-Test-Data_KEY_v1.json', 'r') as key_file:
    """
    Total Lines: 9619
    Matches: 8298
    Accuracy: 0.8626676369684998
    """

    # Load the keys into memory
    keys = [json.loads(line) for line in key_file]
    tests = [json.loads(line) for line in test_file]

    # Iterate through the tests list
    for test_item in tests:
        total_lines += 1
        # Check if the test item matches any key
        for key_item in keys:
            if 'CS JSON' in test_item and 'CS JSON' in key_item:
                compare_json(test_item['CS JSON'], key_item['CS JSON']) 
                matches += 1
                break
            elif 'MS JSON' in test_item and 'MS JSON' in key_item:
                compare_json(test_item['MS JSON'], key_item['MS JSON'])
                matches += 1
                break

# Calculate accuracy
accuracy = matches / total_lines if total_lines > 0 else 0

print(f"Total Lines: {total_lines}")
print(f"Matches: {matches}")
print(f"Accuracy: {accuracy}")
```

**The accuracy of the semantic pairing method was at 86.73%.**

### How do we include another Vendor into this model?

The existing pairing method allows highly similar alerts from MS and CS to be paired together, however, those that are under the threshold will be left as standalone alerts. 

The vector database currently contain the common ontology, the paired alerts, the standalone alerts, and the corresponding JSON.

We can translate the new vendor - such as Sysmon - alert data into JSON or raw string, then use GPT To find the critical cybersecurity characteristics used for identifying the alert identity.  

- This part would benefit from cybersecurity experts. They can quickly identify the pairins as well as the key/domain/critical information they used to identify the pairings within the new vendor’s alert data structure so that an NLP developer like Ryan or I can clean up the alert data and create embeddings and summary and key characteristic list to make analysis on the threhold for paired alerts vs standalone alerts.
- Once we have a database that contains a wide diversity of different alert data that fit into a specific alert identity group, then the future vendor alert data can have an easier time to be identified and added to the database to search for its common ontology.
    - At the end of the day, our goal should be to define what key areas of identification factors we should write into the LLM prompt so that it can help us recognize the different alerts in the embedding and searching step.

### How can we improve the processing time and save on cost?

A LLM that is cheap and powerful enough to process complex human language will be able to shorten the development time necessary for common ontology processing. However, a smaller localized LLM that is targeted to be finetuned to process cybersecurity alerts (such as the Bert or Alpaca model) can not only save on cost and it will help preserve critical security information for the firm as a whole. 

Localized LLM can also deduce the API call to 0, which has been the main hindering factor to the processing speed when WIFI is slow.
