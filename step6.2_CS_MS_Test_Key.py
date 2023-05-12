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
