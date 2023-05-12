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
