# 1. Research YARA Rule Structure and Create Templates
#     - Task: Understand the structure of YARA rules, including required and common attributes.
#     - Output: Define a basic YARA rule template with placeholders for patterns, metadata, and conditions.


import requests
import os

# Function to fetch data from a URL or local file path
def fetch_data(input_value):
    if input_value.startswith("http" or "https"):  # Input is a URL
        response = requests.get(input_value)
        if response.status_code == 200:
            return response.text.splitlines()
        else:
            raise Exception(f"Failed to fetch data from URL: {input_value}")
    elif os.path.exists(input_value):  # Input is a file path
        with open(input_value, 'r') as file:
            return file.readlines()
    else:
        raise ValueError("Input must be a valid URL or existing file path")

# Function to extract hashes (MD5/SHA256) from data
def extract_hashes(data):
    hashes = []
    for line in data:
        if len(line.strip()) == 32 or len(line.strip()) == 64:  # MD5 or SHA256
            hashes.append(line.strip())
    return hashes

# Function to generate a YARA rule
def generate_yara_rule(rule_name, keywords, hashes):
    rule = f"""
rule {rule_name} {{
    meta:
        description = "Automatically generated YARA rule for phishing"
    strings:
        {''.join([f'$kw{i} = "{keyword}"\n' for i, keyword in enumerate(keywords)])}
    condition:
        any of them or any of {{ {', '.join([f'"{h}"' for h in hashes])} }}
}}
"""
    return rule

# User input for phishing data source
input_source = input("Enter a phishing feed URL or file path: ")
data = fetch_data(input_source)

# Extract relevant phishing keywords from the data
# Example of simplistic keyword extraction from URL paths
phishing_keywords = [line.split('/')[-1].split('.')[0] for line in data if line.startswith("http")]
print(f"Extracted keywords: {phishing_keywords[:5]}")  # Print first 5 keywords for verification

# Extract hashes (if any) from the data
hash_list = extract_hashes(data)
print(f"Extracted hashes: {hash_list[:5]}")  # Print first 5 hashes for verification

# Generate YARA rule
rule_name = input("Enter a name for your YARA rule: ")
yara_rule = generate_yara_rule(rule_name, phishing_keywords, hash_list)

# Display the generated YARA rule
print("\nGenerated YARA Rule:\n")
print(yara_rule)

# Optionally save the YARA rule to a file
save_option = input("Do you want to save this rule to a file? (yes/no): ").strip().lower()
if save_option == "yes":
    output_file = f"{rule_name}.yar"
    with open(output_file, 'w') as file:
        file.write(yara_rule)
    print(f"YARA rule saved to {output_file}")

# 2. Collect Data for Signature Generation
#     - Task: Decide on the types of data you’ll analyze (malware files, network signatures, behavioral patterns).
#     - Output: Collect a sample dataset to test the YARA rule generation process.




# 3. Develop a Script to Analyze Data and Identify Patterns
#     - Task: Write a Python script that:
#         - Loads each sample file.
#         - Extracts unique patterns (e.g., strings, hashes, binary patterns).
#         - Compiles these patterns into a list of signatures.
#     - Output: Code that processes files and returns a list of unique patterns.




# 4. Generate YARA Rules from Template and Extracted Data
#     - Task: Write code to:
#         - Load the YARA rule template.
#         - Replace placeholders in the template with extracted patterns (signatures).
#         - Output a YARA rule for each analyzed file.
#     - Output: A set of YARA rules generated from the template.




# 5. Test Generated Rules
#     - Task: Test each YARA rule to:
#         - Ensure it detects the file it was generated from.
#         - Adjust any patterns to reduce false positives or errors.
#     - Output: Refined YARA rules that detect the intended files.




# 6. (Optional) Build a User Interface for Rule Generation
#     - Task: If desired, create a simple console or graphical interface that allows users to:
#         - Select files to analyze.
#         - View or modify generated rules.
#     - Output: Basic interface for managing rule generation.




# 7. Initial YARA Rule Template
#     - Define a template to be populated in Step 4. Example:

#       rule RuleName
#       {
#           meta:
#               description = "Placeholder for rule description"
#               author = "Placeholder for author"
#               date = "Placeholder for date"
#           strings:
#               $string1 = "example_string"  // Patterns to be added here
#               $string2 = { E2 34 A1 C3 }   // Binary patterns here
#           condition:
#               all of them
#       }
