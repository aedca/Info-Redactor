import re
import json
import os

def redact_sensitive_data(file_path):
    try:
        if not os.path.isfile(file_path):
            print(f"Skipping non-file path: {file_path}")
            return

        # Read file content
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.readlines()

        redacted_content = []

        for line in content:
            # Skip redaction for lines labeled "timestamp_ms"
            if '"timestamp_ms":' in line:
                redacted_content.append(line)
                continue

            # Redact sensitive information
            line = re.sub(r'(password(?: is)?\s*[:=]?\s*[^\s]+)', '[Redacted]', line, flags=re.IGNORECASE)
            line = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[Redacted]', line)

            phone_patterns = [
                r'\(\d{3}\) \d{3}-\d{4}',
                r'\(\d{3}\)-\d{3}-\d{4}',
                r'\d{3}-\d{3}-\d{4}',
                r'\d{3} \d{3} \d{4}',
                r'\d{10}'
            ]
            for pattern in phone_patterns:
                line = re.sub(pattern, '[Redacted]', line)

            line = re.sub(r'\d{3}-\d{2}-\d{4}', '[Redacted]', line)  # SSN pattern

            # Redact SSN-like patterns in free text
            line = re.sub(r'\b\d{3}\s?\d{2}\s?\d{4}\b', '[Redacted]', line)

            address_patterns = [
                r'\d{1,5}\s+\w+(\s+\w+)*,?\s+\w+(\s+\w+)*,?\s+(?:AL|AK|AS|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY)\s+\d{5}',
                r'(my address is\s*[:=]?\s*[\w\s,]+)',
            ]
            for pattern in address_patterns:
                line = re.sub(pattern, '[Redacted]', line, flags=re.IGNORECASE)

            redacted_content.append(line)

        # Write redacted content back to the file
        with open(file_path, 'w', encoding='utf-8') as file:
            file.writelines(redacted_content)

        print(f"Sensitive data redacted in file: {file_path}")

    except Exception as e:
        print(f"Error processing file {file_path}: {e}")

def process_files():
    print("Enter the path of a file or folder containing JSON, HTML, or TXT files:")
    path = input().strip()

    if not os.path.exists(path):
        print("Path does not exist. Please try again.")
        return

    if os.path.isfile(path):
        redact_sensitive_data(path)
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(('.json', '.html', '.txt')):
                    file_path = os.path.join(root, file)
                    redact_sensitive_data(file_path)
    else:
        print("Invalid path. Please provide a valid file or folder.")

if __name__ == "__main__":
    print("Welcome to the Sensitive Data Redactor!")
    process_files()
