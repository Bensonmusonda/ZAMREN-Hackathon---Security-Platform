import json
import os

def split_json_logs(input_file_path: str, output_directory: str = "network_test_files"):
    """
    Reads a single JSON file containing a list of log entries and saves each entry
    as a separate JSON file in a specified output directory.
    """
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)
        print(f"Created output directory: {output_directory}")

    try:
        with open(input_file_path, 'r', encoding='utf-8') as f:
            log_entries = json.load(f)
    except FileNotFoundError:
        print(f"Error: Input file '{input_file_path}' not found.")
        return
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from '{input_file_path}'. Please ensure it's valid JSON.")
        return

    if not isinstance(log_entries, list):
        print(f"Error: Expected a list of JSON objects in '{input_file_path}', but got a different type.")
        return

    print(f"Found {len(log_entries)} log entries to split.")

    for i, entry in enumerate(log_entries):
        if 'filename' in entry and 'content' in entry:
            output_filename = entry['filename']
            log_content = entry['content']
            
            output_file_path = os.path.join(output_directory, output_filename)
            
            try:
                with open(output_file_path, 'w', encoding='utf-8') as outfile:
                    json.dump(log_content, outfile, indent=4)
                print(f"Saved: {output_filename}")
            except Exception as e:
                print(f"Error saving {output_filename}: {e}")
        else:
            print(f"Warning: Entry {i+1} does not have 'filename' or 'content' key. Skipping.")

    print(f"\nAll specified log files have been saved to the '{output_directory}' directory.")

if __name__ == "__main__":
    input_json_file = "all_network_test_logs.json" 
    
    output_folder = "network_test_files" 

    split_json_logs(input_json_file, output_folder)