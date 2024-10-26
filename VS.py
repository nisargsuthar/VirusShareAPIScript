import argparse
import time
from virusshare import VirusShare

# Create an instance of PyVirusShare
v = VirusShare('XXXX')  # Replace 'XXXX' with your VirusShare API key

def download_samples_from_file(file_path, destination_folder, max_retries=3, rate_limit_pause=60, request_interval=15):
    try:
        with open(file_path, 'r') as file:
            for line in file:
                hash_value = line.strip()
                if hash_value:
                    retries = 0
                    while retries < max_retries:
                        try:
                            result = v.download(hash_value, destination_folder)
                            print(f"Downloaded: {hash_value} to {destination_folder}")
                            time.sleep(request_interval)
                            break
                        except Exception as e:
                            if "rate limit" in str(e).lower():
                                print(f"Rate limit exceeded. Pausing for {rate_limit_pause} seconds.")
                                time.sleep(rate_limit_pause)
                            else:
                                print(f"Failed to download {hash_value}: {e}")
                                break
                            retries += 1
                            if retries == max_retries:
                                print(f"Failed to download {hash_value} after {max_retries} retries.")
    except Exception as e:
        print(f"Error reading file: {e}")

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Download malware samples from VirusShare by providing a hash file and destination folder.')
    parser.add_argument('hash_file', type=str, help='Path to the file containing the hashes.')
    parser.add_argument('destination_folder', type=str, help='Directory where the samples will be downloaded.')

    args = parser.parse_args()

    download_samples_from_file(args.hash_file, args.destination_folder)