import requests
import json

def check_cve(cve_id):
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    response = requests.get(nvd_url)
    if response.status_code == 200:
        cve_data = json.loads(response.text)
        return cve_data
    else:
        return None

def check_device_cves(device_name):
    cve_list = []
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={device_name}"
    response = requests.get(nvd_url)
    if response.status_code == 200:
        cve_data = json.loads(response.text)
        cve_list = cve_data["result"]["CVE_Items"]
    return cve_list

def check_ip_cves(ip_address):
    cve_list = []
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={ip_address}"
    response = requests.get(nvd_url)
    if response.status_code == 200:
        cve_data = json.loads(response.text)
        cve_list = cve_data["result"]["CVE_Items"]
    return cve_list

def main():
    while True:
        user_input = input("Enter '1' to check a specific CVE, '2' to check CVEs for a device, or '3' to check CVEs for an IP address (q to quit): ")
        if user_input == 'q':
            break
        elif user_input == '1':
            cve_id = input("Enter the CVE ID: ")
            cve_data = check_cve(cve_id)
            if cve_data:
                print("CVE Information:")
                print(cve_data)
            else:
                print(f"No information found for CVE ID {cve_id}")
        elif user_input == '2':
            device_name = input("Enter the device name: ")
            cve_list = check_device_cves(device_name)
            if cve_list:
                print("CVE Information:")
                for cve in cve_list:
                    print(cve["cve"]["CVE_data_meta"]["ID"])
            else:
                print(f"No information found for device {device_name}")
        elif user_input == '3':
            ip_address = input("Enter the IP address: ")
            cve_list = check_ip_cves(ip_address)
            if cve_list:
                print("CVE Information:")
                for cve in cve_list:
                    print(cve["cve"]["CVE_data_meta"]["ID"])
            else:
                print(f"No information found for IP address {ip_address}")
        else:
            print("Invalid input, please try again.")

if __name__ == '__main__':
    main()