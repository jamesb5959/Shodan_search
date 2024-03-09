import shodan
from ipwhois import IPWhois

api_key = ""
api = shodan.Shodan(api_key)
def search_ips_in_city(city_name, keyword):
    ips = [] 
    try:
        # Perform the search on Shodan
        query = f'city:"{city_name}" "{keyword}"'
        results = api.search(query)
        # Check if there are results
        if results['total'] > 0:
            print(f"Results found: {results['total']}")
            for result in results['matches']:
                ips.append(result['ip_str'])
                # Perform WHOIS lookup
                try:
                    obj = IPWhois(result['ip_str'])
                    whois_result = obj.lookup_whois()
                    city = None
                    for net in whois_result['nets']:
                        if 'city' in net:
                            city = net['city']
                            break
                    if city == 'Camp Pendleton':
                        print(f"WHOIS for {result['ip_str']}: City - {city}")
                except Exception as e:
                    print(f"WHOIS Error for {result['ip_str']}: {e}")
        else:
            print("No results found.")
    except shodan.APIError as e:
        print(f"Error: {e}")

def search_ips(name):
    ips = [] 
    try:
        # Perform the search on Shodan
        results = api.search(name)
        # Check if there are results
        if results['total'] > 0:
            print(f"Results found: {results['total']}")
            for result in results['matches']:
                ips.append(result['ip_str'])
                # Perform WHOIS lookup
                try:
                    obj = IPWhois(result['ip_str'])
                    whois_result = obj.lookup_whois()
                    city = None
                    for net in whois_result['nets']:
                        if 'city' in net:
                            city = net['city']
                            break
                    if city == 'Camp Pendleton':
                        print(f"WHOIS for {result['ip_str']}: City - {city}")
                except Exception as e:
                    print(f"WHOIS Error for {result['ip_str']}: {e}")
        else:
            print("No results found.")
    except shodan.APIError as e:
        print(f"Error: {e}")

# Example usage
search_ips_in_city("Camp Pendleton", "ATAK")
search_ips("Camp Pendleton ATAK")
search_ips_in_city("San Diego", "ATAK")
search_ips_in_city("Oceanside", "ATAK")
