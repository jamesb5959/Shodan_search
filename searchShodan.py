import shodan
from ipwhois import IPWhois
import argparse

api_key = ""
api = shodan.Shodan(api_key)

def search_ips(city_name=None, keyword=None):
    ips = [] 
    query = ""
    if city_name and keyword:
        query = f'city:"{city_name}" "{keyword}"'
    elif city_name:
        query = f'city:"{city_name}"'
    elif keyword:
        query = f'"{keyword}"'
    else:
        print("No search parameters provided.")
        return
    try:
        # Perform the search on Shodan
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
                except Exception as e:
                    print(f"WHOIS Error for {result['ip_str']}: {e}")
        else:
            print("No results found.")
    except shodan.APIError as e:
        print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser(description='Search IP addresses in Shodan based on location and/or keyword.')
    parser.add_argument('-L', '--location', help='Location to search for', default=None)
    parser.add_argument('-K', '--keyword', help='Keyword to search for', default=None)
    args = parser.parse_args()
    search_ips(city_name=args.location, keyword=args.keyword)

if __name__ == '__main__':
    main()
