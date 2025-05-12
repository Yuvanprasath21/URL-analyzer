import pandas as pd
from flask import Flask, render_template, request, jsonify
from bs4 import BeautifulSoup
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import ssl
import socket
import warnings
import dns.resolver
warnings.filterwarnings('ignore')
from urllib.parse import urlparse
import re
import requests
import whois
from datetime import datetime

app = Flask(__name__)

# Read the dataset
go = pd.read_csv(r'C:\Users\yuvan\OneDrive\Desktop\New\dataset.csv')

# Drop rows with missing target values
go = go.dropna(subset=['Result'])

# Select relevant features and target variable
X = go[['having_IPhaving_IP_Address', 'age_of_domain', 'double_slash_redirecting',
        'SFH', 'Redirect', 'Iframe', 'DNSRecord', 'Google_Index',
        'Links_pointing_to_page', 'Abnormal_URL']]
y = go['Result']

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Create a Random Forest Classifier
rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)

# Train the classifier
rf_classifier.fit(X_train, y_train)

# Get feature importances
feature_importances = rf_classifier.feature_importances_

# Map features to their importance scores
feature_importance_dict = dict(zip(X.columns, feature_importances))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_url():
    input_url = request.json.get('url')

    # Initialize score
    score = 0
    parsed_url = urlparse(input_url)

    # Extract relevant features
    ip_address = parsed_url.hostname
    ip_address = 1 if ip_address else -1
    score += 10 * feature_importance_dict.get('having_IPhaving_IP_Address', 0)

    try:
        # Other parts of your existing code...
        def get_domain_age(url, score):
            parsed_url = urlparse(url)
            domain = parsed_url.netloc

            try:
                domain_info = whois.whois(domain)
                if domain_info.creation_date:
                    creation_date = domain_info.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]

                    today = datetime.now()
                    age = today - creation_date
                    if age.days > 25:
                        age_of_domain = 1
                    else:
                        age_of_domain = -1
                    score += age_of_domain * feature_importance_dict['age_of_domain']
                    return age_of_domain, score
                else:
                    return -1, score
            except Exception as e:
                print(f"An error occurred: {e}")
                score -= 10
                return None, score

        # Check domain age for the new URL
        age_of_domain, score = get_domain_age(input_url, score)

        # Check for double slash redirecting
        if '//' in input_url:
            double_slash_redirecting = 1
        else:
            double_slash_redirecting = -1
        score += double_slash_redirecting * feature_importance_dict['double_slash_redirecting']

        # Check SFH vulnerability
        def check_sfh_vulnerability(url, score):
            try:
                response = requests.get(url)
                if "unintended_response" in response.text:
                    SFH = -1
                else:
                    SFH = 1
            except Exception as e:
                print(f"An error occurred: {e}")
                SFH = -1
            score += SFH * feature_importance_dict['SFH']
            return SFH, score

        # Check SFH for the new URL
        SFH, score = check_sfh_vulnerability(input_url, score)

        # Check redirects
        def find_redirects(url, score):
            try:
                response = requests.get(url, allow_redirects=False)
                if response.status_code in [301, 302]:
                    red = -1
                else:
                    red = 1
            except Exception as e:
                print(f"An error occurred: {e}")
                red = -1
            score += red * feature_importance_dict['Redirect']
            return red, score
        redirect, score = find_redirects(input_url, score)

        # Check iframes
        def find_iframes(url, score):
            response = requests.get(url)
            response.raise_for_status()

            soup = BeautifulSoup(response.content, 'html.parser')
            iframes = soup.find_all('iframe')

            iframe_info = []
            for iframe in iframes:
                info = {'src': iframe.get('src')}
                iframe_info.append(info)

            if iframe_info:
                iframe = -1
            else:
                iframe = 1
            score += iframe * feature_importance_dict['Iframe']
            print(iframe_info)
            return iframe, score

        iframe_presence, score = find_iframes(input_url, score)

        # Check DNS record
        def get_dns_record(url, record_type, score):
            x = None
            try:
                answers = dns.resolver.resolve(url, record_type)
                for rdata in answers:
                    x = rdata.to_text()
                if x:
                    dn = 1
                else:
                    dn = -1
            except Exception as e:
                print(f"An error occurred: {e}")
                dn = None

            if dn is not None:
                score += dn * feature_importance_dict.get('DNSRecord', 0)
            else:
                score += 10  # Default score if dn is None

            return dn, score

        record_type = "A"
        dns_record, score = get_dns_record(input_url, record_type, score)

        # Check Google index
        def check_google_index(url, score):
            response = requests.get(f"https://www.google.com/search?q=site:{url}")
            if response.status_code == 200 and url in response.text:
                gn = 1
            else:
                gn = -1
            score += gn * feature_importance_dict['Google_Index']
            return gn, score

        google_index, score = check_google_index(input_url, score)

        # Check links
        def check_links(url, score):
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            links = [link.get('href') for link in soup.find_all('a')]

            if links:
                lt = 1
            else:
                lt = -1
            score += lt * feature_importance_dict['Links_pointing_to_page']
            return lt, score

        links, score = check_links(input_url, score)

        # Check abnormal URL
        def is_abnormal_url(url, score):
            parsed_url = urlparse(url)
            if len(parsed_url.netloc) == 0 or len(parsed_url.scheme) == 0:
                Abnormal_URL = -1
                score = 0
            else:
                Abnormal_URL = 1
            score += Abnormal_URL * feature_importance_dict['Abnormal_URL']
            return Abnormal_URL, score

        # Add more checks based on your specific requirements
        ab_url, score = is_abnormal_url(input_url, score)

        new_data = pd.DataFrame({
            'having_IPhaving_IP_Address': [ip_address],
            'age_of_domain': [age_of_domain],
            'double_slash_redirecting': [double_slash_redirecting],
            'SFH': [SFH],
            'Redirect': [redirect],
            'Iframe': [iframe_presence],
            'DNSRecord': [dns_record],
            'Google_Index': [google_index],
            'Links_pointing_to_page': [links],
            'Abnormal_URL': [ab_url]
        })

        new_predictions = rf_classifier.predict(new_data)

        # Debugging: Print the new data and predictions
        print("Debug: New Data")
        print(new_data)
        print("Debug: Predictions for the new data:")
        print(new_predictions)

        # Return the result based on predictions
        result = {"result": "Fake" if new_predictions[0] == -1 else "Safe"}
        return jsonify(result)

    except Exception as e:
        print(f"An error occurred: {e}")
        # If an exception occurs, return the default result as "Harmful"
        return jsonify({"result": "Fake"})

if __name__ == '__main__':
    app.run(debug=True)
