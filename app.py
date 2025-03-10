from flask import Flask, jsonify, render_template
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
import time
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
import requests

app = Flask(__name__)

GEMINI_API_KEY = "AIzaSyBSAA7ymihQV28HOXj_Wy6uJMLLyNSAzoo"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

def setup_driver():
    chrome_options = Options()
    chrome_options.add_argument("--ignore-certificate-errors")  # Ignores certificate errors
    chrome_options.add_argument("--headless")  # Run in headless mode
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--window-size=1920,1080")
    
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=chrome_options)
    return driver

def check_cve_exists(cve_id):
    """Check if CVE exists in multiple sources"""
    sources = [
        f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
        f"https://www.cvedetails.com/cve/{cve_id}/"
    ]
    
    driver = setup_driver()
    try:
        for url in sources:
            try:
                driver.get(url)
                time.sleep(2)  # Wait for page load
                
                # Check for common error indicators
                if "CVE ID not found" in driver.page_source or \
                   "404 Not Found" in driver.page_source or \
                   "Page not found" in driver.page_source or \
                   "No results found" in driver.page_source:
                    continue
                
                # If we get here, CVE exists in at least one source
                return True
            except Exception as e:
                print(f"Error checking {url}: {str(e)}")
                continue
                
        return False
    finally:
        driver.quit()

def scrape_opencve_data(driver, cve_id, data):
    """Separate function to scrape OpenCVE data"""
    try:
        opencve_url = f"https://app.opencve.io/cve/{cve_id}"
        driver.get(opencve_url)
        time.sleep(2)  # Reduced wait time
        
        # Find the vendors and products table
        tables = driver.find_elements(By.CSS_SELECTOR, "table.table.table-striped.table-bordered")
        vendors_table = None
        
        # Find the correct table that contains vendors and products
        for table in tables:
            try:
                header_row = table.find_element(By.TAG_NAME, "tr")
                headers = [th.text.strip() for th in header_row.find_elements(By.TAG_NAME, "th")]
                if len(headers) == 2 and "Vendors" in headers[0] and "Products" in headers[1]:
                    vendors_table = table
                    break
            except:
                continue
        
        if vendors_table:
            # Get all rows from the table
            rows = vendors_table.find_elements(By.TAG_NAME, "tr")[1:]  # Skip header row
            
            for row in rows:
                try:
                    cols = row.find_elements(By.TAG_NAME, "td")
                    if len(cols) >= 2:
                        vendor = cols[0].text.strip()
                        products_ul = cols[1].find_element(By.TAG_NAME, "ul")
                        products = [li.text.strip() for li in products_ul.find_elements(By.TAG_NAME, "li")]
                        
                        if vendor and products:  # Only add if both vendor and products are non-empty
                            data["vendors_and_products"].append({
                                "vendor": vendor,
                                "products": products
                            })
                except Exception as e:
                    print(f"Error processing vendor row: {str(e)}")
                    continue
    except Exception as e:
        print(f"OpenCVE scraping error: {str(e)}")

def scrape_nvd_details(driver, cve_id, data):
    """Separate function to scrape NVD data"""
    try:
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        driver.get(url)
        time.sleep(2)  # Reduced wait time
        
        # Wait for content to load
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )

        # Check if CVE exists in NVD specifically
        try:
            # Check for error message that indicates CVE doesn't exist
            error_message = driver.find_element(By.CSS_SELECTOR, "div.alert.alert-danger")
            if error_message and "CVE ID not found" in error_message.text:
                return {
                    "success": False,
                    "error": f"CVE ID {cve_id} exists but is not available in the NVD database."
                }
        except:
            pass  # No error message found, CVE exists in NVD

        # Add a longer delay to ensure JavaScript content is loaded
        time.sleep(5)

        # Updated description handling
        try:
            description = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "p[data-testid='vuln-description']"))
            )
            if description:
                data["description"] = description.text.strip()
            else:
                data["description"] = "Description not available"
        except Exception as e:
            print(f"Description error: {str(e)}")
            data["description"] = "Description not available"
            # Don't return error - continue with other data collection

        # Get modification info - using the exact structure you provided
        try:
            mod_container = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "div.bs-callout.bs-callout-info[role='alert'][data-testid='vuln-warning-alert-container']"))
            )
            
            mod_status = mod_container.find_element(By.CSS_SELECTOR, "strong.h4Size span[data-testid='vuln-warning-status-name']")
            mod_text = mod_container.find_element(By.CSS_SELECTOR, "p[data-testid='vuln-warning-banner-content']")
            
            data["modification_info"]["status"] = mod_status.text.strip()
            data["modification_info"]["text"] = mod_text.text.strip()
            print(f"Found modification info: {data['modification_info']['status']}")
        except Exception as e:
            print(f"Modification info error: {str(e)}")

        # Get CVSS metrics - using the exact structure you provided
        try:
            metrics_container = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "div#vulnCvssPanel.row.bs-callout.bs-callout-success.cvssVulnDetail"))
            )

            # CVSS v3.x
            try:
                # Click CVSS v3 button if it's not already active
                v3_button = driver.find_element(By.CSS_SELECTOR, "button#btn-cvss3")
                if "btn-active" not in v3_button.get_attribute("class"):
                    v3_button.click()
                    time.sleep(1)

                v3_panel = driver.find_element(By.CSS_SELECTOR, "div#Vuln3CvssPanel")
                
                # NIST v3 metrics
                nist_score = v3_panel.find_element(By.CSS_SELECTOR, "a#Cvss3NistCalculatorAnchor")
                nist_vector = v3_panel.find_element(By.CSS_SELECTOR, "span[data-testid='vuln-cvss3-nist-vector']")
                
                data["cvss_metrics"]["v3"]["nist"]["base_score"] = nist_score.text.strip()
                data["cvss_metrics"]["v3"]["nist"]["vector"] = nist_vector.text.strip()
                data["cvss_metrics"]["v3"]["nist"]["source"] = "NVD"
                
                # ADP v3 metrics
                try:
                    adp_score = v3_panel.find_element(By.CSS_SELECTOR, "a#Cvss3AdpCalculatorAnchor")
                    adp_vector = v3_panel.find_element(By.CSS_SELECTOR, "span[data-testid='vuln-cvss3-adp-vector']")
                    
                    data["cvss_metrics"]["v3"]["adp"]["base_score"] = adp_score.text.strip()
                    data["cvss_metrics"]["v3"]["adp"]["vector"] = adp_vector.text.strip()
                    data["cvss_metrics"]["v3"]["adp"]["source"] = "CISA-ADP"
                except Exception as e:
                    print(f"ADP v3 metrics error: {str(e)}")
            except Exception as e:
                print(f"CVSS v3 error: {str(e)}")

            # CVSS v2.0
            try:
                # Click CVSS v2 button
                v2_button = driver.find_element(By.CSS_SELECTOR, "button#btn-cvss2")
                v2_button.click()
                time.sleep(1)

                v2_panel = driver.find_element(By.CSS_SELECTOR, "div#Vuln2CvssPanel")
                base_score = v2_panel.find_element(By.CSS_SELECTOR, "a#Cvss2CalculatorAnchor")
                vector = v2_panel.find_element(By.CSS_SELECTOR, "span[data-testid='vuln-cvss2-panel-vector']")
                
                data["cvss_metrics"]["v2"]["base_score"] = base_score.text.strip()
                data["cvss_metrics"]["v2"]["vector"] = vector.text.strip()
            except Exception as e:
                print(f"CVSS v2 error: {str(e)}")

        except Exception as e:
            print(f"CVSS metrics error: {str(e)}")

        # Get references/hyperlinks
        try:
            hyperlinks_table = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "table[data-testid='vuln-hyperlinks-table']"))
            )
            
            # Get all rows
            rows = hyperlinks_table.find_elements(By.CSS_SELECTOR, "tr[data-testid^='vuln-hyperlinks-row-']")
            
            for row in rows:
                try:
                    # Get the link
                    link_element = row.find_element(By.CSS_SELECTOR, "a")
                    link_url = link_element.get_attribute("href")
                    
                    # Get the resource types (badges)
                    badges = row.find_elements(By.CSS_SELECTOR, "span.badge")
                    resource_types = [badge.text.strip() for badge in badges]
                    
                    # Add to references list
                    data["references"].append({
                        "url": link_url,
                        "resource_types": resource_types
                    })
                except Exception as e:
                    print(f"Error processing reference row: {str(e)}")
                    continue
                    
            print(f"Found {len(data['references'])} references")
        except Exception as e:
            print(f"References error: {str(e)}")

        print("Data collected:", json.dumps(data, indent=2))
        return {"success": True, "data": data}
    except Exception as e:
        print(f"NVD scraping error: {str(e)}")
        return {
            "success": False,
            "error": f"Error accessing CVE ID {cve_id}: {str(e)}"
        }

def get_gemini_analysis(cve_id, description=""):
    """Get enhanced CVE analysis from Gemini AI"""
    prompt = f"""
    Analyze this CVE vulnerability and provide detailed insights:
    CVE ID: {cve_id}
    Description: {description}

    Please provide a detailed technical analysis in this exact JSON format:
    {{
        "summary": "Brief technical summary",
        "technical_analysis": {{
            "vulnerability_type": "Type of vulnerability",
            "affected_components": "List of affected components",
            "attack_vector": "How the vulnerability can be exploited"
        }},
        "risk_assessment": {{
            "severity": "Critical/High/Medium/Low",
            "complexity": "Low/Medium/High",
            "privileges_required": "None/Low/High",
            "user_interaction": "None/Required"
        }},
        "impact_analysis": {{
            "confidentiality": "Impact description",
            "integrity": "Impact description",
            "availability": "Impact description"
        }},
        "mitigation_strategies": [
            "Strategy 1",
            "Strategy 2",
            "Strategy 3"
        ],
        "additional_recommendations": "Extra security recommendations"
    }}
    
    Provide specific technical details and avoid generic responses.
    """
    
    headers = {"Content-Type": "application/json"}
    data = {
        "contents": [{
            "parts": [{"text": prompt}]
        }]
    }
    
    try:
        response = requests.post(
            f"{GEMINI_API_URL}?key={GEMINI_API_KEY}",
            headers=headers,
            json=data,
            timeout=30
        )
        
        print(f"Gemini API Response: {response.status_code}")
        print(f"Response content: {response.text[:500]}...")  # Debug print
        
        if response.status_code == 200:
            result = response.json()
            if 'candidates' in result and result['candidates']:
                text = result['candidates'][0]['content']['parts'][0]['text']
                try:
                    # Try to extract JSON from the response
                    json_start = text.find('{')
                    json_end = text.rfind('}') + 1
                    if json_start >= 0 and json_end > json_start:
                        json_str = text[json_start:json_end]
                        return json.loads(json_str)
                except Exception as e:
                    print(f"JSON parsing error: {str(e)}")
                    return {"analysis": text}
        
        print("Failed to get valid response from Gemini")
        return {"error": "Failed to get analysis from Gemini"}
    except Exception as e:
        print(f"Gemini API error: {str(e)}")
        return {"error": str(e)}

def debug_ai_response(cve_id, response):
    """Debug AI response issues"""
    print(f"\n=== AI Debug for {cve_id} ===")
    print(f"Response type: {type(response)}")
    print(f"Response content preview: {str(response)[:500]}")
    try:
        if isinstance(response, dict):
            print("Keys available:", list(response.keys()))
        print("\nResponse structure valid: Yes")
    except Exception as e:
        print(f"\nResponse structure error: {str(e)}")
    print("=" * 50)

def scrape_nvd_data(cve_id):
    print(f"Starting analysis for {cve_id}...")
    data = {
        "cve_id": cve_id.upper(),
        "description": "",
        "modification_info": {"status": "", "text": ""},
        "cvss_metrics": {
            "v3": {"nist": {"base_score": "N/A", "vector": "N/A"}},
            "v2": {"base_score": "N/A", "vector": "N/A"}
        },
        "references": [],
        "vendors_and_products": [],
        "ai_analysis": None,
        "ai_powered": True  # Indicate AI enhancement
    }

    # First get basic NVD data for better AI context
    driver = setup_driver()
    try:
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        driver.get(url)
        time.sleep(2)
        
        try:
            description = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "p[data-testid='vuln-description']"))
            )
            if description:
                data["description"] = description.text.strip()
        except:
            pass
    finally:
        driver.quit()

    # Now run concurrent operations
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(check_cve_exists, cve_id): "exists",
            executor.submit(get_gemini_analysis, cve_id, data["description"]): "ai_analysis",
            executor.submit(scrape_opencve_data, setup_driver(), cve_id, data): "opencve"
        }
        
        for future in as_completed(futures):
            try:
                result = future.result()
                if futures[future] == "exists" and not result:
                    return {
                        "success": False,
                        "error": f"CVE ID {cve_id} does not exist in any known vulnerability database."
                    }
                elif futures[future] == "ai_analysis":
                    data["ai_analysis"] = result
            except Exception as e:
                print(f"Error in {futures[future]}: {str(e)}")

    # Continue with detailed NVD scraping
    driver = setup_driver()
    try:
        scrape_nvd_details(driver, cve_id, data)
    finally:
        driver.quit()

    # Add AI confidence score
    if data["ai_analysis"] and not isinstance(data["ai_analysis"], dict):
        data["ai_analysis"] = {"analysis": str(data["ai_analysis"])}
    
    data["ai_analysis"]["confidence_score"] = "high" if data["description"] else "medium"
    
    return {"success": True, "data": data}

@app.route('/')
def index():
    return render_template('index.html', ai_powered=True)

@app.route('/scrape/<cve_id>')
def scrape_cve(cve_id):
    try:
        # Validate CVE ID format
        if not re.match(r'^CVE-\d{4}-\d{4,7}$', cve_id.upper()):
            return jsonify({
                "success": False,
                "error": "Invalid CVE ID format. Please use format: CVE-YYYY-NNNN"
            })

        result = scrape_nvd_data(cve_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Error processing CVE ID {cve_id}: {str(e)}"
        })

@app.route('/ai-analysis/<cve_id>')
def get_ai_analysis(cve_id):
    """Endpoint for AI-only analysis"""
    try:
        if not re.match(r'^CVE-\d{4}-\d{4,7}$', cve_id.upper()):
            return jsonify({
                "success": False,
                "error": "Invalid CVE ID format. Please use format: CVE-YYYY-NNNN"
            })

        analysis = get_gemini_analysis(cve_id)
        return jsonify({
            "success": True,
            "ai_powered": True,
            "data": analysis
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Error getting AI analysis for {cve_id}: {str(e)}"
        })

if __name__ == '__main__':
    app.run(debug=True, port=5000)      