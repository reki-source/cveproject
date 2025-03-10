# cveproject

# Project Name
CVE Data Scraper

## Description
This project is a Flask-based web application that scrapes CVE (Common Vulnerabilities and Exposures) data from multiple sources, including NVD, MITRE, CVE Details, and OpenCVE. It utilizes Selenium WebDriver with Chrome to automate web scraping and retrieve CVE details such as descriptions, CVSS scores, vendors, and products.

## Dependencies
Ensure you have the following dependencies installed:
- Python 3.x
- Flask
- Selenium
- webdriver-manager
- requests

To install the required dependencies, run:
```sh
pip install flask selenium webdriver-manager requests
```

## Running the Project
Follow these steps to run the project:

1. Clone the repository:
```sh
git clone <repository_url>
cd <project_directory>
```

2. Set up the required environment variables (if necessary):
   - Update `GEMINI_API_KEY` in the script with a valid API key if needed.

3. Run the Flask application:
```sh
python app.py
```

4. Access the application in your browser:
```
http://127.0.0.1:5000/
```

## Additional Notes
- The application uses Selenium WebDriver in headless mode to scrape data.
- It waits for page elements dynamically to ensure data accuracy.
- Ensure Google Chrome is installed on your system, as the script uses ChromeDriver.

## Troubleshooting
- If ChromeDriver issues occur, ensure that you have the latest version:
  ```sh
  pip install --upgrade webdriver-manager
  ```
- If running in a Linux environment, install additional dependencies:
  ```sh
  sudo apt install -y google-chrome-stable
  ```

## License
This project is open-source and available for modification and distribution.

