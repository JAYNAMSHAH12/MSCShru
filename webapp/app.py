import streamlit as st
from PIL import Image
import base64
from io import BytesIO
from tensorflow import keras
from urllib.parse import urlparse
import numpy as np
import re
import os
import shutil
import time
import pyfiglet
from Extract.url_app import URL_detector
from Extract.PE_app import PE_scanner

st.set_page_config(page_title="Malware Detection", page_icon="gnk-logo.png")

st.markdown(
    """
    <style>
    /* Center the logo and title in the sidebar */

    .sidebar-container {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 30px; /* Space between logo and title */
    }


    /* Adjust the logo size */
    .sidebar-logo {
        max-width: 50px; /* Adjust width */
        height: 50px;
        margin-bottom: 10px;
    }

    /* Ensure sidebar content fits responsively */
    .sidebar-content {
        width: 100%; 
        text-align: center;
        padding-top: 20px;
    }

    /* Full-width buttons in the sidebar */
    .stButton>button {
        width: 100%; /* Make buttons take full width */
        margin-top: 10px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)



def image_to_base64(img):
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode()


logo = Image.open("gnk-logo.png")
logo_base64 = image_to_base64(logo)

def render_image_as_html(image_path, css_class):
    """Convert Streamlit image to HTML with given CSS class."""
    with open(image_path, "rb") as img_file:
        encoded_image = base64.b64encode(img_file.read()).decode()
    return f'<img src="data:image/png;base64,{encoded_image}" class="{css_class}" alt="Logo">'

#Sidebar logo & title
with st.sidebar:
    st.markdown(
        f"""
        <div class="sidebar-content">
            <div class="sidebar-container">
                {render_image_as_html("gnk-logo.png", "sidebar-logo")}
                <h2>MSC Project</h2>
                {render_image_as_html("gnk-logo.png", "sidebar-logo")}
            </div>
        </div>
        <br>
        <br>
        """,
        unsafe_allow_html=True,
    )



# Tabs for Navigation
tabs = ["URL Scanner", "File Scanner"]
selected_page = "URL Scanner"

if 'selected_page' not in st.session_state:
    st.session_state.selected_page = "File Scanner"

# Update selected tab on button click
for tab in tabs:
    if st.sidebar.button(tab):
        st.session_state.selected_page = tab

# Sidebar tab buttons - only update state when clicked
# if st.sidebar.button("URL Scanner"):
#     st.session_state.selected_page = "URL Scanner"

# if st.sidebar.button("File Scanner"):
#     st.session_state.selected_page = "File Scanner"
       
selected_page = st.session_state.selected_page

# Main Page Content
st.title("Malware Detection using Python")
st.caption("This program helps you to scan for any malware in your domain or files. Just paste your URL or upload your file and hit Scan.")
st.write("")
st.write("")


# Display content based on selected tab
if selected_page == "URL Scanner":        
    def load_model():
        model=keras.models.load_model('Malicious_URL_Prediction.h5')
        return model
    with st.spinner("Loading Model...."):
        model=load_model()
        
    def fd_length(url):
        urlpath= urlparse(url).path
        try:
            return len(urlpath.split('/')[1])
        except:
            return 0
    
    def digit_count(url):
        digits = 0
        for i in url:
            if i.isnumeric():
                digits = digits + 1
        return digits

    def letter_count(url):
        letters = 0
        for i in url:
            if i.isalpha():
                letters = letters + 1
        return letters

    def no_of_dir(url):
        urldir = urlparse(url).path
        return urldir.count('/')

    def having_ip_address(url):
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
        if match:
            # print match.group()
            return -1
        else:
            # print 'No matching pattern found'
            return 1

    def extract_features(url):
        # 'hostname_length', 'path_length', 'fd_length', 'count-', 'count@', 'count?', 'count%', 'count.', 'count=', 'count-http','count-https', 'count-www', 'count-digits','count-letters', 'count_dir', 'use_of_ip'
        hostname_length = len(urlparse(url).netloc)
        path_length = len(urlparse(url).path)
        f_length = fd_length(url)
        count_1 = url.count('-')
        count_2 = url.count('@')
        count_3 = url.count('?')
        count_4 = url.count('%')
        count_5 = url.count('.')
        count_6 = url.count('=')
        count_7 = url.count('http')
        count_8 = url.count('https')
        count_9 = url.count('www')
        count_10 = digit_count(url)
        count_11 = letter_count(url)
        count_12 = no_of_dir(url)
        count_13 = having_ip_address(url)
        output = [hostname_length, path_length, f_length, count_1, count_2, count_3, count_4, count_5, count_6, count_7, count_8, count_9, count_10, count_11, count_12, count_13]
        print(output)
        features = np.array([output]) 
        return features

    def predict(val):
        st.write(f'<span style="color:#494848;">Classifying URL: </span>{val}', unsafe_allow_html=True)
        with st.spinner("Classifying..."):
            input = extract_features(val)
            print(input.shape)
            for item in input:
                print(type(item))
            pred_test = model.predict(input)
            percentage_value = pred_test[0][0] * 100
            if (pred_test[0] < 0.5):
                st.write(f'<span style="color:green;">✅ **SAFE with {percentage_value:.2f}% malicious confidence**</span>', unsafe_allow_html=True)
            else: 
                st.write(f'<span style="color:red;">⛔️ **MALICOUS with {percentage_value:.2f}% malicious confidence**</span>', unsafe_allow_html=True)
            print(input, pred_test)


    value = st.text_input("Enter URL to scan", "https://www.google.com")
    submit = st.button("Scan URL")

    if submit:
        predict(value)


base_dir = os.path.abspath(os.path.dirname(__file__))
temp_dir = os.path.join(base_dir, 'TestFile', 'temp')
os.makedirs(temp_dir, exist_ok=True)

def run_PE():
    file = input("Enter the path and name of the file: ")
    os.system(f"python Extract/PE_main.py {file}")

if selected_page == "File Scanner":
    st.markdown('## File(PE) Scanner:')
    
    # File uploader to accept multiple files
    upload_files = st.file_uploader('Choose files:', accept_multiple_files=True)

    # Initialize PE scanner
    pe_scanner = PE_scanner()

    # Check if files were uploaded
    if upload_files:
        temp_dir = os.path.join('TestFile', 'temp')
        os.makedirs(temp_dir, exist_ok=True)

        with st.spinner("Checking files..."):
            for file in upload_files:
                # Save the uploaded file temporarily
                file_path = f"{temp_dir}/temp_{file.name}"
                with open(file_path, 'wb') as f:
                    f.write(file.getvalue())

                # Run the PE scan on the uploaded file
                legitimate = pe_scanner.PE_scan(file_path)

                # Display results based on scan outcome
                if legitimate:
                    st.success(f"File {file.name} is safe.", icon="✅")
                else:
                    mal_class = pe_scanner.PE_mal_classify(file_path)
                    st.warning(f"File {file.name} is malicious. Likely malware class: {mal_class}", icon='🚨')



    # if 'uploaded_files' not in st.session_state:
    #     st.session_state.uploaded_files = []

    # upload_files = st.file_uploader('Choose files: ', accept_multiple_files=True)

    # if upload_files:
    #     st.session_state.uploaded_files = upload_files

    # if st.session_state.uploaded_files:
    #     pe_scanner = PE_scanner()
    #     for i in st.session_state.uploaded_files:
    #         with open(f'TestFile/temp/temp_{i.id}', 'wb') as file:
    #             file.write(i.getvalue())
    #             legitimate = pe_scanner.PE_scan(f'TestFile/temp/temp_{i.id}')
    #             if legitimate:
    #                 st.success(f"File {i.name} is safe.", icon="✅")
    #             else:
    #                 mal_class = pe_scanner.PE_mal_classify(f'TestFile/temp/temp_{i.id}')
    #                 st.warning(f"File {i.name} is malicious. Likely malware class: {mal_class}", icon='🚨')

