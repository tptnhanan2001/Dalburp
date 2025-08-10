# DalBurp

DalBurp is a **Burp Suite Extension** that automates XSS vulnerability scanning by integrating directly with **Dalfox CLI**.

## Features

- **Automatic Request Capture**  
  Automatically fetch requests from Burp (GET, POST, PUT, PATCH, DELETE).

- **Payload Support**  
  Support sending data in the body when scanning methods with payload (POST/PUT/PATCH).

- **Manual Control**  
  Allows manual **Start/Stop** scanning right in the separate tab UI.

- **Result Display**  
  Displays scan results including: **HTTP Method**, **URL**, **Status**, and **Payload POC**.

- **Duplicate Scan Prevention**  
  Reduces duplicate scanning by tracking **URL + method**.

## Application

DalBurp is convenient for **pentesters** and **bug hunters** who want to quickly test XSS while intercepting traffic without having to manually copy-paste requests to Dalfox.

## Requirements

- **Burp Suite** (Community or Professional)
- **Dalfox CLI** installed and accessible in system PATH  
  Install Dalfox:  
  ```bash
  go install github.com/hahwul/dalfox/v2@latest
![DalBurp UI]([https://raw.githubusercontent.com/<username>/<repo>/main/images/screenshot.png](https://github.com/tptnhanan2001/Dalburp/blob/main/Screenshot%202025-08-10%20154210.png))
