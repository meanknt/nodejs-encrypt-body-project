# Node.js Encrypted Body Simulation Project

This project is a **web application** designed to simulate secure data transmission using different methods such as encryption and integrity verification. It is primarily built for penetration testing training, where users can learn to analyze and bypass encryption mechanisms.

---

## Features

This project includes three versions of secure communication to demonstrate different approaches to handling data:

- **Version 1 (v1):** Encrypts the request body using **AES (CBC)** and sends it as a JSON payload.
- **Version 2 (v2):** Sends the **AES-encrypted body** as a raw string, removing JSON wrapping.
- **Version 3 (v3):** Sends plain JSON and adds an **HMAC hash** in the request headers to verify the integrity of the request body.

---

## Installation

Follow these steps to install and run the project locally:

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/nodejs-encrypt-body-project.git
   cd nodejs-encrypt-body-project
   npm install
   node app.js
   ```
