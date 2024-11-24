# Node.js Encrypted Body Simulation Project

This project is a **web application** designed to simulate secure data transmission using different methods such as encryption and integrity verification. It is primarily built for penetration testing training, where users can learn to analyze and bypass encryption mechanisms.

---

## Features

This project includes five versions of secure communication to demonstrate different approaches to handling data:

- **App 1:** Encrypts the request body using **AES (CBC)** with a static IV and sends it as a JSON payload.
- **App 2:** Sends the **AES-encrypted body** as a raw string, removing JSON wrapping.
- **App 3:** Sends plain JSON and adds an **HMAC hash** in the request headers to verify the integrity of the request body.
- **App 4:** Encrypts the request body using **AES (CBC)** with a dynamically generated IV for every request and includes the IV in the payload.
- **App 5:** Encrypts the request body using **AES (CBC)** with both a dynamically generated IV and a dynamically generated secret key for every request, ensuring maximum data protection.

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
