# SOC Analyst Interview Questions

## Technical Questions

1. Explain the difference between IDS and IPS. When would you use one over the other?

	IDS only detects threats, while IPS can both detect and prevent them

	Use an Intrusion Detection System (IDS) when you want to monitor your network for suspicious activity and receive alerts about potential threats.

	Intrusion Prevention System (IPS) is better when you need to actively block attacks in real-time by taking immediate action against detected threats.

2. How does a firewall work, and what are its limitations?

	Monitoring and filtering incoming and outgoing network traffic based on pre-defined rules.

	Acting as a barrier between a private network and the public internet.

	Allowing only authorized traffic to pass through while blocking malicious attempts.

	Its limitations include not being able to protect against all types of threats, particularly sophisticated attacks, insider threats, or user negligence, and can sometimes hinder network performance if not properly configured.

3. What is the purpose of a SIEM, and how do you investigate an alert in it?

Collect, analyze, and correlate security logs from various sources across an organization's network to identify potential security threats and incidents by detecting unusual patterns or anomalies.

To investigate an alert in a SIEM, analysts review the related log entries, analyze the context of the event, cross-check with other security data sources, and determine if the activity is malicious, taking appropriate actions like further investigation or incident response if needed. 

4. 


5. How does SSL/TLS ensure secure communication?

Secure communication by using a combination of encryption, authentication, and digital signatures to scramble data in transit, verify the identity of the communicating parties, and guarantee that data hasn't been tampered with

6. What is the principle of least privilege, and how do you implement it?

Granting users only the minimum level of access needed to perform their job functions, essentially minimizing the potential damage caused by a security breach by limiting unnecessary permissions.

Define user roles, assign specific access based on those roles, and regularly review and update access policies to ensure only the necessary privileges are granted.


7. How would you approach a misconfigured S3 bucket exposing sensitive data?

Immediately restrict access to the bucket by changing its permissions to block public access.

Conduct a thorough analysis of the exposed data to determine its sensitivity and potential impact.

Initiating mitigation steps like data encryption and access control updates to secure the bucket properly

8. What is the difference between authentication and authorization?

Authentication verifies a user's identity this process uses credentials, such as passwords or fingerprint scans, to prove a user's identity.

Authorization determines what a user can access grants access based on that level. This process uses user permissions to outline what each user can do within a particular resource or network.

9. How does DNS work, and what are some common DNS-based attacks?

Allowing users to access websites and services using human-readable domain names (e.g., example.com) instead of numerical IP addresses (e.g., 192.0.2.1).

**User Request:**

When a user types a domain name (e.g., www.example.com) in the browser, the request is sent to a DNS resolver (usually provided by the ISP or a third-party service like Google DNS).

**DNS Query Process:**

The resolver checks if it has the IP address for the requested domain cached. If not, it starts a recursive search:

 * Root DNS Server: It first queries a root DNS server, which points to the TLD (Top-Level Domain) server (e.g., .com).
 
 * TLD DNS Server: The TLD server then points to the authoritative DNS server for the specific domain (e.g., example.com).

 * Authoritative DNS Server: The authoritative DNS server provides the final IP address for the domain (e.g., 192.0.2.1).

**Response to User:**

The IP address is sent back to the user's DNS resolver, which caches the result and then provides it to the user’s browser to connect to the website.

**Connection:**

The browser can now connect to the website using the resolved IP address.

 DNS hijacking (redirecting users to malicious sites by manipulating DNS records) 

 DNS cache poisoning (tricking a DNS server into storing incorrect IP addresses)

 DNS amplification attacks (overwhelming a target server with traffic using open DNS resolvers)

 DNS tunneling (encoding data within DNS queries to hide malicious activity). 

10. How would you explain risk, vulnerability and threat?

**Risk**

Probability of a security incident occurring, along with the potential impact it could have on an organization's assets, operations, or reputation.

It’s a combination of threat and vulnerability.

**Vulnerability**

A vulnerability is a weakness or flaw in a system, application, or network that could be exploited by a threat to gain unauthorized access or cause damage.

**Threat**

A threat is any potential danger or event that could exploit a vulnerability to cause harm.

Vulnerability: A known bug in the banking app's login feature allows an attacker to bypass authentication if the app doesn’t have proper input validation.

Threat: An attacker who knows about this bug and is actively seeking to compromise banking apps to steal sensitive user information.

Risk: The risk is the probability that the attacker will exploit the bug (vulnerability) and cause financial loss or reputational damage to the bank

11. What port number does ping use?

The ping utility uses the ICMP (Internet Control Message Protocol), which does not rely on port numbers. ICMP is a network-layer protocol that is used for sending error messages and operational information, like the "echo request" and "echo reply" messages sent by the ping command.

12. What is an IPS, and how does it differ from IDS?

An IPS can actively block attacks, while an IDS only alerts about them

13. What is the difference between encoding, encryption and hashing?

Encryption is a type of encoding technique where the message is encoded using an encryption algorithm so that only authorized persons can access that information. RSA AES DES 

Encoding is a technique where the data is transformed from one form to another. ASCII BASE64

Hashing is the process of converting data into a fixed-size string or value using a hash function. MD5 SHA256

14. Give examples of algorithms or techniques used for encoding, encryption, and hashing.

Examples of Encoding: ASCII, Unicode, UTF-8, Base64, etc.
Examples of Encryption: AES, DES, RSA, Blowfish, etc.
Examples of Hashing: bcrypt, MD5, SHA-1, SHA-256, etc.
