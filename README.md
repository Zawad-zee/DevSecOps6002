This rep was created as an extension of an assignment for my course MCSC Cybersecurity Architecture, Design, and Secure Software Development at Humber Polytechnic.

Lab Overview
In this lab, you will explore the fundamentals of DevSecOps, understand the SDLC (Software Development
Life Cycle) from a security perspective, and apply basic security principles to a sample application. You
will practice integrating security into development processes, ensuring Confidentiality, Integrity, and
Availability (CIA), and implementing data integrity verification.

Learning Objectives
By the end of this lab, you will be able to:
- Explain the DevSecOps Software Development Life Cycle (SDLC).
- Identify stages in development where security measures should be implemented.
- Design and implement mechanisms to ensure data confidentiality and integrity.
- Analyze potential threats in a software system and propose appropriate mitigation strategies.

Tasks were to write a Python script to read/write unencrypted credentials from/to a json file. The second version would be encrypting the credentials and hashing the entry, 
which later would be used to check the integrity of the data.

I expanded this DevSecOps and CIA‑focused lab to simulate a more realistic workflow by incorporating threat modeling with OWASP Threat Dragon and developing two Python scripts: one intentionally insecure and one implementing strong secure‑coding practices such as DRY principles, removal of hard‑coded credentials, logging, integrity checks, exception‑safe file handling, and password requirements. The project also integrates Docker and Splunk for logging, monitoring, and operational visibility.
