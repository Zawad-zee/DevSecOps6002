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

As the lesson was on DevSecOps and CIA Triad, I decided to extend the project to give a more real life experience for myself.
- Threat Modeling using OWASP Zap
- first script to be following no secure coding principles
- second script following and implementing significant principles to showcase the secure coding principles (DRY, no hardcoded credentials, logging, integrity checks, file handling exception, pwd requirements)
- Docker + Splunbk for logging and monitoring
