# Honeypot-HAT
Jacob Andrews 
University dissertation system files.
Profiling Dark Web Actors Using an Added-Value Honeypot Driven Approach:
A Novel Proof of Concept Solution

This repository contains the honeypot test-bed (website) which was hosted on the Dark Web and the Honeypot
Analysis Tool (HAT) which was utilised to analyse DW users.

The system works by hosting the honeypot on a local web server and directly accessing and analysing the
server logs via the HAT.

########################################
RUNNING THE HONEYPOT:
########################################
Due to the honeypot being 100% HTML & CSS, pulling the Honeypot folder and opening any HTML file should give you access to the honeypot website.


########################################
RUNNING THE Honeypot Analysis Tool (HAT):
########################################
The HAT was built using Python 3.6.9 with a number of external packages.
To run the HAT, these packages need to be installed:
- PyQt4
- functools
- datetime
- matplotlib
- matplotlib.collections
- matplotlib.backends
- networkx
- statistics
- pandas
- numpy
- seaborn
- sqlite3
- re

Once these packages have been installed, run the HAT by executing the honeypot_analysis_tool.py file.
The functionality would usually depend on a local web server being installed, but for marking
purposes, I have provided an example server log file for the HAT to use (server_logs/server_access.txt).

If you do log out, create an account via the login portal to log back into the application.
If this doesn't work, re-execute the honeypot_analysis_tool.py file or us these login details:
Username: test
Password: password


########################################
ACCESSING THE NODE POSITION MARKOV MODEL:
########################################
This can be viewed via the "experiment_data/Experiment Data Analysis.xlsx" file.


