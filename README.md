REsource
========

Ruby scripts for static analysis of malicous files. 

Currently supported filetypes:
* PE (32-bit/64-bit)
* ELF
* JPEG
* Scripts (BASH, Python, Perl, etc..)


Features
--------
Currently REsource will:
- Provide you with hashes of the file
- Perform some cursory analysis on the file, such as some characteristics and build information 
- Output the strings from the file into a separate txt file
- Query VirusTotal for the hash of the file and provide you with the permalink to the analysis if the hash has been previously analyzed.


How-To
-------
1. Install ruby using RVM, Apt, Yum, or whichever way you choose
2. Clone the repository
3. If you do not have ruby bundler installed, install it.
4. From within repository directory, run 'bundle install' to install required gems
5. Add VirusTotal API key to scalpel.rb in the vt_query() function
6. Run 'ruby dissector.rb'
