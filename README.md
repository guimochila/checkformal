checkformal v0.1
==========

checkformal is basic first approach for malicious software.<br />
I wrote this code to practice my Python skills and automate my first look at a malicious file.
<p />
The process is very simple:
<p />
1- Create a MD5 from a file<br />
2- Create a directory with the MD5 value<br />
3- Identify if it has any packer<br />
4- Call for the strings command and try to find any possible Domain/URL/IP/Email<br />
5- Check the MD5 against Virus Total Database<br />
6- Shows all the positives results found.<br />
7- Zip the file and copy it to the MD5 directory<br />
8- Write a report with the data found from the file.<br />
<p />
<p />
It's a very simple script that might help you to save time or just to learn about Python and Malware.

