smp
===

Socialist Millionaire Protocol implementation in C

Chris Weaver
06.14.2015

Background
---

The Socialist Millionaire Protocol is a very useful method of assuring mutual trust between two parties in an untrustable environment.  Read more about it <a href="http://en.wikipedia.org/wiki/Socialist_millionaire">here</a> and <a href="http://twistedoakstudios.com/blog/Post3724_explain-it-like-im-five-the-socialist-millionaire-problem-and-secure-multi-party-computation">here.</a>

<a href="https://shanetully.com/">Shane Tully</a> wrote an implementation of the protocol in Python that does a great job of illustrating how it works.  However, there are many instances where a C implementation would be preferable, which was my motivation to create this project.

I have borrowed extensively from Shane's implementation, using his function names and even variable names in order to show the translation.

You can read Shane's blog post and find his original code <a href="https://shanetully.com/2013/08/mitm-protection-via-the-socialist-millionaire-protocol-otr-style/">here.</a>

I have included his code in the smp-p subdirectory in this project with a few minor changes to make python to c socket communication easier.  Specifically, I added a 4-byte header to all socket comm that tells the receiver the expected size of the incoming data.


Requirements
---
* Mac OS X
* XCode
* OpenSSL (I used openssl-1.0.1i)


HOWTO
---
1.  Using XCode, compile the smp-c project
2.  Start the python app with 'python smp-p/smp_test.py listen'
3.  Start the C app either through XCode or from the command line
4.  At the prompt for the C app from STDIN, enter a secret passphrase
5.  At the prompt for the Python app, enter a matching passphrase.
6.  Both apps will report a match or no match


TODO
---
*  FIX: The C version is leaving a socket hanging (port 5000) until it times out causing consecutive runs to fail
*  ENHANCE: Add better error handling in socket code and main code
*  ENHANCE: Make the port a command-line param
*  Refactoring for tighter code

CONTACT
---
Any questions, comments or bug fixes, feel free to contact me at jchrisweaver at gmail dot com


LICENSE
---
My work is free to be used as is and is commited to public commons.
If you find any bugs or make any enhancements, I'd appreciate it if you'd let me know.
If you do use it, I'd also appreciate it if you'd give me a tweet at @jchrisweaver

Enjoy.
