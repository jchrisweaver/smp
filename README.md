smp
===

Socialist Millionaire Protocol implementation in C

Chris Weaver
11/3/2014

Background
---

The Socialist Millionaire Protocol is a very useful method of assuring mutual trust between two parties in an untreatable environment.  Read more about it <a href="http://en.wikipedia.org/wiki/Socialist_millionaire">here</a> and <a href="http://twistedoakstudios.com/blog/Post3724_explain-it-like-im-five-the-socialist-millionaire-problem-and-secure-multi-party-computation">here.</a>

Shane Tully wrote an implementation of the protocol in Python that does a great job of illustrating how it works.  However, there are many instances where a C implementation would be preferable, which was my motivation to create this project.

I have borrowed extensively from Shane's implementation, using his function names and even variable names in order to show the translation.

You can read Shane's blog post and find his original code <a href"https://shanetully.com/2013/08/mitm-protection-via-the-socialist-millionaire-protocol-otr-style/">here.</a>

I have included his code in the smp-p subdirectory in this project with a few minor changes to make python to c socket communication easier.  Specifically, I added a 4-byte header to all socket comm that tells the receiver the expected size of the incoming data.





