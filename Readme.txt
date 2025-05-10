UMBC ID: SY88373
Name: Brandon Nguyen (Solo)

b. In this assignment, I learned how to implement a basic tcp connection between a client host and a server host. \
c. I didn't really face any particular challenges as I did a similar project in CMSC421, where we implemented a TCP connection mimicking a YouTube likes server, so I had prior knowledge on the matter.
I was about to struggle until I found out that python has some very good libraries that speeds things up.

2. In total, I think I spent about 1 day (24 hours worth) of work on this project spread across the whole timeframe before due date

For grader: I implemented the code in VScode, but tested it on the VM. In order to get a tcpdump file(session1.pcap), I had to disable my SSL encryption, so it will slightly differ from the 
images that you will see. I will submit the final versions of the client, server, and SSL certification needed. I did NOT implement a question chain. I will also include a copy of the client
to test the select operator as well; it should work and support multiple clients concurrently. 

Extra notes on implementation: Server will not terminate until user uses keyboard interruption (CTRL+C). Client will time out after 180 seconds, you may edit this to test it.