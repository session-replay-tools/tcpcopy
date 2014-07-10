#[TCPCopy](https://github.com/wangbin579/tcpcopy) - A TCP Stream Replay Tool

TCPCopy is a TCP stream replay tool to support real testing of Internet server applications. 


##Description
Although the real live flow is important for the test of Internet server applications, it is hard to simulate it as online environments are too complex. To support more realistic testing of Internet server applications, we propose a live flow reproduction tool – TCPCopy, which could generate the test workload that is similar to the production workload. TCPCopy consists of two components: the TCPCopy Client (tcpcopy) and the TCPCopy Server (intercept). The TCPCopy Client (tcpcopy) is deployed on the production system and it copies live flow data, does necessary modifications and sends them to the test system in real-time. The TCPCopy Server (intercept) is deployed on the test system and it returns necessary response information to the TCPCopy Client (tcpcopy). To the test server, the reproduced workload is just from end-users. Currently, TCPCopy has been widely used by companies in China.   

TCPCopy has little influence on the production system except occupying additional CPU, memory and bandwidth. Moreover, the reproduced workload is similar to the production workload in request diversity, network latency and resource occupation.


##Scenarios:
* Distributed stress testing
  - Use tcpcopy to copy real-world data to stress test your server software. Bugs that only can be produced in high-stress situations can be found
* Live testing
  - Prove the new system is stable and find bugs that only occur in the real world
* Regression testing
* Performance comparison
  - For instance, you can use TCPCopy to [compare the performance of Apache and Nginx](https://raw.github.com/wangbin579/auxiliary/master/docs/Apache%202.4%20vs.%20Nginx%20-%20A%20comparison%20under%20real%20online%20applications.pdf)
    


##Architecture 

There are two ways to use TCPCopy: adopting the traditional architecture or using the advanced architecture.

###Traditional architecture
![tcpcopy](https://raw.github.com/wangbin579/auxiliary/master/images/traditional_archicture.GIF)


As shown in Figure 1, TCPCopy consists of two parts: the TCPCopy client (tcpcopy) and the TCPCopy server (intercept). While the TCPCopy client runs on the online server and captures the online requests, the TCPCopy server runs on the test server and does some assistant work, such as passing response info to the TCPCopy client and filtering outbound traffic.

The TCPCopy client (tcpcopy) utilizes raw socket input technique by default to capture the online packets at the network layer and does the necessary processing (including TCP interaction simulation, network latency control, and common upper-layer interaction simulation), and uses raw socket output technique by default to send packets to the test server. 

The TCPCopy server (intercept) is responsible for passing the response header to the TCPCopy client. By setting the iptables command, locally generated response packets will be sent to the corresponding kernel module (ip_queue or nfqueue), and then the kernel module will attempt to deliver the packets to the TCPCopy server (intercept), which will extract response header information and determine whether to drop the packet or not. To make the TCPCopy client send the next packet, the TCPCopy server (intercept) often needs to send the response header to the TCPCopy client using a special channel. When the TCPCopy client receives the response header, it utilizes the header information to modify the attributes of online packets and continues to send another packet. 
It should be noticed that the responses from the test server are dropped at the network layer of the test server and not return to the end-user by default.


![tcpcopy](https://raw.github.com/wangbin579/auxiliary/master/images/traditional_usage.GIF)

Figure 2 shows the architecture of using TCPCopy to do realistic testing of Internet server applications. In the online production system, when the end-users access the online application server, the application server may visit the backend services to process users’ requests if needed and return feedbacks to end-users. Meanwhile, the TCPCopy Client (tcpcopy) is deployed on the production server to copy and send the reproduced workload to the test server. In the test system, the reproduced flow accesses the test application server, which would also visit the backend services if needed and then return feedbacks. The TCPCopy Server (intercept)  handles these feedbacks and returns the necessary response information to the TCPCopy Client (tcpcopy). In addition, as both the TCPCopy Client (tcpcopy) and the TCPCopy Server (intercept) could be deployed on several servers, TCPCopy has good scalability. It could copy live flow on one or several production servers to one test server.  

###Advanced architecture

The difference between the advanced architecture and the traditional architecture is that the TCPCopy server (intercept) runs on a separate machine instead of the test server. Thus, the test tasks will not be influenced by the TCPCopy server (intercept).

![tcpcopy](https://raw.github.com/wangbin579/auxiliary/master/images/advanced_archicture.GIF)

The advanced architecture of TCPCopy can be seen in Figure 3. Assume the online server is running online services, the test server is used to do the test tasks and the assistant server is adopted to run the TCPCopy server (intercept). The only operation needed in the test server for TCPCopy is setting appropriate route commands to route response packets to the assistant server. The TCPCopy server (intercept) at the assistant server captures response packets at the data link layer and passes the response header to the TCPCopy client on the online server.  These changes lead to more realistic testing because the test task in the test server is no longer influenced by the TCPCopy server (intercept). Moreover, as the TCPCopy server (intercept) captures packets more efficiently at the data link layer and multiple instances of the TCPCopy server (intercept) could run concurrently, the processing ability of the TCPCopy server (intercept) is also enhanced.

![tcpcopy](https://raw.github.com/wangbin579/auxiliary/master/images/advanced_usage.GIF)

Figure 4 shows the advanced architecture of using TCPCopy to do realistic testing of Internet server applications. The TCPCopy server (intercept) runs on an independent machine which no longer influences the test tasks. 



##Quick start

Two quick start options are available:

* [Download the latest release](https://github.com/wangbin579/tcpcopy/releases).
* Clone the repo: `git clone git://github.com/wangbin579/tcpcopy.git`.


##Getting TCPCopy installed
1. cd tcpcopy
2. sh autogen.sh
3. ./configure 
  - choose appropriate configure options if needed
4. make
5. make install


###Configure Options
    --enable-debug      compile TCPCopy with debug support (saved in a log file)
    --enable-mysqlsgt   run TCPCopy at mysql skip-grant-tables mode(recommended)
    --enable-mysql      run TCPCopy at mysql mode
    --enable-offline    run TCPCopy at offline mode
    --enable-pcap       run TCPCopy at pcap mode
    --enable-udp        run TCPCopy at udp mode
    --enable-nfqueue    run the TCPCopy server (intercept) at nfqueue mode
    --enable-advanced   run TCPCopy at advanced mode (advanced archecture) 
    --enable-dlinject   send packets at the data link layer instead of the IP layer
    --enable-rlantency  add more lantency control

###Recommended use

    1. Recommended use of TCPCopy with traditional architecture
    ./configure  
           
    2. Recommended use of TCPCopy with advanced architecture
    ./configure --enable-advanced                 #The TCPCopy client (tcpcopy)
    ./configure --enable-advanced --enable-pcap   #The TCPCopy server (intercept)

    3. Recommended use of mysql replay
    ./configure --enable-mysqlsgt  
    
    It should be noticed that mysql in the test server needs to work in skip-grant-table mode.

    4. Use of offline replay 
    ./configure --enable-offline  
    
    TCPCopy also supports offline replay of TCP stream which reads packets from the pcap file.
    

##Running TCPCopy

###Traditional architecture:
    Assume TCPCopy with "./configure" is configured

	After installing TCPCopy, you have to deploy the TCPCopy client (tcpcopy) on the online source
	server and the TCPCopy server (intercept) on the target server. 

    Run:
    a) on the target host (root privilege is required):

      using ip queue (kernel < 3.5):
        modprobe ip_queue # if not running
        iptables -I OUTPUT -p tcp --sport port -j QUEUE # if not set
        ./intercept 

      or

      using nfqueue (kernel >= 3.5):
        iptables -I OUTPUT -p tcp --sport port -j NFQUEUE # if not set
        ./intercept

    b) on the source host (root privilege is required):
       ./tcpcopy -x localServerPort-targetServerIP:targetServerPort


###Advanced architecture:
	Assume tcpcopy with "./configure --enable-advanced" is configured on the online
	server and intercept with "./configure --enable-advanced --enable-pcap" is configured  
	on the assistant server.

	Run:
	a) On the test server which runs test server applications (root privilege is required):
	    Set route command appropriately to route response packets to the assistant server

        Take a web application as an example:

	    Assume 61.135.233.219 is the actual IP address which is the default gateway, while 
		61.135.233.161 is the IP address of the assistant server. We set the following route 
		commands to route all external responses to the assistant server.

           route del default gw 61.135.233.219
           route add default gw 61.135.233.161

	b) On the assistant server which runs intercept (the TCPCopy server) (root privilege is required):
	  ./intercept -F <filter> -i <device,> 
	  
	  Note that the filter format is the same as the pcap filter.
	  For example:
	  ./intercept -i eth0 -F 'tcp and src port 80' -d
	  Intercept will capture response packets of the TCP based application which listens on port 80 
	  from device eth0 
	
	c) On the online source server (root privilege is required):
	  ./tcpcopy -x localServerPort-targetServerIP:targetServerPort -s <intercept server,>  
	  



###Additional commands
Please execute "./tcpcopy -h" or "./intercept -h" for more details


##Note
1. It is tested on Linux only (kernal 2.6 or above)
2. TCPCopy may lose packets hence lose requests
3. Root privilege is required
4. TCPCopy does only support client-initiated connections now
5. TCPCopy does not support replay for server applications which use SSL/TLS



##Example (TCPCopy with traditional architecture)

Suppose there are two online hosts, 1.2.3.25 and 1.2.3.26. And 1.2.3.161 is the target host. Port 11311 is used as local server port and port 11511 is used as remote target server port. We use tcpcopy to test if 1.2.3.161 can process 2X requests than a host can serve.

Here we use traditional tcpcopy to perform the above test task.
    
    1) on the target host (1.2.3.161, kernel 2.6.18)
       # modprobe ip_queue 
       # iptables -I OUTPUT -p tcp --sport 11511 -j QUEUE 
       # ./intercept

    2) online host (1.2.3.25)
       # ./tcpcopy -x 11311-1.2.3.161:11511

    3) online host(1.2.3.26)
       # ./tcpcopy -x 11311-1.2.3.161:11511

    CPU load and memory usage is as follows:
       1.2.3.25:
           21158 appuser   15   0  271m 226m  756 S 24.2  0.9  16410:57 asyn_server
           9168  root      15   0 18436  12m  380 S  8.9  0.1  40:59.15 tcpcopy
       1.2.3.26:
           16708 appuser   15   0  268m 225m  756 S 25.8  0.9  17066:19 asyn_server
           11662 root      15   0 17048  10m  372 S  9.3  0.0  53:51.49 tcpcopy
       1.2.3.161:
           27954 root      15   0  284m  57m  828 S 58.6  1.4 409:18.94 asyn_server
           1476  root      15   0 14784  11m  308 S  7.7  0.3  49:36.93 intercept
    Access log analysis (Note that the following log files are generated by upper-layer applications):
       1.2.3.25:
           $ wc -l access_1109_09.log
             7867867,  2185 reqs/sec
       1.2.3.26:
           $ wc -l access_1109_09.log
             7843259,  2178 reqs/sec
       1.2.3.161:
           $ wc -l access_1109_09.log
             15705229, 4362 reqs/sec
       request loss ratio:
           (7867867 + 7843259 - 15705229) / (7867867 + 7843259) = 0.0375%

Clearly, the target host can process 2X of requests a source host can serve.How is the CPU load? Well, tcpcopy on online host 1.2.3.25 used 8.9%, host 1.2.3.26 used 9.3%, while intercept on the target host consumed about 7.7%. We can see that the CPU load is low here, and so is the memory usage.



##Influential Factors
There are several factors that could influence TCPCopy, which will be introduced in detail in the following sections.

###1. Capture Interface
TCPCopy utilizes raw socket input interface by default to capture packets at the network layer on the online server. The system kernel may lose some packets when the system is busy. Thus, the related system parameters should be set appropriately. 

If you configure TCPCopy with "--enable-pcap", then TCPCopy could capture packets at the data link layer and could also filter packets in the kernel.

###2. Sending Interface
TCPCopy utilizes raw socket output interface by default to send packets at the network layer to a target server. The system kernel may encounter problems and not send all the packets successfully. For example, when the packet size is larger than MTU, raw socket output interface would refuse to send these large packets. In TCPCopy 0.5 or above versions, with our special processing, large packets are supported.

If you configure TCPCopy with "--enable-dlinject", then TCPCopy could send packets at the data link layer to a target server.

###3.On the Way to the Target Server 
When a packet is sent by the TCPCopy client (tcpcopy), it may encounter many challenges before reaching the target server. As the source IP address in the packet is still the end-user’s IP address other than the online server’s, some security devices may take it for an invalid or forged packet and drop it. In this case, when you use tcpdump to capture packets on the target server, no packets from the expected end-users will be captured. To know whether you are under such circumstances, you can choose a target server in the same network segment to do a test. If packets could be sent to the target server successfully in the same network segment but unsuccessfully across network segments, your packets may be dropped halfway. 

To solve this problem, we suggest deploying the TCPCopy client (tcpcopy) and the TCPCopy server (intercept) on servers in the same network segment. There’s also another solution with the help of a proxy in the same network segment. The TCPCopy client could send packets to the proxy and then the proxy would send the corresponding requests to the target server in another network segment.

Note that deploying the TCPCopy server on one virtual machine in the same segment may face the above problems.

####4. OS of the Target Server
The target server may set rpfilter, which would check whether the source IP address in the packet is forged. If yes, the packet will be dropped at the network layer.

If the target server could not receive any requests although packets can be captured by tcpdump on the target server, you should check if you have any corresponding rpfilter settings. If set, you have to remove the related settings to let the packets pass through the network layer.

There are also other reasons that cause TCPCopy not working, such as iptables setting problems in the traditional framework.

###5. Applications on the Target Server
It is likely that the application on the target server could not process all the requests in time. On the one hand, bugs in the application may make the request not be responded for a long time. On the other hand, some protocols above TCP layer may only process the first request in the socket buffer and leave the remaining requests in the socket buffer unprocessed. 

###6. Netlink Socket Interface 
The following problem only occurs in the traditional architecture when IP Queue is used.

Packet loss also occurs when ip queue module transfers the response packet to the TCPCopy server (intercept) under a high-pressure situation. By using command "cat /proc/net/ip_queue", you can check the state of ip queue. 

If the value of queue dropped increases continually, ip_queue_maxlen should be set larger. For example, the following command modifies the default queue length 1024 to 4096.
 > echo 4096 > /proc/sys/net/ipv4/ip_queue_maxlen

If the value of netlink dropped increases continually, rmem_max and wmem_max should be set larger.
Here is an example.
 >sysctl -w net.core.rmem_max=16777216  
 >sysctl -w net.core.wmem_max=16777216



##Release History
+ 2011.09  v0.1    TCPCopy released
+ 2011.11  v0.2    fix some bugs
+ 2011.12  v0.3    support mysql copy 
+ 2012.04  v0.3.5  add support for multiple copies of the source request
+ 2012.05  v0.4    fix some bugs 
+ 2012.07  v0.5    support large packets (>MTU)
+ 2012.08  v0.6    support offline replaying from pcap files to the target server
+ 2012.10  v0.6.1  support intercept at multi-threading mode
+ 2012.11  v0.6.3  fix the fast retransmitting problem
+ 2012.11  v0.6.5  support nfqueue
+ 2013.03  v0.7.0  support lvs
+ 2013.06  v0.8.0  support new configure option with "configure --enable-advanced" and optimize intercept
+ 2013.08  v0.9.0  support pcap injection, remove GPLv2 code for mysql replay and fix some bugs
+ 2013.09  v0.9.2  add the compatibility check and fix several bugs.
+ 2013.10  v0.9.5  fix many problems including the timestamp problem 
+ 2013.11  v0.9.6  support setting the maximal length of the nfnetlink queue and fix some bugs
+ 2014.02  v0.9.7  fix several issues including the kernel version problem and the gnu99 problem
+ 2014.03  v0.9.8  fix issues when replicating requests across network segments
+ 2014.05  v0.9.9  remove the check for frag_off


##Bugs and feature requests
Have a bug or a feature request? [Please open a new issue](https://github.com/wangbin579/tcpcopy/issues). Before opening any issue, please search for existing issues.


## Copyright and license

Copyright 2013 under [the BSD license](LICENSE).


