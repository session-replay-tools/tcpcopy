# Overview

With the rapid development of internet technology, server-side architectures have become increasingly complex. It is now difficult to rely solely on the personal experience of developers or testers to cover all possible business scenarios. Therefore, real online traffic is crucial for server-side testing. TCPCopy [1] is an open-source traffic replay tool that has been widely adopted by large enterprises. While many use TCPCopy for testing in their projects, they may not fully understand its underlying principles. This article provides a brief introduction to how TCPCopy works, with the hope of assisting readers.

# Architecture

The architecture of TCPCopy has undergone several upgrades, and this article introduces the latest 1.0 version. As shown in the diagram below, TCPCopy consists of two components: *tcpcopy* and *intercept*. *tcpcopy* runs on the online server, capturing live TCP request packets, modifying the TCP/IP header information, and sending them to the test server, effectively "tricking" the test server. *intercept* runs on an auxiliary server, handling tasks such as relaying response information back to *tcpcopy*.

![tcpcopy](images/tcpcopy.png)

Figure 1. Overview of the TCPCopy Architecture.

The simplified interaction process is as follows:

1. *tcpcopy* captures packets on the online server.

2. *tcpcopy* modifies the IP and TCP headers, spoofing the source IP and port, and sends the packet to the test server. The spoofed IP address is determined by the *-x* and *-c* parameters set at startup.

3. The test server receives the request and returns a response packet with the destination IP and port set to the spoofed IP and port from *tcpcopy*.

4. The response packet is routed to the *intercept* server, where *intercept* captures and parses the IP and TCP headers, typically returning only empty response data to *tcpcopy*.

5. *tcpcopy* receives and processes the returned data.

# Technical Principles

TCPCopy operates in two modes: online and offline. The online mode is primarily used for real-time capturing of live request packets, while the offline mode reads request packets from pcap-format files. Despite the difference in working modes, the core principles remain the same. This section provides a detailed explanation of TCPCopy's core principles from several perspectives.

## 1. Packet Capturing and Sending

The core functions of *tcpcopy* can be summarized as "capturing" and "sending" packets. Let's begin with packet capturing. How do you capture real traffic from the server? Many people may feel confused when first encountering this question. In fact, Linux operating systems already provide the necessary functionality, and a solid understanding of advanced Linux network programming is all that's needed. The initialization of packet capturing and sending in *tcpcopy* is handled in the `tcpcopy/src/communication/tc_socket.c` file. Next, we will introduce the two methods *tcpcopy* uses for packet capturing and packet sending.

### Raw Socket

A raw socket can receive packets from the network interface card on the local machine.  This is particularly useful for monitoring and analyzing network traffic. The code for initializing raw socket packet capturing in *tcpcopy* is shown below, and this method supports capturing packets at both the data link layer and the IP layer.

```c
int
tc_raw_socket_in_init(int type)
{
    int        fd, recv_buf_opt, ret;
    socklen_t  opt_len;

    if (type == COPY_FROM_LINK_LAYER) {
        /* Copy ip datagram from Link layer */
        fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    } else {
        /* Copy ip datagram from IP layer */
#if (TC_UDP)
        fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
#else
        fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
#endif
    }

    if (fd == -1) {
        tc_log_info(LOG_ERR, errno, "Create raw socket to input failed");   
        fprintf(stderr, "Create raw socket to input failed:%s\n", strerror(errno));
        return TC_INVALID_SOCK;
    }

    recv_buf_opt = 67108864;
    opt_len = sizeof(int);

    ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &recv_buf_opt, opt_len);
    if (ret == -1) {
        tc_log_info(LOG_ERR, errno, "Set raw socket(%d)'s recv buffer failed");
        tc_socket_close(fd);
        return TC_INVALID_SOCK;
    }

    return fd;
}
```

The code for initializing the raw socket for sending packets is shown below. First, it creates a raw socket at the IP layer and informs the protocol stack not to append an IP header to the IP layer.

```c
int
tc_raw_socket_out_init(void)
{
    int fd, n;

    n = 1;

    /*
     * On Linux when setting the protocol as IPPROTO_RAW,
     * then by default the kernel sets the IP_HDRINCL option and 
     * thus does not prepend its own IP header. 
     */
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (fd == -1) {
        tc_log_info(LOG_ERR, errno, "Create raw socket to output failed");
        fprintf(stderr, "Create raw socket to output failed: %s\n", strerror(errno));
        return TC_INVALID_SOCK;
    } 

    /*
     * Tell the IP layer not to prepend its own header.
     * It does not need setting for linux, but *BSD needs
     */
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n)) < 0) {
        tc_socket_close(fd);
        tc_log_info(LOG_ERR, errno,
                    "Set raw socket(%d) option \"IP_HDRINCL\" failed", fd);
        return TC_INVALID_SOCK;
    }


    return fd;
}

```

Construct the complete packet and send it to the target server.

- `dst_addr` is filled with the target IP address.
- The IP header is populated with the source and destination IP addresses.
- The TCP header is filled with the source port, destination port, and other relevant information.

### Pcap

Pcap is an application programming interface (API) provided by the operating system for capturing network traffic, with its name derived from 'packet capture.' On Linux systems, pcap is implemented via libpcap, and most packet capture tools, such as *tcpdump*, use libpcap for capturing traffic.

Below is the code for initializing packet capture with pcap.

```c
int
tc_pcap_socket_in_init(pcap_t **pd, char *device, 
        int snap_len, int buf_size, char *pcap_filter)
{
    int         fd;
    char        ebuf[PCAP_ERRBUF_SIZE]; 
    struct      bpf_program fp;
    bpf_u_int32 net, netmask;      

    if (device == NULL) {
        return TC_INVALID_SOCK;
    }

    tc_log_info(LOG_NOTICE, 0, "pcap open,device:%s", device);

    *ebuf = '\0';

    if (tc_pcap_open(pd, device, snap_len, buf_size) == TC_ERR) {
        return TC_INVALID_SOCK;
    }

    if (pcap_lookupnet(device, &net, &netmask, ebuf) < 0) {
        tc_log_info(LOG_WARN, 0, "lookupnet:%s", ebuf);
        return TC_INVALID_SOCK;
    }

    if (pcap_compile(*pd, &fp, pcap_filter, 0, netmask) == -1) {
        tc_log_info(LOG_ERR, 0, "couldn't parse filter %s: %s", 
                pcap_filter, pcap_geterr(*pd));
        return TC_INVALID_SOCK;
    }

    if (pcap_setfilter(*pd, &fp) == -1) {
        tc_log_info(LOG_ERR, 0, "couldn't install filter %s: %s",
                pcap_filter, pcap_geterr(*pd));
        pcap_freecode(&fp);
        return TC_INVALID_SOCK;
    }

    pcap_freecode(&fp);

    if (pcap_get_selectable_fd(*pd) == -1) {
        tc_log_info(LOG_ERR, 0, "pcap_get_selectable_fd fails"); 
        return TC_INVALID_SOCK;
    }

    if (pcap_setnonblock(*pd, 1, ebuf) == -1) {
        tc_log_info(LOG_ERR, 0, "pcap_setnonblock failed: %s", ebuf);
        return TC_INVALID_SOCK;
    }

    fd = pcap_get_selectable_fd(*pd);

    return fd;
}
```

The code for initializing packet sending with pcap is as follows:

```c
int
tc_pcap_snd_init(char *if_name, int mtu)
{
    char  pcap_errbuf[PCAP_ERRBUF_SIZE];

    pcap_errbuf[0] = '\0';
    pcap = pcap_open_live(if_name, mtu + sizeof(struct ethernet_hdr), 
            0, 0, pcap_errbuf);
    if (pcap_errbuf[0] != '\0') {
        tc_log_info(LOG_ERR, errno, "pcap open %s, failed:%s", 
                if_name, pcap_errbuf);
        fprintf(stderr, "pcap open %s, failed: %s, err:%s\n", 
                if_name, pcap_errbuf, strerror(errno));
        return TC_ERR;
    }

    return TC_OK;
}
```

### Raw Socket vs. Pcap

Since *tcpcopy* offers two methods, which one is better?

When capturing packets, we are primarily concerned with the specific packets we need. If the capture configuration is not set correctly, the system kernel might capture too many irrelevant packets, leading to packet loss, especially under high traffic pressure. After extensive testing, it has been found that when using the pcap interface to capture request packets, the packet loss rate in live environments is generally higher than when using raw sockets. Therefore, *tcpcopy* defaults to using raw sockets for packet capture, although the pcap interface can also be used (with the `--enable-pcap` option), which is mainly suited for high-end pfring captures and captures after switch mirroring.

For packet sending, *tcpcopy* uses the raw socket output interface by default, but it can also send packets via pcap_inject (using the `--enable-dlinject` option). The choice of which method to use can be determined based on performance testing in your actual environment.

## **2. TCP Protocol Stack**

We know that the TCP protocol is stateful. Although the packet sending mechanism was explained earlier, without establishing an actual TCP connection, the sent packets cannot be truly received by the testing service. In everyday network programming, we typically use the TCP socket interfaces provided by the operating system, which abstract away much of the complexity of TCP states. However, in *tcpcopy*, since we need to modify the source IP and destination IP of the packets to deceive the testing service, the APIs provided by the operating system are no longer sufficient.

As a result, *tcpcopy* implements a simulated TCP state machine, representing the most complex and challenging aspect of its codebase. The relevant code, located in `tcpcopy/src/tcpcopy/tc_session.c`, handles crucial tasks such as simulating TCP interactions, managing network latency, and emulating upper-layer interactions.

![](images/tcp_state_machine.png)

Figure 2. Classic TCP state machine overview.

In *tcpcopy*, a session is defined to maintain information for different connections. Different captured packets are processed accordingly:

- **SYN Packet:** Represents a new connection request. *tcpcopy* assigns a source IP, modifies the destination IP and port, then sends the packet to the test server. At the same time, it creates a new session to store all states of this connection.
- **ACK Packet:**
  - **Pure ACK Packet:** To reduce the number of sent packets, *tcpcopy* generally doesn't send pure ACKs.
  - **ACK Packet with Payload (indicating a specific request):** It finds the corresponding session and sends the packet to the test server. If the session is still waiting for the response to the previous request, it delays sending.
- **RST Packet:** If the current session is waiting for the test server's response, the RST packet is not sent. Otherwise, it's sent.
- **FIN Packet:** If the current session is waiting for the test server's response, it waits; otherwise, the FIN packet is sent.

## **3. Routing**

After *tcpcopy* sends the request packets, their journey may not be entirely smooth:

- The IP of the request packet is forged and not the actual IP of the machine running *tcpcopy*. If some machines have rpfilter (reverse path filtering) enabled, it will check whether the source IP address is trustworthy. If the source IP is untrustworthy, the packet will be discarded at the IP layer.
- If the test server receives the request packet, the response packet will be sent to the forged IP address. To ensure these response packets don't mistakenly go back to the client with the forged IP, proper routing configuration is necessary. If the routing isn't set up correctly, the response packet won't be captured by *intercept*, leading to incomplete data exchange.
- After *intercept* captures the response packet, it extracts the response packet and discards the actual data, returning only the response headers and other necessary information to *tcpcopy*. When necessary, it also merges the return information to reduce the impact on the network of the machine running *tcpcopy*.

## **4. Intercept**

For those new to *tcpcopy*, it might be puzzling—why is *intercept* necessary if we already have *tcpcopy*? While *intercept* may seem redundant, it actually plays a crucial role. You can think of *intercept* as the server-side counterpart of *tcpcopy*, with its name itself explaining its function: an "interceptor." But what exactly does *intercept* need to intercept? The answer is the response packet from the test service.

If *intercept* were not used, the response packets from the test server would be sent directly to *tcpcopy*. Since *tcpcopy* is deployed in a live environment, this means the response packets would be sent directly to the production server, significantly increasing its network load and potentially affecting the normal operation of the live service. With *intercept*, by spoofing the source IP, the test service is led to "believe" that these spoofed IP clients are accessing it. *Intercept* also performs aggregation and optimization of the response packet information, further ensuring that the live environment at the network level is not impacted by the test environment.

*intercept* is an independent process that, by default, captures packets using the pcap method. During startup, the `-F` parameter needs to be passed, for example, "tcp and src port 8080," following libpcap's filter syntax. This means that *intercept* does not connect directly to the test service but listens on the specified port, capturing the return data packets from the test service and interacting with *tcpcopy*.

## **5. Performance**

*tcpcopy* uses a single-process, single-thread architecture based on an epoll/select event-driven model, with related code located in the `tcpcopy/src/event` directory. By default, epoll is used during compilation, though you can switch to select with the `--select` option. The choice of method can depend on the performance differences observed during testing. Theoretically, epoll performs better when handling a large number of connections.

In practical use, *tcpcopy*'s performance is directly tied to the amount of traffic and the number of connections established by *intercept*. The single-threaded architecture itself is usually not a performance bottleneck (for instance, Nginx and Redis both use single-threaded + epoll models and can handle large amounts of concurrency). Since *tcpcopy* only establishes connections directly with *intercept* and does not need to connect to the test machines or occupy port numbers, *tcpcopy* consumes fewer resources, with the main impact being on network bandwidth consumption.

```c
static tc_event_actions_t tc_event_actions = {
#ifdef TC_HAVE_EPOLL
    tc_epoll_create,
    tc_epoll_destroy,
    tc_epoll_add_event,
    tc_epoll_del_event,
    tc_epoll_polling
#else
    tc_select_create,
    tc_select_destroy,
    tc_select_add_event,
    tc_select_del_event,
    tc_select_polling
#endif
};
```

# Conclusion

TCPCopy is an excellent open-source project. However, due to the author's limitations, this article only covers the core technical principles of TCPCopy, leaving many details untouched [2]. Nevertheless, I hope this introduction provides some inspiration to those interested in TCPCopy and traffic replay technologies!

# References：

[1] https://github.com/session-replay-tools/tcpcopy.

[2] https://testerhome.com/articles/34737
