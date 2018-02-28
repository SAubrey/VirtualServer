#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <string.h>

/* Sean Aubrey
 * CIS 457
 */

struct fwdTable {
    char prefixAddr[9]; // overall IP dst
    char prefixBits[3]; // /16, /24
    char nexthop[9]; // IP addr (may be '-')
    char interfaceName[8]; // name of hop interface
};

struct interface {
    char * name;
    int sockNum;
    unsigned char mac[6];
    unsigned char ip[4];
};

struct arp_hdr { // 28 bytes
    unsigned short       h_type;        // hardware type
    unsigned short       p_type;        // protocol type
    unsigned char        h_addr_length; // length of hardware addr
    unsigned char        p_addr_length; // length of protocol addr
    unsigned short       op;            // op code, 1=req, 2=rep
    unsigned char        sha[6];        // Sender hardware addr
    unsigned char        sip[4];        // sender IP addr
    unsigned char        dha[6];        // target hardware addr
    unsigned char        dip[4];        // target IP addr
};

struct ip_hdr { // 20 bytes
    unsigned char v:4, hl:4; // version, header length (4 bits ea)
    unsigned char tos;       // ip type of service
    unsigned short int len;  // total length
    unsigned short int id;   // unique id
    unsigned short int off;  // frag offset
    unsigned char ttl;       // time to live
    unsigned char protocol;  // protocol
    unsigned short int csum; // ip checksum
    unsigned int src;        // source
    unsigned int dst;        // destination
};

struct icmp_hdr { // 4 bytes
    unsigned char icmp_type;     // 0 if reply/request
    unsigned char icmp_code;     // 0 if echo reply
    unsigned short int icmp_sum; // checksum
};

int sendARPReply(char buf[1500], struct ether_header *eth, struct arp_hdr arp,
                 struct interface interfaces[6], int psock, int i) {
    char buffer[42]; // 28 + 14
    struct ether_header *ethReply;
    struct arp_hdr arpReply;

    /* Copy over headers, then modify */
    memcpy(&ethReply, &eth, 14);
    memcpy(&arpReply, &arp, 28);

    /* Modify */
    memcpy(&ethReply->ether_dhost, &eth->ether_shost, 6);
    memcpy(&ethReply->ether_shost, &interfaces[i].mac, 6);

    arpReply.op = (unsigned short)htons(2);
    memcpy(&arpReply.sha, &interfaces[i].mac, 6);
    memcpy(&arpReply.sip, &interfaces[i].ip, 4);
    memcpy(&arpReply.dha, &arp.sha, 6);
    memcpy(&arpReply.dip, &arp.sip, 4);

    /* Populate buffer */
    memcpy(&buffer, ethReply, 14);
    memcpy(&buffer[14], &arpReply, 28);

    printf("Reply DST IP: %d.%d.%d.%d\n",
           arpReply.dip[0],
           arpReply.dip[1],
           arpReply.dip[2],
           arpReply.dip[3]
    );

    int bytes = send(psock, buffer, sizeof(buffer), 0);
    printf("%d byte ARP reply sent on interface: %s\n\n",
           bytes, interfaces[i].name);
    return 0;
}

int sendARPRequest(char** replyBuf,
                   char nexthop[10],
                   struct interface interfaces[6],
                   int sock,
                   int sockIndex) {
    char buffer[42]; // 28 + 14
    struct ether_header *eth = (struct ether_header*)malloc(14);
    struct arp_hdr *arp = (struct arp_hdr*)malloc(28);

    /* Construct eth header */
    unsigned char broadcast[6];
    int q;
    for (q = 0; q < 6; q++) {
        broadcast[q] = 0XFF;
    }
    memcpy(&eth->ether_dhost, &broadcast, 6);
    memcpy(&eth->ether_shost, &interfaces[sockIndex].mac, 6);
    eth->ether_type = htons(0x0806); // ARP type

    /* Construct ARP header */
    arp->h_type = htons(1); // ether
    arp->p_type = htons(2048); // IPv4
    arp->h_addr_length = 6; // mac addr
    arp->p_addr_length = 4; // IP addr
    arp->op = (unsigned short)htons(1); // request

    memcpy(&arp->dha, &eth->ether_dhost, 6);
    memcpy(&arp->sha, &eth->ether_shost, 6);

    struct sockaddr_in *temp =
            (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));

    unsigned char dstip[4];
    inet_aton(nexthop, &temp->sin_addr); // nexthop into temp
    memcpy(&dstip, &temp->sin_addr, 4);

    printf("ARP Request DST IP address: %d.%d.%d.%d\n",
           dstip[0],
           dstip[1],
           dstip[2],
           dstip[3]
    );

    memcpy(&arp->dip, &dstip, 4); //
    memcpy(&arp->sip, &interfaces[sockIndex].ip, 4);

    memcpy(&buffer, eth, 14);
    memcpy(&buffer[14], arp, 28);

    int bytes = send(sock, buffer, sizeof(buffer), 0);
    printf("%d byte ARP request sent on interface: %s\n\n",
           bytes, interfaces[sockIndex].name);

    /* Get response */
    int reply = 1;
    struct sockaddr_ll recvaddr;
    int recvaddrlen = sizeof(struct sockaddr_ll);
    while (reply) {
        // make this nonblocking, or set a timeout
        int n = recvfrom(sock, replyBuf, 1500, 0,
                         (struct sockaddr*)&recvaddr, &recvaddrlen);
        if(recvaddr.sll_pkttype == PACKET_OUTGOING) {
            printf("skipping outgoing packet\n");
            continue;
        }
        reply = 0;
        printf("Received ARP response. \n");
    }
    free(eth);
    free(arp);
    return 0;
}

void forwardICMP(char buf[1500], // packet contents
              struct fwdTable fTable[5],
              struct interface interfaces[6],
              char* addr,
              int j,
              int fwdRows) {
    char buffer[98];
    memcpy(&buffer, &buf[0], 98);
    /* Match for the interface of next hop,
     * determine socket to send on. */
    int sockIndex;
    int sock = 0;
    for (sockIndex = 0; sockIndex < fwdRows; sockIndex++) {
        if (memcmp(interfaces[sockIndex].name,
                   fTable[j].interfaceName, 7) == 0) {
            sock = interfaces[sockIndex].sockNum;
            break;
        }
    }

    char* tempBuf = (char*)malloc(42); //double ptr to hold reply
    char arpBuf[42];

    /* If the IP dest is outside this router's network. */
    if (memcmp(&fTable[j].nexthop, "-", 1) != 0) {
        printf("-Next hop: %s\n", fTable[j].nexthop);
        sendARPRequest(&tempBuf, fTable[j].nexthop,
                       interfaces, sock, sockIndex);

        /* If the IP dest is within this network. */
    } else if (memcmp(&fTable[j].nexthop, "-", 1) == 0) {
        char dest[10];
        strcpy(dest, addr);// from literal to char array
        printf("-Next hop(destination): %s\n", dest);
        sendARPRequest(&tempBuf, dest,
                       interfaces, sock, sockIndex);
    }

    /* Transfer and extract the ARP packet's ether header */
    memcpy(&arpBuf, &tempBuf, 42);
    struct ether_header* ethFwd = (struct ether_header*) arpBuf;
    memcpy(&ethFwd->ether_dhost, &ethFwd->ether_shost, 6);
    memcpy(&ethFwd->ether_shost, &interfaces[sockIndex].mac, 6);
    ethFwd->ether_type = htons(0x0800); // IPv4

    // print eth destination received from ARP reply
    printf("-DST MAC from ARP reply: %02X:%02X:%02X:%02X:%02X:%02X\n",
           ethFwd->ether_dhost[0],
           ethFwd->ether_dhost[1],
           ethFwd->ether_dhost[2],
           ethFwd->ether_dhost[3],
           ethFwd->ether_dhost[4],
           ethFwd->ether_dhost[5]
    );

    /* Populate buffer. IP and ICMP headers already in buffer */
    memcpy(&buffer[0], ethFwd, 14);
    int bytes = send(sock, buffer, sizeof(buffer), 0);
    printf("%d byte ICMP reply sent on interface: %s\n\n",
           bytes, interfaces[sockIndex].name);
}

int main() {
    int packet_socket;
    struct interface interfaces[6];
    fd_set sockets;
    FD_ZERO(&sockets);
    int i = 0;
    int fwdRows = 0;

    /* Read from provided forwarding table into ftables struct */
    struct fwdTable fTable[5];
    FILE *fp;
    char fileName[30];
    printf("Enter the file name of a forwarding table: \n");
    fgets(fileName, 30, stdin);
    fileName[strlen(fileName) - 1] = '\0';
    fp = fopen(fileName, "r");
    if (fp == NULL) {
        printf("File not found. \n");
        return 1;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t numChars;
    char str[50];
    while ((numChars = getline(&line, &len, fp)) != -1) {
        strcpy(str, line);
        strcpy(fTable[fwdRows].prefixAddr, strtok(str, "/"));
        strcpy(fTable[fwdRows].prefixBits, strtok(NULL, " "));
        strcpy(fTable[fwdRows].nexthop, strtok(NULL, " "));
        strcpy(fTable[fwdRows].interfaceName, strtok(NULL, "\n"));
        fwdRows++;
    }

    for (i = 0; i < fwdRows; i++) {
        printf("PrefixAddr: %s ", fTable[i].prefixAddr);
        printf("PrefixBits: %s ", fTable[i].prefixBits);
        printf("Nexthop: %s ", fTable[i].nexthop);
        printf("Interface: %s", fTable[i].interfaceName);
        printf("\n");
    }
    free(line);
    fclose(fp);

    /* Get linked list of interface addresses. Interface name is in
     * ifa_name, address is in ifa_addr. This will detect multiple
     * types of addresses on the same interface, so use the interface
     * name to pair them into the interface struct. */
    struct ifaddrs *ifaddr, *tmp;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 1;
    }
    //have the list, loop over the list
    i = 0;
    int j = 0;
    printf("\n");
    for (tmp = ifaddr; tmp != NULL; tmp = tmp->ifa_next) {
        //Check if this is a packet address, there will be one per
        //interface. There are IPv4 and IPv6 as well, but we don't care
        //about those for the purpose of enumerating interfaces. We can
        //use the AF_INET addresses in this list to get a list
        //of our own IP addresses
        if (tmp->ifa_addr->sa_family == AF_PACKET) {
            //printf("Interface: %s\n", tmp->ifa_name);

            //create a packet socket on interface r?-eth1
            if (!strncmp(&(tmp->ifa_name[3]), "eth", 3)) {
                printf("Creating Socket on interface %s\n", tmp->ifa_name);

                //create a packet socket
                //AF_PACKET makes it a packet socket
                //SOCK_RAW makes it so we get the entire packet
                //could also use SOCK_DGRAM to cut off link layer header
                //ETH_P_ALL indicates we want all (upper layer) protocols
                //we could specify just a specific one
                packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
                if (packet_socket < 0) {
                    perror("socket");
                    return 2;
                }
                //Bind the socket to the address, so we only get packets
                //received on this specific interface. For packet sockets, the
                //address structure is a struct sockaddr_ll (see the man page
                //for "packet"), but of course bind takes a struct sockaddr.
                //Here, we can use the sockaddr we got from getifaddrs (which
                //we could convert to sockaddr_ll if we needed to)
                if (bind(packet_socket, tmp->ifa_addr, sizeof(struct sockaddr_ll)) == -1) {
                    perror("bind");
                }

                struct sockaddr_ll *s = (struct sockaddr_ll *) tmp->ifa_addr;

                memcpy(&interfaces[i].mac, s->sll_addr, 6);

                interfaces[i].sockNum = packet_socket;
                interfaces[i].name = tmp->ifa_name; // assign name to interface
                FD_SET(packet_socket, &sockets);
                printf("Interface sock num: %d\n", interfaces[i].sockNum);
                i++;
            }
        } // end if AF_PACKET

        /* AF_INET packets come after AF_PACKET, and so iterate separately. */
        if (tmp->ifa_addr->sa_family == AF_INET) {
            if (!strncmp(&(tmp->ifa_name[3]), "eth", 3)) {

                struct sockaddr_in *ip = (struct sockaddr_in *) tmp->ifa_addr;
                unsigned char *ipaddr = (unsigned char *) &(ip->sin_addr.s_addr);

                u_int32_t in;
                memcpy(&interfaces[j].ip, &(ip->sin_addr.s_addr), 4);

                printf("For interface %s, my IP is: %d.%d.%d.%d\n",
                       tmp->ifa_name,
                       interfaces[j].ip[0],
                       interfaces[j].ip[1],
                       interfaces[j].ip[2],
                       interfaces[j].ip[3]
                );
                j++;
            }
        }
    } // end loop through interfaces
    freeifaddrs(ifaddr);

    /* Loop and receive packets. Each interface accords with a single
     * socket. This uses select to determine if a socket has received
     * data. */
    printf("----------Ready to receive now----------\n\n");
    while (1) {
        char buf[1500];
        struct sockaddr_ll recvaddr;
        int recvaddrlen = sizeof(struct sockaddr_ll);
        fd_set tmp_set = sockets;
        select(FD_SETSIZE, &tmp_set, NULL, NULL, NULL);
        int psock;
        for (psock = 0; psock < FD_SETSIZE; psock++) {
            if (FD_ISSET(psock, &tmp_set)) {
                //we can use recv, since the addresses are in the packet, but we
                //use recvfrom because it gives us an easy way to determine if
                //this packet is incoming or outgoing (when using ETH_P_ALL, we
                //see packets in both directions. Only outgoing can be seen when
                //using a packet socket with some specific protocol)
                int n = recvfrom(psock, buf, 1500, 0,
                                 (struct sockaddr *) &recvaddr, &recvaddrlen);
                //ignore outgoing packets (we can't disable some from being sent
                //by the OS automatically, for example ICMP port unreachable
                //messages, so we will just ignore them here)
                if (recvaddr.sll_pkttype == PACKET_OUTGOING) {
                    printf("Outgoing or incomplete packet dropped.\n");
                    continue;
                }

                /* Determine socket number, then move on */
                /* Do not change i for the rest of this psock */
                for (i = 0; i < 6; i++) {
                    if (interfaces[i].sockNum == psock)
                        break;
                }

                /* Begin processing all others. */
                /* Ether header can be extracted in advance. */
                printf("---Got a %d byte packet---\n", n);
                struct ether_header *eth = (struct ether_header *) buf;
                printf("Type: %x\n", eth->ether_type);
                /* --If ARP-- */
                if (ntohs(eth->ether_type) == 0x0806) {
                    struct arp_hdr arp; // Sender's data
                    memcpy(&arp, &buf[14], 28);

                    /* If ARP reply */
                    if (ntohs(arp.op) == 2) {
                        printf("-Detected ARP reply-\n");
                        // arp reply must be for me

                    }
                        /* If ARP request */
                    else if (ntohs(arp.op) == 1) {
                        printf("-Detected ARP request-\n");
                        printf("SENDER dst IP address: %d.%d.%d.%d\n",
                               arp.dip[0],
                               arp.dip[1],
                               arp.dip[2],
                               arp.dip[3]
                        );
                        printf("My IP address for eth%d: %d.%d.%d.%d\n",
                               i,
                               interfaces[i].ip[0],
                               interfaces[i].ip[1],
                               interfaces[i].ip[2],
                               interfaces[i].ip[3]
                        );

                        // check to see if I am the destination
                        if (memcmp(arp.dip, interfaces[i].ip, 4) == 0) {
                            printf("There was an ARP request for me!\n");
                            sendARPReply(buf, eth, arp, interfaces, psock, i);
                        }
                        // else if request not for me, ignore
                    }
                } // end if-ARP

                    /* --If ICMP-- */
                else if (recvaddr.sll_protocol == 8) { //ICMP
                    printf("-Detected ICMP packet-\n");
                    int matched = 1;
                    struct ip_hdr ip;
                    memcpy(&ip, &buf[14], 20);
                    struct icmp_hdr icmp;
                    memcpy(&icmp, &buf[14 + 20], 4);

                    unsigned char dstip[4];
                    memcpy(&dstip, &ip.dst, 4);

                    printf("SENDER dst IP address: %d.%d.%d.%d\n",
                           dstip[0],
                           dstip[1],
                           dstip[2],
                           dstip[3]
                    );
                    printf("My IP address for eth%d: %d.%d.%d.%d\n",
                           i,
                           interfaces[i].ip[0],
                           interfaces[i].ip[1],
                           interfaces[i].ip[2],
                           interfaces[i].ip[3]
                    );

                    int forme = 0; // acts as boolean
                    int r = 0;
                    /* Checks if packet destination is one of my
                     * interface IP addresses. */
                    for (r = 0; r < fwdRows; r++) {
                        if (memcmp(&dstip, &interfaces[r].ip, 4) == 0) {
                            forme = 1;
                            break;
                        }
                    }

                    if (forme == 1) {
                        printf("ICMP packet is for me!\n");
                        char buffer[98];
                        memcpy(&buffer, &buf[0], 98);
                        struct ether_header *ethReply;
                        struct ip_hdr ipReply; // 20
                        struct icmp_hdr icmpReply; // 4

                        /* Copy over headers */
                        memcpy(&ethReply, &eth, 14);
                        memcpy(&ipReply, &ip, 20);
                        memcpy(&icmpReply, &buf[(14 + 20)], 4);

                        /* Swap src/dst */
                        memcpy(&ethReply->ether_dhost, &eth->ether_shost, 6);
                        memcpy(&ethReply->ether_shost, &interfaces[i].mac, 6);
                        memcpy(&ipReply.dst, &ipReply.src, sizeof(ip.dst));
                        memcpy(&ipReply.src, &ip.dst, sizeof(ip.src));

                        /* Flip type (code is already 0) */
                        icmpReply.icmp_type = 0;
                        icmpReply.icmp_code = 0;
                        /*
                        printf("SENDER dst IP address: %d.%d.%d.%d\n",
                               dstip[0],
                               dstip[1],
                               dstip[2],
                               dstip[3]
                        );
                        */

                        /* Populate buffer */
                        memcpy(&buffer[0], ethReply, 14);
                        memcpy(&buffer[14], &ipReply, 20);
                        memcpy(&buffer[34], &icmpReply, 4);
                        int bytes = send(psock, buffer, sizeof(buffer), 0);
                        printf("%d byte ICMP reply sent on interface: %s\n\n",
                               bytes, interfaces[i].name);
                    }
                        /* Not for me, so forward if possible, else,
                         * drop and send error packet back to sender. */
                    else {
                        printf("ICMP packet is for someone else.\n");
                        // Check the checksum here, if fail, drop
                        ip.ttl--; // type 11
                        // decrement TTL, if zero as a result, send ICMP TTL exceeded, then drop
                        // Otherwise, recompute checksum

                        char *addr = (char *) malloc(10);
                        // Put int IP addr into sockaddr_in to utilize string
                        // formatting of inet_ntoa function.
                        struct sockaddr_in tempsock;
                        memcpy(&tempsock.sin_addr.s_addr, &ip.dst, 4);
                        addr = inet_ntoa(tempsock.sin_addr);

                        /* Compare ip_hdr dest with forwarding table.
                         * j is the row number (index) of the prefix in the
                         * forwarding table that matches the destination IP address.*/
                        int sock;
                        for (j = 0; j < fwdRows; j++) {
                            // number of chars in IP string(with dots)=num bytes*2
                            int cmpLen = (atoi(fTable[j].prefixBits) / 8) * 2;

                            if ((memcmp(addr, fTable[j].prefixAddr, cmpLen)) == 0) {
                                printf("Routing table match for prefix: %s\n",
                                       fTable[j].prefixAddr);
                                matched = 0;
                                break;
                            }
                        }

                        /* If prefix exists */
                        if (matched == 0) {
                            forwardICMP(buf, fTable, interfaces, addr, j, fwdRows);
                        } else {
                            printf("ICMP error - destination does not exist.\n");
                            // send ICMP error message back to sender
                        }
                        //free(addr);
                    }
                }
            }
        }// end select loop
    }// end while(1)
    return 0;
}// end main