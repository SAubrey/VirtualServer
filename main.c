#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <string.h>

/* Sean Aubrey
 * CIS 457
 */
struct ftable {
    char prefix[19];
    char nexthop[16];
    char interface[8];
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
    unsigned char icmp_type;     //
    unsigned char icmp_code;     // 0 if echo reply
    unsigned short int icmp_sum; // checksum
};

int main() {
    int packet_socket;
    struct interface interfaces[6];
    fd_set sockets; // could put sockets, file, stdin/stdout in here
    FD_ZERO(&sockets); // initialize, nothing in there yet

    //get list of interface addresses. This is a linked list. Next
    //pointer is in ifa_next, interface name is in ifa_name, address is
    //in ifa_addr. You will have multiple entries in the list with the
    //same name, if the same interface has multiple addresses. This is
    //common since most interfaces will have a MAC, IPv4, and IPv6
    //address. You can use the names to match up which IPv4 address goes
    //with which MAC address.

    /* Read from provided forwarding table into ftables struct */
    /*
    struct ftable ftables[5];
    FILE* fp;
    char fileName[30];
    printf("Enter the file name of a forwarding table: \n");
    fgets(fileName, 30, stdin);
    fp = fopen(fileName, "r");
    if (fp == NULL) {
        printf("File not found. \n");
        return 1;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t numChars;
    char str[50];
    int i = 0;
    while ((numChars = getline(&line, &len, fp)) != -1) {
        //printf("Retrieved line of length %zu :\n", read);
        //printf("%s", line);
        strcpy(str, line);
        str[numChars] = '\0';
        strcpy(ftables[i].prefix, strtok(str, " "));
        strcpy(ftables[i].nexthop, strtok(NULL, " "));
        strcpy(ftables[i].interface, strtok(NULL, "\n"));
        i++;
        printf("%s\n", ftables[i].interface);
    }
    free(line);
    fclose(fp);
    */

    struct ifaddrs *ifaddr, *tmp;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 1;
    }
    //have the list, loop over the list
    int i = 0;
    int j = 0;
    for (tmp = ifaddr; tmp != NULL; tmp = tmp->ifa_next) {
        //Check if this is a packet address, there will be one per
        //interface.  There are IPv4 and IPv6 as well, but we don't care
        //about those for the purpose of enumerating interfaces. We can
        //use the AF_INET addresses in this list for example to get a list
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
                //recieved on this specific interface. For packet sockets, the
                //address structure is a struct sockaddr_ll (see the man page
                //for "packet"), but of course bind takes a struct sockaddr.
                //Here, we can use the sockaddr we got from getifaddrs (which
                //we could convert to sockaddr_ll if we needed to)
                if (bind(packet_socket, tmp->ifa_addr, sizeof(struct sockaddr_ll))==-1){
                    perror("bind");
                }

                struct sockaddr_ll* s = (struct sockaddr_ll *) tmp->ifa_addr;

                //interfaces[i].mac = (s->sll_addr);
                memcpy(&interfaces[i].mac, s->sll_addr, 6);
                /*
                printf("My MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                       interfaces[i].mac[0],
                       interfaces[i].mac[1],
                       interfaces[i].mac[2],
                       interfaces[i].mac[3],
                       interfaces[i].mac[4],
                       interfaces[i].mac[5]
                );
                 */
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
                memcpy(&in, &(ip->sin_addr.s_addr), 4);

                interfaces[j].ip[0] = in & 0xFF;
                interfaces[j].ip[1] = (in >> 8) & 0xFF;
                interfaces[j].ip[2] = (in >> 16) & 0xFF;
                interfaces[j].ip[3] = (in >> 24) & 0xFF;

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

    //loop and receive packets. We are only looking at one interface,
    //for the project you will probably want to look at more (to do so,
    //a good way is to have one socket per interface and use select to
    //see which ones have data)
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
                    printf("Outgoing packet - dismissed.\n");
                    continue;
                }

                /* Determine socket number, then move on */
                /* Do not change i for the rest of this psock */
                for (i = 0; i < 6; i++) {
                    if (interfaces[i].sockNum == psock) {
                        //printf("sock match! sockNum: %d, i: %d\n", psock, i);
                        break;
                    }
                }

                /* Begin processing all others. */
                /* Ether header can be extracted in advance. */
                printf("--Got a %d byte packet--\n", n);
                struct ether_header *eth = (struct ether_header *) buf;

                /* If ARP */
                if (ntohs(eth->ether_type) == 0x0806) {
                    struct arp_hdr arp; // Sender's data
                    memcpy(&arp, &buf[14], 28);

                    // if arp reply
                    if(ntohs(arp.op) == 2) {
                        printf("-Detected ARP reply-\n");
                    }
                    else if (ntohs(arp.op) == 1) {
                        printf("-Detected ARP request-\n");
/*
                        printf("SENDER IP address: %d.%d.%d.%d\n",
                               arp.sip[0],
                               arp.sip[1],
                               arp.sip[2],
                               arp.sip[3]
                        );
                        */
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
                        /*
                        printf("Sender's DST MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                               eth->ether_dhost[0],
                               eth->ether_dhost[1],
                               eth->ether_dhost[2],
                               eth->ether_dhost[3],
                               eth->ether_dhost[4],
                               eth->ether_dhost[5]
                        );
                         */
                        // check to see if I am the destination
                        if (memcmp(arp.dip, interfaces[i].ip, 4) == 0) {
                            printf("There was an ARP request for me!\n");

                            char buffer[42]; // 28 + 14
                            struct ether_header *ethReply;
                            struct arp_hdr arpReply;

                            /* Copy over headers, then modify */
                            memcpy(&ethReply, &eth, 14); // & ?????
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
/*
                            printf("DST eth MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                                   ethReply->ether_dhost[0],
                                   ethReply->ether_dhost[1],
                                   ethReply->ether_dhost[2],
                                   ethReply->ether_dhost[3],
                                   ethReply->ether_dhost[4],
                                   ethReply->ether_dhost[5]
                            );
                            printf("DST arp MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                                     arpReply.dha[0],
                                     arpReply.dha[1],
                                     arpReply.dha[2],
                                     arpReply.dha[3],
                                     arpReply.dha[4],
                                     arpReply.dha[5]
                            );
                            printf("MY eth MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                                   ethReply->ether_shost[0],
                                   ethReply->ether_shost[1],
                                   ethReply->ether_shost[2],
                                   ethReply->ether_shost[3],
                                   ethReply->ether_shost[4],
                                   ethReply->ether_shost[5]
                            );
                            printf("MY arp MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                                   arpReply.sha[0],
                                   arpReply.sha[1],
                                   arpReply.sha[2],
                                   arpReply.sha[3],
                                   arpReply.sha[4],
                                   arpReply.sha[5]
                            );
                            printf("DST IP: %d.%d.%d.%d\n",
                                   arpReply.dip[0],
                                   arpReply.dip[1],
                                   arpReply.dip[2],
                                   arpReply.dip[3]
                            );
                            printf("SRC IP: %d.%d.%d.%d\n",
                                   arpReply.sip[0],
                                   arpReply.sip[1],
                                   arpReply.sip[2],
                                   arpReply.sip[3]
                            );
*/
                            int bytes = send(psock, buffer, sizeof(buffer), 0);
                            printf("%d byte ARP reply sent on interface: %s\n\n",
                                   bytes, interfaces[i].name);
                        }
                        // else if not, forward

                    }
                } // end if-ARP

                /* If ICMP */
                else if (recvaddr.sll_protocol == 8) { //ICMP
                    printf("-Detected ICMP packet-\n");
                    struct ip_hdr ip;
                    memcpy(&ip, &buf[14], 20);
                    struct icmp_hdr icmp;
                    memcpy(&icmp, &buf[14 + 20], 4);

                    printf("Sender's SRC MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                           eth->ether_shost[0],
                           eth->ether_shost[1],
                           eth->ether_shost[2],
                           eth->ether_shost[3],
                           eth->ether_shost[4],
                           eth->ether_shost[5]
                    );
                    printf("My MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                           interfaces[i].mac[0],
                           interfaces[i].mac[1],
                           interfaces[i].mac[2],
                           interfaces[i].mac[3],
                           interfaces[i].mac[4],
                           interfaces[i].mac[5]
                    );

                    // ip.ttl--; // time exceeded? type 11
                    unsigned char packip[4];
                    unsigned int tempdst = ip.dst;

                    packip[0] = (unsigned char)tempdst & 0xFF;
                    packip[1] = (unsigned char)(tempdst >> 8) & 0xFF;
                    packip[2] = (unsigned char)(tempdst >> 16) & 0xFF;
                    packip[3] = (unsigned char)(tempdst >> 24) & 0xFF;

                    printf("SENDER dst IP address: %d.%d.%d.%d\n",
                           packip[0],
                           packip[1],
                           packip[2],
                           packip[3]
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
                    for (r = 0; r < 2; r++) {
                        if (memcmp(&packip, &interfaces[r].ip, 4) == 0) {
                            forme = 1;
                            break;
                        }
                    }

                    if (forme == 1) {
                        printf("ICMP packet is for me!\n");
                        char buffer[98];
                        memcpy(&buffer, &buf[0], 98);
                        struct ether_header* ethReply;
                        struct ip_hdr ipReply; // 20
                        struct icmp_hdr icmpReply; // 4

                        /* Copy over headers, then modify */
                        memcpy(&ethReply, &eth, 14);
                        memcpy(&ipReply, &ip, 20);
                        memcpy(&icmpReply, &buf[(14 + 20)], 4);

                        /* Swap src/dst */
                        memcpy(&ethReply->ether_dhost, &eth->ether_shost, 6);
                        memcpy(&ethReply->ether_shost, &interfaces[i].mac, 6);
                        memcpy(&ipReply.dst, &ipReply.src, sizeof(ip.dst));
                        memcpy(&ipReply.src, &ip.dst, sizeof(ip.src));

                        /* flip type (code is already 0) */
                        icmpReply.icmp_type = 0;
                        icmpReply.icmp_code = 0;

                        printf("MY eth MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                               ethReply->ether_shost[0],
                               ethReply->ether_shost[1],
                               ethReply->ether_shost[2],
                               ethReply->ether_shost[3],
                               ethReply->ether_shost[4],
                               ethReply->ether_shost[5]
                        );
                        printf("DST eth MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                               ethReply->ether_dhost[0],
                               ethReply->ether_dhost[1],
                               ethReply->ether_dhost[2],
                               ethReply->ether_dhost[3],
                               ethReply->ether_dhost[4],
                               ethReply->ether_dhost[5]
                        );
                        /*
                        tempdst = ipReply.dst;
                        packip[0] = (unsigned char)tempdst & 0xFF;
                        packip[1] = (unsigned char)(tempdst >> 8) & 0xFF;
                        packip[2] = (unsigned char)(tempdst >> 16) & 0xFF;
                        packip[3] = (unsigned char)(tempdst >> 24) & 0xFF;
                        printf("SENDER dst IP address: %d.%d.%d.%d\n",
                               packip[0],
                               packip[1],
                               packip[2],
                               packip[3]
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
                    // if not
                }
            }
        }

        //what else to do is up to you, you can send packets with send,
        //just like we used for TCP sockets (or you can use sendto, but it
        //is not necessary, since the headers, including all addresses,
        //need to be in the buffer you are sending)

    }// end while(1)
    //exit
    return 0;
} // end main