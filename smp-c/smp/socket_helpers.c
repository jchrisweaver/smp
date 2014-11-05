//
//  socket_helpers.c
//  Smp
//
//  Created by Chris Weaver on 9/26/14.
//  www.chrisweaver.com
//
//  This work is highly based off Shane Tully's Python SMP implementation found here:
//  https://shanetully.com/2013/08/mitm-protection-via-the-socialist-millionaire-protocol-otr-style/
//
//  Use feel free to use this code however you like, royalty free.
//  If you do use it, please consider letting me know with a tweet at at @jchrisweaver
//

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "socket_helpers.h"
#include "utils.h"

int connect_to_server( char* serverIP )
{
    struct sockaddr_in serv_addr;
    int sockfd = 0;
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return 1;
    }
    
    memset(&serv_addr, '0', sizeof(serv_addr));
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(5000);
    
    if(inet_pton(AF_INET, serverIP, &serv_addr.sin_addr)<=0)
    {
        printf("\n inet_pton error occured\n");
        return 1;
    }
    
    if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\n Error : Connect Failed \n");
        return 1;
    }
    return sockfd;
}

unsigned int revc_from_server( int sockfd, unsigned char* recvBuff, unsigned int buf_len )
{
    int msg_len = 0;    // first 4 bytes recvd
    ssize_t n = 0;
    while ( ( n = read( sockfd, recvBuff, buf_len ) ) > 0 )
    {
        recvBuff[n] = 0;
        
        if ( msg_len == 0 )
        {
            // first 4 bytes are length
            msg_len = big2littleEndian( *( ( unsigned int * )recvBuff ) );
        }
        if ( n >= msg_len )
            break;
    }
    
    if( n < 0 )
    {
        printf("\n Read error \n");
        return -1;
    }
    
    memmove( recvBuff, ( recvBuff + 4 ), n - 1);
    * ( recvBuff + n - 1 ) = 0x00;
    return (unsigned int) ( n - 4 );
}

void disconnect_from_server( int sockfd )
{
    close( sockfd );
}

unsigned int write_to_server( int connfd, unsigned char* sendBuff, unsigned int buf_len )
{
    unsigned char buffer[ 4048 ];
    *( ( unsigned int * )buffer ) = little2bigEndian( buf_len + sizeof( unsigned int) );
    memcpy( ( buffer + 4), sendBuff, buf_len );
    ssize_t len = write( connfd, buffer, 4 + buf_len ); // only ONE write
    return ( int )len;
}

int listen_server( int argc, char *argv[] )
{
    int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr;
    
    listenfd = socket( AF_INET, SOCK_STREAM, 0 );
    memset( &serv_addr, '0', sizeof( serv_addr ) );
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl( INADDR_ANY );
    serv_addr.sin_port = htons( 5000 );
    
    bind( listenfd, ( struct sockaddr* )&serv_addr, sizeof( serv_addr ) );
    
    listen( listenfd, 10 );
    
    while( connfd == 0 )
    {
        connfd = accept( listenfd, ( struct sockaddr* ) NULL, NULL);
        sleep( 1 );
    }
    return connfd;
}
