//
//  socket_helpers.h
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

#ifndef __Smp__socket_helpers__
#define __Smp__socket_helpers__

int connect_to_server( char *server );
unsigned int revc_from_server( int sockfd, unsigned char* recvBuff, unsigned int buf_len );
void disconnect_from_server( int sockfd );
unsigned int write_to_server( int connfd, unsigned char* sendBuff, unsigned int buf_len );
int listen_server( void );


#endif /* defined(__Smp__socket_helpers__) */
