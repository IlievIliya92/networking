/*C program to format/extract ip address octets.*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Function : extractIpAddress
Arguments :
1) sourceString - String pointer that contains ip address
2) ipAddress - Target variable short type array pointer that will store ip address octets
*/

void extractIpAddress(unsigned char *sourceString,short *ipAddress)
{
    unsigned short len=0;
    unsigned char  oct[4]={0},cnt=0,cnt1=0,i,buf[5];

    len=strlen(sourceString);
    for(i=0;i<len;i++)
    {
        if(sourceString[i]!='.'){
            buf[cnt++] =sourceString[i];
        }
        if(sourceString[i]=='.' || i==len-1){
            buf[cnt]='\0';
            cnt=0;
            oct[cnt1++]= atoi(buf);
        }
    }
    ipAddress[0]=oct[0];
    ipAddress[1]=oct[1];
    ipAddress[2]=oct[2];
    ipAddress[3]=oct[3];
}

int main()
{
    unsigned char *ip= "192.168.205.146";
    short ipAddress[4];

    int test_ip_roller[10];

    printf("Enter IP Address (xxx.xxx.xxx.xxx format): ");

    int  i = 0;

    for (i = 3; i > -1; i--)
        printf("I %d\n", i);

    extractIpAddress(ip, ipAddress);

    printf("\nIp Address: %03d.%03d.%03d.%03d\n",ipAddress[0],ipAddress[1],ipAddress[2],ipAddress[3]);

    test_ip_roller[0] = ipAddress[3] % 10;
    ipAddress[3] /= 10;
    test_ip_roller[1] = ipAddress[3] % 10;
    ipAddress[3] /= 10;
    test_ip_roller[2] = ipAddress[3] % 10;


    for (int i = 0; i < 3; i++)
        printf("IP: %d\n", test_ip_roller[i]);

    return 0;
}
