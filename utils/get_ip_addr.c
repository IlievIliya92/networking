/******************************** INCLUDE FILES *******************************/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

/********************************** DEFINES ***********************************/
#define TRUE 1
#define FALSE 0

typedef int bool_t;
/********************************* LOCAL DATA *********************************/

/******************************* INTERFACE DATA *******************************/

/******************************* LOCAL FUNCTIONS ******************************/

/***************************** INTERFACE FUNCTIONS ****************************/
static bool_t getInterfaceIpV4(const char *interface, struct sockaddr_in *addr_out)
{
  bool_t success = FALSE;
  struct ifaddrs *ifap, *ifa;

  /* Get the IP address of the interface */
  if (getifaddrs(&ifap) == 0)
  {
    for (ifa = ifap; ifa; ifa = ifa->ifa_next)
    {
      if (ifa->ifa_addr->sa_family == AF_INET)
      {
        if(strcmp(ifa->ifa_name, interface) == 0)
        {
          *addr_out = *((struct sockaddr_in *) ifa->ifa_addr);
          success = TRUE;
          break;
        }
      }
    }
    freeifaddrs(ifap);
  }

  return success;
}


/***************************** MAIN ****************************/
int main(int argc, char *argv[])
{
  struct sockaddr_in addr_out;
  bool_t ret = FALSE;
  char ipStr[INET_ADDRSTRLEN];

  if (2 != argc) {
      fprintf(stdout, "usage: ./a.out [interface] \n");

      return -1;
  }

  const char *interface = argv[1];

  ret = getInterfaceIpV4(interface, &addr_out);
  if (ret)
  {
    // now get it back and print it
    inet_ntop(AF_INET, &(addr_out.sin_addr), ipStr, INET_ADDRSTRLEN);

    fprintf(stdout, "%s ip : %s\n", interface, ipStr);
  }
  else
  {
    fprintf(stderr, "Failed to get ip of %s", interface);
    return -1;
  }


  return 0;
}

