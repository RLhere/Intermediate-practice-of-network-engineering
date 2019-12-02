
#include<stdio.h>
#include<stdlib.h>
#include<mysql/mysql.h>

static char *host = "localhost";
static char *user = "unix";

static char *pass = "TBBZ3F";//need be changed
static char *dbname = "sys";//need be changed


unsigned int port = 3306;

static char* unix_socket = NULL;

unsigned int flag = 0;


int main(int argc, char const *argv[])
{
    MYSQL *conn;
    conn = mysql_init(NULL);
    if(!(mysql_real_connect(conn,host,user,pass,dbname,port,unix_socket,flag)))
    {
        fprintf(stderr, "\nError: %s [%d]\n",mysql_error(conn),mysql_errno(conn));
        exit(1);
    }
    printf("Connect Successful!\n\n");

    return EXIT_SUCCESS;
}

