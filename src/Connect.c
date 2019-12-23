
#include<stdio.h>
#include<stdlib.h>
#include<mysql/mysql.h>

static char *host = "localhost";
static char *user = "Newuser";

static char *pass = "123456";//need be changed
static char *dbname = "information_schema";//need be changed


unsigned int port = 3306;

static char* unix_socket = NULL;

unsigned int flag = 0;


int main(int argc, char const *argv[])
{
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;

    conn = mysql_init(NULL);

    if(!(mysql_real_connect(conn,host,user,pass,dbname,port,unix_socket,flag)))
    {
        fprintf(stderr, "\nError: %s [%d]\n",mysql_error(conn),mysql_errno(conn));
        exit(1);
	}

    mysql_query(conn, "SELECT * FROM users");

    res = mysql_store_result(conn);

    while(row = mysql_fetch_row(res))
    {
        printf("%s\t%s\t%s\n", row[0], row[1], row[2]);
    }

    mysql_free_result(res);
    mysql_close(conn);
    
    return EXIT_SUCCESS;
}

