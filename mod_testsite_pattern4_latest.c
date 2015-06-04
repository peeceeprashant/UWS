/*
 *  mod_testsite.c
 *  
*/

/*
 * Header Files
*/

#include "http_protocol.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_connection.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include <apr_network_io.h>
#include "util_ebcdic.h"
#include "apr_hash.h"
#include "apr_thread_mutex.h"
#include "apr_time.h"
#include "ap_mpm.h"
#include "string.h"


/*
 * Function Declaration
*/
static int printConf(request_rec *r);
module AP_MODULE_DECLARE_DATA testsite_module;


/*
 * Global Parameters
*/

/* default listen port number */
#define DEF_LISTEN_PORT         80
/* default socket backlog number. SOMAXCONN is a system default value */
#define DEF_SOCKET_BACKLOG      SOMAXCONN
/* default buffer size */
#define BUFSIZE                 4096
/* useful macro */
#define CRLF_STR                "\r\n"
/* default connect hostname */
#define DEF_REMOTE_HOST         "10.185.39.246"
/* default connect port number */
#define DEF_REMOTE_PORT         8080
/* default socket timeout */
#define DEF_SOCK_TIMEOUT        (APR_USEC_PER_SEC * 30)
/* default buffer size */
#define BUFSIZE                 4096
/* useful macro */
#define CRLF_STR                "\r\n"

#define HEADEREND CRLF CRLF
#define ASCII_ZERO  "\060"
#define ASCII_CRLF  "\015\012"
const char *srv ;
apr_table_t  *mytable=NULL;

static int do_connect(apr_socket_t **sock, apr_pool_t *mp, request_rec *r);
static char* do_client_task(apr_socket_t *sock, const char *filepath, apr_pool_t *mp, request_rec *r);

static char* func1(request_rec *r) {
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "In func: func1");
  apr_status_t rv;
  apr_pool_t *mp;
  apr_socket_t *s;

  apr_initialize();
  apr_pool_create(&mp, NULL);
  rv = do_connect(&s, mp, r);
  if (rv != APR_SUCCESS) {
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"func1: Connection to Tomcat Server (Sitestory/Memento Server) failed");
      goto error;
  }
 
  char *uri =  r->unparsed_uri;
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"mod_sitestory: added mod_sitestory for request  %s",uri) ;
  //char *rObject = do_client_task(s, "/sitestory/timegate/http://10.147.151.224:80/index3.html", mp, r);
  //char *rObject = do_client_task(s, "/sitestory/timegate/http://localhost/externcsshtml.html", mp, r);
  //char *rObject = do_client_task(s, "/sitestory/timegate/http://localhost/dlib.html", mp, r);
  
  //char *rObject = do_client_task(s, "/sitestory/timegate/http://50.17.155.79/externcsshtml.html", mp, r);
  char* tUrl = "/sitestory/timegate/http://";
  char* fUrl = apr_pstrcat(r->pool,tUrl,r->hostname,r->uri,NULL);  
  char* rObject = do_client_task(s, fUrl, mp, r);
  //apr_socket_close(s);

  //char *finalResult  = do_client_task(s, mementoUrl, mp, r);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"func1: rObject:  %d", rObject);
  char *finalResult = rObject;
 
  //Processing Memento
  //char *htmlBody = strstr(mementoUrl, "<html");
  char *htmlBody = strstr(finalResult, "<html");
  if(htmlBody == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"func1: htmlBody is NULL") ;
    char *htmlBody = strstr(finalResult, "HTML");
  }else {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"func1: htmlBody is not NULL") ;
  }
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"func1: htmlBody:  %s", htmlBody) ;
  //End of Processing of Memento

  apr_socket_close(s);
  //End of Memento Request

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"func1: finalResult:  %s", finalResult);

  apr_pool_destroy(mp);
  apr_terminate();
  return htmlBody;
  error: {
    char errbuf[256];
    apr_strerror(rv, errbuf, sizeof(errbuf));
    printf("error: %d, %s\n", rv, errbuf);
  }
  apr_terminate();
  return 1;
}

/**
 * Connect to the remote host
 */
static apr_status_t do_connect(apr_socket_t **sock, apr_pool_t *mp, request_rec *r)
{
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_connect: Enter Function");
  apr_sockaddr_t *sa;
  apr_socket_t *s;
  apr_status_t rv;

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_connect: Info Get");
  rv = apr_sockaddr_info_get(&sa, DEF_REMOTE_HOST, APR_INET, DEF_REMOTE_PORT, 0, mp);
  if (rv != APR_SUCCESS) {
    return rv;
  }

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_connect: Sock Create");
  rv = apr_socket_create(&s, sa->family, SOCK_STREAM, APR_PROTO_TCP, mp);
  if (rv != APR_SUCCESS) {
    return rv;
  }

  /* it is a good idea to specify socket options explicitly.
   * in this case, we make a blocking socket with timeout. */
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_connect: Opt Set");
  apr_socket_opt_set(s, APR_SO_NONBLOCK, 1);
 
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_connect: Timeout Set");
  apr_socket_timeout_set(s, DEF_SOCK_TIMEOUT);

  rv = apr_socket_connect(s, sa);
  if (rv != APR_SUCCESS) {
      return rv;
  }

  /* see the tutorial about the reason why we have to specify options again */
  apr_socket_opt_set(s, APR_SO_NONBLOCK, 0);
  apr_socket_timeout_set(s, DEF_SOCK_TIMEOUT);

  *sock = s;
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_connect: Leaving Function");
  return APR_SUCCESS;
}

/**
 * Send a request as a simple HTTP request protocol.
 * Write the received response to the standard output until the EOF.
 */

static char* do_client_task(apr_socket_t *sock, const char *filepath, apr_pool_t *mp, request_rec *r)
{ 
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Enter Function"); 
  apr_sockaddr_t *sa;
  apr_socket_t *s;
  apr_status_t rv;

  const char *req_hdr = apr_pstrcat(mp, "GET ", filepath, " HTTP/1.0" CRLF_STR CRLF_STR, NULL);
  apr_size_t len = strlen(req_hdr);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Request: %s", req_hdr);
  if(sock == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Sock NULL");
  } else {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Sock Not NULL");
  }

  rv = apr_socket_send(sock, req_hdr, &len);
  if (rv != APR_SUCCESS) {
    return rv;
  }

  char *bufRSPC;
  char* final;
  apr_size_t count = 0;
  char *temp = "";
  {
    //apr_file_t *stdout;
    //apr_file_open_stdout(&stdout, mp);
    while (1) {
      char buf[BUFSIZE];
      apr_size_t len2 = sizeof(buf);
      len2 = len2 - 1;
      apr_status_t rv = apr_socket_recv(sock, buf, &len2);
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Buffer Length %d", len2);
      if (rv == APR_EOF || len2 == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: While-If");
        break;
      }

      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Buffer Length 2 %d", len2); 
      buf[len2] = '\0';
      len2 = len2+1;
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Buffer Length 3 %d", len2);
      //apr_file_write(stdout, buf, &len2);
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Buffer Length 4 %d", len2);
    
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Length %d", len2);
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Buffer %s", buf);
      char *beforeTemp = apr_palloc(r->pool, sizeof(char)*(count));
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: temp : %s", temp);
      //strcpy(beforeTemp, temp); 
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Temp Bytes %d", count);
      apr_cpystrn(beforeTemp, temp, count);
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: beforeTemp2 : %s", beforeTemp);      

      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Length %d", len2);
      temp = apr_palloc(r->pool, sizeof(char)*(count+len2)); 
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Length %d", len2);

      //strcpy(temp, beforeTemp);
      apr_cpystrn(temp, beforeTemp, (count+len2));
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Length %d", len2);
      strcat(temp, buf);
      //apr_pstrcat(r->pool, *temp, *buf);
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Count Before %d", count);
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Length %d", len2);
      count = count + len2;
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Count After %d", count);
      final = temp;
 
      //bufRSPC = &buf;
      //ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Buffer %s", bufRSPC);
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Count As Of Now : %d", count);
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Final As Of Now : %s", final);
    }
    //apr_file_close(stdout);
  }

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Final Value : %s", final);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "do_client_task: Leaving Function");
  return final;
}


static char* myta_pre_conn(request_rec *r) {
  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,"In func: myta_pre_conn", r->filename);
  srv = ap_get_server_name(r);
  char *line;
  char *req_line;
  char *protocolstr;
  //conf=ap_get_module_config(r->per_dir_config, &testsite_module);
  req_line=apr_pstrdup(r->pool, r->the_request);
  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,"Requested URI: r->request: %s", req_line);
  
  return req_line;
}


int set_headers( void *req, apr_table_t *tab ) {
  request_rec *r = (request_rec *) req;
  
  //apr_table_set(r->headers_out, "Content-Location", pathname) ;
  //apr_table_set(r->headers_out, "Location", pathname) ;
  //apr_table_unset(r->headers_out, "Content-Length") ;
  //apr_table_unset(r->headers_out, "Content-Type") ;
  //r->status = HTTP_CREATED ;
  //r->status = HTTP_TEMPORARY_REDIRECT ;	// 307
  r->status = 200;
  return 0;
}

static int printitem(void* rec, const char* key, const char* value) {
  /* rec is a userdata pointer.  We'll pass the request_rec in it */
  request_rec* r = rec ;
  ap_rprintf(r, "<tr><th scope=\"row\">%s</th><td>%s</td></tr>\n",
	ap_escape_html(r->pool, key), ap_escape_html(r->pool, value)) ;
  /* Zero would stop iterating; any other return value continues */
  return 1 ;
}
static void printtable(request_rec* r, apr_table_t* t,
	const char* caption, const char* keyhead, const char* valhead) {

  /* print a table header */
  ap_rprintf(r, "<table><caption>%s</caption><thead>"
	"<tr><th scope=\"col\">%s</th><th scope=\"col\">%s"
	"</th></tr></thead><tbody>", caption, keyhead, valhead) ;

  /* Print the data: apr_table_do iterates over entries with our callback */
  apr_table_do(printitem, r, t, NULL) ;

  /* and finish the table */
  ap_rputs("</tbody></table>\n", r) ;
}

static int printRequestInfo(request_rec *r) {
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"the request: %s", r->the_request);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"protocol: %s", r->protocol);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"hostname: %s", r->hostname);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"status line: %s", r->status_line);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"method: %s", r->method);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"range: %s", r->range);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"content type: %s", r->content_type);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"R handler: %s", r->handler);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"Content encoding: %s", r->content_encoding);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"vlist_validator: %s", r->vlist_validator);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"user: %s", r->user);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"ap auth type: %s", r->ap_auth_type);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"unparsed uri: %s", r->unparsed_uri);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"uri: %s", r->uri);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"filename: %s", r->filename);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"canonical filename: %s", r->canonical_filename);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"path info: %s", r->path_info);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"args: %s", r->args);
  
  return 1;
}
static int uws_module_handler(request_rec *r)
{
   ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"Request handler (r->handler) is NULL");
  //concatAtt(r);
  if(r->handler == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"Request handler (r->handler) is NULL");
    return DECLINED;
  } else {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"R handler: %s", r->handler);  
    if(!strcmp(r->handler, "horcruxes")) {
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"Function: failsafe activated");
      char *req_line = myta_pre_conn(r);
      request_rec* rprev = r->prev;
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"Function: Previous Hostname : %s", rprev->hostname);
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"Function: Previous Unparsed URI : %s", rprev->unparsed_uri);
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"Function: Previous URI : %s", rprev->uri);
      char* rObject = func1(rprev);
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"Archived Copy : %s", rObject);
      r->content_type = "text/html";
      set_headers(r, r->headers_out);
      if(!r->header_only) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,"Function: Finally Done"); 
        ap_rputs(rObject, r);
      }
      return OK;
    } else {
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r," UWS is not processing the request");
      return DECLINED;
    }//End of "strcmp"
  }//End of "r->handler == NULL"
}//End of function

static void myta_register_hooks(apr_pool_t *p)
{ 
  //ap_register_output_filter("SWAP", swap_filter, NULL,  AP_FTYPE_CONTENT_SET);
  ap_hook_handler(uws_module_handler, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA testsite_module = {
  STANDARD20_MODULE_STUFF,
  NULL,      /* dir config creater */
  NULL,           /* dir merger --- default is to override */
  NULL,  /* server config */
  NULL,         /* merge server configs */
  NULL,
  myta_register_hooks  /* register hooks */
};
