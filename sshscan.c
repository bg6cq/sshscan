#include "sshscan.h"

unsigned int nproc = 10;
unsigned long timeout = 3;
FILE *fp;
unsigned int wlen = 0;
uint32_t n = 0;
char buff[MAX_WORD_SIZE];
uint8_t verbose = 0;
uint32_t port = 22;
int scan_times = 0;
int retry = 5;
int exit_when_success = 1;

const unsigned int d_nproc = 10;
const unsigned long d_timeout = 3;

void help(){
    printf("\nMultithreaded SSH scan tool for one host ip\n");
    printf("Use: sshscan [OPTIONS] [USER_PASSW FILE] [HOST IP]\n");
    printf("Options:\n");
    printf("\t-t [NUMTHREADS]: Change the number of threads used. Default is %d\n", d_nproc);
    printf("\t-s [TIMEOUT]: Change the timeout for the connection in seconds. Default is %ld\n", d_timeout);
    printf("\t-p [PORT]: Specify another port to connect to\n");
    printf("\t-r [RETRY]: Specify retry times when error, Default is %d\n", retry);
    printf("\t-e : do not exit when success\n");
    printf("\t-h : Show this help\n");
    printf("\t-v : Verbose mode\n");

}
void to_bytes(uint32_t val, uint8_t *bytes){
    bytes[0] = (uint8_t) val;
    bytes[1] = (uint8_t) (val >> 8);
    bytes[2] = (uint8_t) (val >> 16);
    bytes[3] = (uint8_t) (val >> 24);
}

char *ip2str(uint32_t val)
{
    char *buf;
    size_t sz;
    uint8_t ipblock[4] = {0,0,0,0};
    to_bytes(val, ipblock);
    sz = snprintf(NULL, 0, "%d.%d.%d.%d", ipblock[0],ipblock[1],ipblock[2],ipblock[3]);
    buf = (char *) malloc(sz + 1); /* make sure you check for != NULL in real code */
    snprintf(buf, sz+1, "%d.%d.%d.%d", ipblock[0],ipblock[1],ipblock[2],ipblock[3]);
    return (char *)buf;
}

int parseip(char *subnet_str, uint32_t *prefix){
    int result;
    uint8_t ipbytes[4] = {0,0,0,0};

    result = sscanf(subnet_str, "%hhd.%hhd.%hhd.%hhd", &ipbytes[0], &ipbytes[1], &ipbytes[2], &ipbytes[3]);
    if (result < 0 ) return result;
    else{
        *prefix = 0x00;
        *prefix = ipbytes[0] | (ipbytes[1] << 8) | (ipbytes[2] << 16) | (ipbytes[3] << 24);
        return result;
    }
}

int ConnectSSH(int jobid, uint32_t ipaddr, char* user, char *passwd){
    int return_val = -1;    
    ssh_session my_ssh_session;
    int rc;
    
    scan_times ++;
    if (verbose) printf(ANSI_COLOR_BOLD"JOB %4d [%s]"ANSI_COLOR_ENDC" Trying with user:%s  pass:%s\n",jobid, ip2str(ipaddr),user,passwd);
    int retries = 0;
    while(1) {
        // Open session and set options
        my_ssh_session = ssh_new();
        if (my_ssh_session == NULL)
            return return_val;
        ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, ip2str(ipaddr));
        ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, user);
        ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);
        ssh_options_set(my_ssh_session, SSH_OPTIONS_TIMEOUT, &timeout);

        retries ++;
        // Connect to server
        rc = ssh_connect(my_ssh_session);
        if (rc != SSH_OK){
            if(verbose) printf(ANSI_COLOR_BOLD"JOB %4d [%s]"ANSI_COLOR_ENDC" try %d Error connecting: %s\n",jobid,ip2str(ipaddr), retries, ssh_get_error(my_ssh_session));
            ssh_free(my_ssh_session);
            if( (retry>0) && (retries>=retry)) {
                printf(ANSI_COLOR_BOLD"JOB %4d [%s]"ANSI_COLOR_ENDC" SKIP %s %s %s\n",jobid,ip2str(ipaddr), ip2str(ipaddr), user, passwd);
                return return_val;
	    }
        } else
            break;
    }

    rc = ssh_userauth_password(my_ssh_session, NULL, passwd);
    if (rc != SSH_AUTH_SUCCESS){
        if (verbose) printf(ANSI_COLOR_BOLD"JOB %4d [%s]"ANSI_COLOR_ENDC" Error authenticating with user:%s pass: %s %s\n",jobid, ip2str(ipaddr),user,passwd,ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        return return_val;
    }else if(rc == SSH_AUTH_SUCCESS){
        printf(ANSI_COLOR_BOLD"JOB %4d [%s]"ANSI_COLOR_ENDC" Succeed with user:%s  pass:%s\n",jobid,ip2str(ipaddr),user,passwd);

	FILE *f = fopen("valid_credentials", "a");
	fprintf(f, "[%s][%s:%s]\n",ip2str(ipaddr),user,passwd);
	fclose(f);
	
        if(exit_when_success) 
            exit(0);
        return_val=1;
    }
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    return return_val;
}

void checkSSH(void *context){
    thread_arg_t *targs = context;
    int j = 0;
    // if (verbose) printf(ANSI_COLOR_BOLD"JOB %4d [%s]"ANSI_COLOR_ENDC" Connecting\n",targs->jobid, ip2str(targs->ipadrr));
    for(j=targs->from; j<=targs->to; j++){
        char user[MAX_WORD_SIZE];
        char passwd[MAX_WORD_SIZE];
        int result = 0;
        result = sscanf(targs->wtable[j], "%128[^,],%s", user,passwd);
        printf(ANSI_COLOR_YELLOW"JOB %4d [%s] from=%d to=%d, j=%d user:%s   paswd:%s\n"ANSI_COLOR_RESET,
		targs->jobid, ip2str(targs->ipadrr), targs->from, targs->to, j, user,passwd);
        if(result<0) {
            printf("Error splitting user and password from user,password file. %s\n", targs->wtable[j]);
            break;
        }
        //if (DEBUGON) printf("[%s] %d\n",ip2str(targs->ipadrr),targs->ipadrr);

        int res = ConnectSSH(targs->jobid, targs->ipadrr, user, passwd);
        if(res>0) targs->solution=j+1;
    }
    // if (verbose) printf(ANSI_COLOR_BOLD"JOB %4d [%s]"ANSI_COLOR_ENDC" done\n",targs->jobid, ip2str(targs->ipadrr));
}

int main(int argc, char ** argv){
  int c;

  while ((c = getopt (argc, argv, "hvep:t:s:r:")) != -1)
    switch (c){
      case 'h':
        help();
        exit(0);
        break;
      case 'v':
        verbose = 1;
        break;
      case 'e':
        exit_when_success = 0;
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 't':
        nproc = atoi(optarg);
        break;
      case 's':
        timeout = atol(optarg);
        break;
      case 'r':
        retry = atol(optarg);
        break;
      }
    
    if(argc-optind!=2){
	help();
	exit(0);
    }
    
    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    ssh_init();

    threadpool thpool = thpool_init(nproc);

    uint32_t ip_addr = 0;

    if(parseip(argv[optind + 1], &ip_addr)<0){
        printf("Error reading host ip: %s, format must be X.X.X.X\n",argv[2]);
        exit(-1);
    }
    
    fp = fopen(argv[optind], "r");
    while(fgets(buff, MAX_WORD_SIZE, (FILE*)fp)!=NULL)  wlen++;
    printf("password-user file \"%s\" has %d combinations\n",argv[optind],wlen);
    fclose(fp);
    
    if (verbose) printf("Reading password-user file\n");
    char *words[wlen];
    fp = fopen(argv[optind], "r");
    unsigned int index = 0;
    while(fgets(buff, MAX_WORD_SIZE, (FILE*)fp)!=NULL){
	int blen = strlen(buff);
        words[index] = (char *) malloc(blen);
        memcpy(words[index],buff,blen-1);
	words[index][blen-1]=0;
        //if (DEBUGON) printf("pass-user: %s\n",words[index]);
        index++;
    }
    fclose(fp);
    
    int i;
    for(i=0; i< wlen; i+=10) {
        thread_arg_t *targs;
        targs = malloc(sizeof(thread_arg_t));
 	if(targs==NULL) {
            printf("malloc error\n");
	    exit(0);
	}
        targs->jobid = i;
        targs->ipadrr = ip_addr;
        targs->from = i;
        targs->to = i+9;
	if(targs->to > wlen-1)
	    targs->to = wlen-1;
        targs->wtable = words;
        targs->solution = -1;
        thpool_add_work(thpool, (void*)checkSSH, (void*)targs);
        //if(verbose) printf("jobqueue-len=%d\n", thpool_num_jobs(thpool));
        while(thpool_num_jobs(thpool)>nproc*2) {
	    // if(verbose) printf("sleep 1 for job to run\n");
	    sleep(1);
	    // if(verbose) printf("sleep ended\n");
   	}
    }

    thpool_wait(thpool);
    thpool_destroy(thpool);
    printf("Done\n");
    printf("scan_time: %d\n", scan_times);
    
    return 0;
}
