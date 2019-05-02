Libpcap庫主要函數

函數名稱：pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf) 
函數功能：獲得用於捕獲網路封包的封包捕獲描述字。 
參數說明：device 參數為指定打開的網路設備名。snaplen參數定義捕獲封包的最大位元組數。promisc指定是否將網路介面置於混雜模式。to_ms參數指*定超時時 間（毫秒）。ebuf參數則僅在pcap_open_live()函數出錯返回NULL時用於傳遞錯誤消息。

函數名稱：pcap_t *pcap_open_offline(char *fname, char *ebuf) 
函數功能：打開以前保存捕獲封包的文件，用於讀取。 
參數說明：fname參數指定打開的文件案名。該文件中的封包格式與tcpdump和tcpslice相容。”-“為標準輸入。ebuf參數則僅在pcap_open_offline()函數出錯返回NULL時用於傳遞錯誤消息。

函數名稱：pcap_dumper_t *pcap_dump_open(pcap_t *p, char *fname) 
函數功能：打開用於保存捕獲封包的文件，用於寫入。 
參數說明：fname 參數為”-“時表示標準輸出。出錯時返回NULL。p參數為調用pcap_open_offline()或pcap_open_live()函數後返回的 pcap結構指標。fname參數指定打開的文件案名。如果返回NULL，則可調用pcap_geterr()函數獲取錯誤消 息。

函數名稱：char *pcap_lookupdev(char *errbuf) 
函數功能：用於返回可被pcap_open_live()或pcap_lookupnet()函式呼叫的網路設備名指標。參數說明：如果函數出錯，則返回NULL，同時errbuf中存放相關的錯誤消息。

函數名稱：int pcap_lookupnet(char *device, bpf_u_int32 *netp,bpf_u_int32 *maskp, char *errbuf) 
函數功能：獲得指定網路設備的網路號和遮罩。 
參數說明：netp參數和maskp參數都是bpf_u_int32指標。如果函數出錯，則返回-1，同時errbuf中存放相關的錯誤消息。

函數名稱：int pcap_dispatch(pcap_t *p, int cnt,pcap_handler callback, u_char *user) 
函數功能：捕獲並處理封包。 
參數說明：cnt 參數指定函數返回前所處理封包的最大值。cnt=-1表示在一個緩衝區中處理所有的封包。cnt=0表示處理所有封包，直到產生以下錯誤之一：讀取 到EOF；超時讀取。callback參數指定一個帶有三個參數的回呼函數，這三個參數為：一個從pcap_dispatch()函數傳遞過來的 u_char指標，一個pcap_pkthdr結構的指標，和一個封包大小的u_char指標。如果成功則返回讀取到的位元組數。讀取到EOF時則返回零 值。出錯時則返回-1，此時可調用pcap_perror()或pcap_geterr()函數獲取錯誤消息。

函數名稱：int pcap_loop(pcap_t *p, int cnt,pcap_handler callback, u_char *user) 
函數功能： 功能基本與pcap_dispatch()函數相同，只不過此函數在cnt個封包被處理或出現錯誤時才返回，但讀取超時不會返回。而如果為 pcap_open_live()函數指定了一個非零值的超時設置，然後調用pcap_dispatch()函數，則當超時發生時 pcap_dispatch()函數會返回。cnt參數為負值時pcap_loop()函數將始終迴圈運行，除非出現錯誤。

函數名稱：void pcap_dump(u_char *user, struct pcap_pkthdr *h,u_char *sp) 
函數功能：向調用pcap_dump_open()函數打開的文件輸出一個封包。該函數可作為pcap_dispatch()函數的回呼函數。

函數名稱：int pcap_compile(pcap_t *p, struct bpf_program *fp,char *str, int optimize, bpf_u_int32 netmask) 
函數功能：將str參數指定的字串編譯到過濾程式中。 
參數說明：fp是一個bpf_program結構的指標，在pcap_compile()函數中被賦值。optimize參數控制結果代碼的優化。netmask參數指定本地網路的網路遮罩。

函數名稱：int pcap_setfilter(pcap_t *p, struct bpf_program *fp) 
函數功能：指定一個過濾程式。 
參數說明：fp參數是bpf_program結構指標，通常取自pcap_compile()函式呼叫。出錯時返回-1；成功時返回0。

函數名稱：u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h) 
函數功能：返回指向下一個封包的u_char指標。 
函數名稱：int pcap_datalink(pcap_t *p) 
函數功能：返回封包連結層類型，例如DLT_EN10MB。

函數名稱：int pcap_snapshot(pcap_t *p) 
函數功能：返回pcap_open_live被調用後的snapshot參數值。

函數名稱：int pcap_is_swapped(pcap_t *p) 
函數功能：返回當前系統主機位元組與被打開文件的位元組順序是否不同。

函數名稱：int pcap_major_version(pcap_t *p) 
函數功能：返回寫入被打開文件所使用的pcap函數的主版本號。

函數名稱：int pcap_minor_version(pcap_t *p) 
函數功能：返回寫入被打開文件所使用的pcap函數的輔版本號。

函數名稱：int pcap_stats(pcap_t *p, struct pcap_stat *ps) 
函數功能：向pcap_stat結構賦值。成功時返回0。這些數值包括了從開始捕獲封包以來至今共捕獲到的封包統計。如果出錯或不支援封包統計，則返回-1，且可調用pcap_perror()或pcap_geterr()函數來獲取錯誤消息。

函數名稱：FILE *pcap_file(pcap_t *p) 
函數功能：返回被打開文件的文件案名。

函數名稱：int pcap_fileno(pcap_t *p) 
函數功能：返回被打開文件的文件描述字號碼。

函數名稱：void pcap_perror(pcap_t *p, char *prefix) 
函數功能：在標準輸出設備上顯示最後一個pcap庫錯誤消息。以prefix參數指定的字串為消息頭。

函數名稱：char *pcap_geterr(pcap_t *p) 
函數功能：返回最後一個pcap庫錯誤消息。

函數名稱：char *pcap_strerror(int error) 
函數功能：如果strerror()函數不可用，則可調用pcap_strerror函數替代。

函數名稱：void pcap_close(pcap_t *p) 
函數功能：關閉p參數相應的文件，並釋放資源。

函數名稱：void pcap_dump_close(pcap_dumper_t *p) 
函數功能：關閉相應的被打開文件。

 

--------------------------------------------------------------------------------------------------------------------

以下為特別注意的地方：

對於最常用的 pcap_loop():

pcap_loop()原型是pcap_loop(pcap_t *p,int cnt,pcap_handler callback,u_char *user)

其中第一個參數是winpcap的控制碼,第二個是指定捕獲的封包個數,如果為-1則無限迴圈捕獲。第四個參數user是留給用戶使用的。

第三個是回呼函數其原型如下:

pcap_callback(u_char* argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content)

其中參數pcap_content表示的捕獲到的封包的內容

參數argument是從函數pcap_loop()傳遞過來的。注意：這裡的參數就是指 pcap_loop中的 *user 參數

參數pcap_pkthdr 表示捕獲到的封包基本資訊,包括時間,長度等資訊.

另外:回呼函數必須是全域函數或靜態函數,其參數預設,比如pcap_loop()可以寫成

pcap_loop(pcap_handle,10,pcap_callback,NULL)不能往裡面傳遞實參.

-----------------------------------------------------------------------------------------------------------------

pcap_loop和callback之間參數存在聯繫：

pcap_loop的最後一個參數user是留給用戶使用的，當callback被調用的時候這個值會傳遞給callback的第一個參數(也叫user)，callback的最後一個參數p指向一塊記憶體空間，這個空間中存放的就是pcap_loop抓到的封包。callback的第二個參數是一個結構體指標，該結構體定義如下：
struct pcap_pkthdr {
struct timeval ts; /* 時間戳記 */ 
bpf_u_int32 caplen; /* 已捕獲部分的長度 */ 
bpf_u_int32 len;   /* 該包的離線長度 */ 
};
這個結構體是由pcap_loop自己填充的，用來取得一些關於封包的資訊
所以，在callback函數當中只有第一個user指標是可以留給用戶使用的，如果你想給callback傳遞自己參數，那就只能通過pcap_loop的最後一個參數user來實現了

-----------------------------------------------------------------------------------------------------------------

typedef struct pcap pcap_t;
struct pcap [pcap-int.h]
{ 
    int fd; /* 文件描述字，實際就是 socket */ 

    /* 在 socket 上，可以使用 select() 和 poll() 等 I/O 複用類型函數 */
    int selectable_fd; 
    int snapshot; /* 使用者期望的捕獲資料包最大長度 */
    int linktype; /* 設備類型 */
    int tzoff;        /* 時區位置，實際上沒有被使用 */
    int offset;    /* 邊界對齊偏移量 */
    int break_loop; /* 強制從讀數據包迴圈中跳出的標誌 */
    struct pcap_sf sf; /* 資料包保存到文件的相關配置資料結構 */
    struct pcap_md md; /* 具體描述如下 */ 
    int bufsize; /* 讀緩衝區的長度 */
    u_char buffer; /* 讀緩衝區指針 */
    u_char *bp;
    int cc;
    u_char *pkt;

    /* 相關抽象操作的函數指標，最終指向特定作業系統的處理函數 */
    int    (*read_op)(pcap_t *, int cnt, pcap_handler, u_char *);
    int    (*setfilter_op)(pcap_t *, struct bpf_program *);
    int    (*set_datalink_op)(pcap_t *, int);
    int    (*getnonblock_op)(pcap_t *, char *);
    int    (*setnonblock_op)(pcap_t *, int, char *);
    int    (*stats_op)(pcap_t *, struct pcap_stat *);
    void (*close_op)(pcap_t *);
    
    /*如果 BPF 過濾代碼不能在內核中執行,則將其保存並在用戶空間執行 */
    struct bpf_program fcode; 
    /* 函式呼叫出錯資訊緩衝區 */
    char errbuf[PCAP_ERRBUF_SIZE + 1];  
    /* 當前設備支援的、可更改的資料連結類型的個數 */
    int dlt_count;
    /* 可更改的資料連結類型號鏈表，在 linux 下沒有使用 */
    int *dlt_list;
    /* 資料包自訂頭部，對資料包捕獲時間、捕獲長度、真實長度進行描述 [pcap.h] */
    struct pcap_pkthdr pcap_header;   
 
};


struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN 
	u_char	ip_hl:4,		/* header length */
		    ip_v:4;			/* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN 
	u_char	ip_v:4,			/* version */
		    ip_hl:4;		/* header length */
#endif
	u_char	ip_tos;			/* type of service */
	short	ip_len;			/* total length */
	u_short	ip_id;			/* identification */
	short	ip_off;			/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
	u_char	ip_ttl;			/* time to live */
	u_char	ip_p;			/* protocol */
	u_short	ip_sum;			/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

struct in_addr {
    uint32_t s_addr; // that's a 32-bit int (4 bytes)
};


struct icmphdr
{
  u_int8_t type;		/* message type */
  u_int8_t code;		/* type sub-code */
  u_int16_t checksum;
  union
  {
    struct
    {
      u_int16_t	id;
      u_int16_t	sequence;
    } echo;			/* echo datagram */
    u_int32_t	gateway;	/* gateway address */
    struct
    {
      u_int16_t	__unused;
      u_int16_t	mtu;
    } frag;			/* path mtu discovery */
  } un;
};

struct sockaddr_in {
    short int sin_family; // Address family, AF_INET
    unsigned short int sin_port; // Port number
    struct in_addr sin_addr; // Internet address
    unsigned char sin_zero[8]; // 與 struct sockaddr 相同的大小
};
----------------------------------------------------------

pcap.h: no such file

sudo apt-get install libpcap0.8-dev
