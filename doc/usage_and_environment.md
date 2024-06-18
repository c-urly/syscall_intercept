# For x86 #

## Build environment and Usage ##

Building libsyscall_intercept requires cmake.

Example:
```sh
cmake path_to_syscall_intercept -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang
make
```
alternatively:
```sh
ccmake path_to_syscall_intercept
make
```

There is an install target. For now, all it does, is cp.
```sh
make install
```

## EXAMPLE 1 ##
We'll utilize the following client-server program, which includes common syscalls shared by the x86 architecture. Our goal is to intercept all the syscalls; specifically, we will alter the behavior of the write syscall and modify its output. For all other syscalls, we will allow them to execute normally but will add a print statement to each for logging purposes.

<details>
  <summary>Click to expand app.c </summary>

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 12345
#define BUFFER_SIZE 1024

void server() {
    int server_socket, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    char *hello = "Hello from server";

    // Creating socket file descriptor
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 12345
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( PORT );

    // Forcefully attaching socket to the port 12345
    if (bind(server_socket, (struct sockaddr *)&address, 
                                 sizeof(address))<0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_socket, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((new_socket = accept(server_socket, (struct sockaddr *)&address, 
                       (socklen_t*)&addrlen))<0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    valread = read( new_socket , buffer, BUFFER_SIZE);
    printf("%s\n",buffer );
    send(new_socket , hello , strlen(hello) , 0 );
    printf("Hello message sent\n");
}

void client() {
    int client_socket;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};
    char *hello = "Hello from client";

    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) {
        printf("\nInvalid address/ Address not supported \n");
        return;
    }

    if (connect(client_socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return;
    }
    send(client_socket , hello , strlen(hello) , 0 );
    printf("Hello message sent\n");
    read( client_socket , buffer, BUFFER_SIZE);
    printf("%s\n",buffer );
}

void use_all_syscalls() {
    // Create a pipe
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe");
        exit(EXIT_FAILURE);
    }

    // Fork a child process
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        // Child process
        
        // Close the read end of the pipe
        close(pipefd[0]);
        
        // Redirect stdout to the pipe
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        // Execute a program using execve
        char *args[] = {"/bin/ls", "-l", NULL};
        execve("/bin/ls", args, NULL);
        perror("execve");
        exit(EXIT_FAILURE);
    } else {
        // Parent process
        
        // Close the write end of the pipe
        close(pipefd[1]);
        
        // Read data from the pipe
        char buffer[1024];
        ssize_t bytes_read = read(pipefd[0], buffer, sizeof(buffer));
        if (bytes_read == -1) {
            perror("read");
            exit(EXIT_FAILURE);
        }

        // Write data to stdout
        write(STDOUT_FILENO, buffer, bytes_read);

        // Wait for the child to terminate
        int status;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status)) {
            fprintf(stderr, "Child process did not terminate normally\n");
        }
        
        // Close the read end of the pipe
        close(pipefd[0]);
    }
}

int main() {

    use_all_syscalls();
    pid_t pid;
    pid = fork();

    if (pid == 0) {
        // Child process
        printf("Child process (client)\n");
        client();
    } else if (pid > 0) {
        // Parent process
        printf("Parent process (server)\n");
        server();
    } else {
        perror("fork failed");
        exit(EXIT_FAILURE);
    }

    return 0;
}
```
</details>



We will use below code to hook most of the syscall used in the application above.

<details>

<summary> 
Click To Expand hook.c
</summary>

```c
#include "install/include/libsyscall_intercept_hook_point.h"
#include <syscall.h>
#include <errno.h>
#include <stdio.h>

static int 
hook(long syscall_number,
		long arg0, long arg1,
		long arg2, long arg3,
		long arg4, long arg5,
		long *result)
{
    switch (syscall_number) {
		case SYS_getdents64:
			printf("Intercepted SYS_getdents64\n");
            break;
        case SYS_open:
            printf("Intercepted SYS_open\n");
            break;
        case SYS_read:
            printf("Intercepted SYS_read\n");
            break;
        case SYS_write:
            char buffer[0x1000]; 
            size_t size = (size_t)arg2;

            if (size > sizeof(buffer))
                size = sizeof(buffer);

            memcpy(buffer, (char *)arg1, size); 

            if (strncmp(buffer, "Hello from ", 11) == 0) {
                char* interceptStr = "Intercepted "; 
                size_t interceptStrLen = strlen(interceptStr);
                size_t remainingSize = size - 11; 

                
                if (size + interceptStrLen < sizeof(buffer)) {
                    
                    memmove(buffer + 11 + interceptStrLen, buffer + 11, remainingSize);
                    memcpy(buffer + 11, interceptStr, interceptStrLen);
                    size += interceptStrLen; 
                }
            }

            
            *result = syscall_no_intercept(SYS_write, arg0, buffer, size);
            return 0;
        case SYS_close:
            printf("Intercepted SYS_close\n");
            break;
        case SYS_fork:
            printf("Intercepted SYS_fork\n");
            break;
        case SYS_execve:
            printf("Intercepted SYS_execve\n");
            break;
        case SYS_wait4:
            printf("Intercepted SYS_wait4\n");
            break;
        case SYS_getpid:
            printf("Intercepted SYS_getpid\n");
            break;
        case SYS_kill:
            printf("Intercepted SYS_kill\n");
            break;
        case SYS_mmap:
            printf("Intercepted SYS_mmap\n");
            break;
        case SYS_munmap:
            printf("Intercepted SYS_munmap\n");
            break;
        case SYS_socket:
            printf("Intercepted SYS_socket\n");
            break;
        case SYS_bind:
            printf("Intercepted SYS_bind\n");
            break;
        case SYS_listen:
            printf("Intercepted SYS_listen\n");
            break;
        case SYS_accept:
            printf("Intercepted SYS_accept\n");
            break;
        default:
            return 1; // Pass other syscalls to the kernel
    }

    // For demonstration, let all intercepted syscalls proceed as usual
    return 1;
}

static __attribute__((constructor)) void
init(void)
{
	// Set up the callback function
	intercept_hook_point = hook;
}

```
</details>

## Build the library and app ##
Once you build the syscall library, you can generate the dynamic and static library to intercept the syscall in the application. We have intercepted write syscall as shown below.

- Steps to build application
```sh
$ gcc -g -fPIC -o app app.c

```
- Steps to build the library (assuming it is build in /usr)

```sh
$ gcc -fPIC -shared -g -o intercept_lib.so hook.c -lsyscall_intercept
```


```sh
$ ./app
total 232
-rwxrwxrwx 1 curly curly   686 Jun 15 19:41 Makefile
-rwxrwxr-x 1 curly curly 22312 Jun 17 05:45 app
-rwxrwxrwx 1 curly curly  4395 Jun 15 19:41 app.c
-rwxrwxrwx 1 curly curly  6528 Jun 15 19:41 app.o
-rwxrwxrwx 1 curly curly 13896 Jun 16 05:24 app_riscv64
-rwxrwxrwx 1 curly curly  4702 Jun 16 05:23 app_riscv64.c
drwxrwxrwx 7 curly curly  4096 Jun 15 19:41 build
-rwxrwxrwx 1 root  root  15608 Jun 16 19:36 examle.so
-rwxrwxrwx 1 curly curly  2021 Jun 17 06:38 example.c
-rwxrwxrwx 1 curly curly 15640 Jun 15 19:41 example.so
drwxrwxrwx 4 root  root   4096 Jun 16 19:18 install
-rwxrwxr-x 1 curly curly 60992 Jun 17 23:04 intercept_lib.so
-rwxrwxr-x 1 curly curly 17184 Jun 17 06:38 libexample.so
-rwx------ 1 curly curly 14140 Jun 17 23:10 log.txt
-rwxrwxrwx 1 curly curly  1123 Jun 15 19:41 ptrace_example.c
-rwxrwxrwx 1 curly curly 16280 Jun 15 19:41 ptrace_intercept
-rwxrwxrwx 1 curly curly    14 Jun 15 19:41 testfile.txt
Parent process (server)
Child process (client)
Hello message sent
Hello from client
Hello message sent
Hello from server

```
- Use LD_PRELOAD to preload the intercept lib for the app.c

```sh
$ LD_PRELOAD=./intercept_lib.so ./app
Intercepted SYS_close
Intercepted SYS_read
Intercepted SYS_close
Intercepted SYS_close
Intercepted SYS_execve
Intercepted SYS_wait4
Intercepted SYS_close
Parent process (server)
Intercepted SYS_socket
Intercepted SYS_bind
Intercepted SYS_listen
Child process (client)
Intercepted SYS_accept
Intercepted SYS_socket
Hello message sent
Intercepted SYS_read
Intercepted SYS_read
Hello from Intercepted client -----> Intercepted write
Hello message sent
Hello from Intercepted server -----> Intercepted write
```

### EXAMPLE 2

We can use the syscall_logger.c in examples which will log all the syscalls in a log.txt file, the ouput will be same as that of strace.

Build Intercept lib with syscall_logger.c

```sh
gcc -fPIC -shared -g -o intercept_lib.so ../examples/syscall_logger.c ../examples/syscall_desc.c -lsyscall_intercept
```

<details>
<summary>Click to Expand the logs </summary>

```
pipe2(0x00007ffe924056a8, 0x0000000000000000) = 0
clone(0x0000000001200011, 0x0000000000000000, 0x0000000000000000, 0x00007131a7730e50, 0x0000000000000000, 0x00007131a7776380) = 14999
close(5) = 0
read(4, 0x00007ffe924056d0, 0x0000000000000400) = 1024
write(1, 0x00007ffe924056d0, 0x0000000000000400) = 1024
wait4(0x0000000000003a97, 0x00007ffe92405698, 0x0000000000000000, 0x0000000000000000) = 14999
close(4) = 0
clone(0x0000000001200011, 0x0000000000000000, 0x0000000000000000, 0x00007131a7730e50, 0x0000000000000000, 0x00007131a7776380) = 15000
fstat(1, 0x00007ffe92405920) = 0
write(1, 0x0000643202f78480, 0x0000000000000018) = 24
socket(0x0000000000000002, 0x0000000000000001, 0x0000000000000000) = 4
setsockopt(4, 0x0000000000000001, 0x000000000000000f, 0x00007ffe924056a4, 0x0000000000000004) = 0
bind(4, 0x00007ffe924056c0, 0x0000000000000010) = 0
listen(4, 0x0000000000000003) = 0
accept(4, 0x00007ffe924056c0, 0x00007ffe924056a8) = 5
read(5, 0x00007ffe924056d0, 0x0000000000000400) = 17
write(1, 0x0000643202f78480, 0x0000000000000012) = 18
sendto(5, 0x00006432020ff008, 0x0000000000000011, 0x0000000000000000) = 17
write(1, 0x0000643202f78480, 0x0000000000000013) = 19
exit_group(0x0000000000000000)
pipe2(0x00007ffe924056a8, 0x0000000000000000) = 0
clone(0x0000000001200011, 0x0000000000000000, 0x0000000000000000, 0x00007131a7730e50, 0x0000000000000000, 0x00007131a7776380) = 14999
close(5) = 0
read(4, 0x00007ffe924056d0, 0x0000000000000400) = 1024
write(1, 0x00007ffe924056d0, 0x0000000000000400) = 1024
wait4(0x0000000000003a97, 0x00007ffe92405698, 0x0000000000000000, 0x0000000000000000) = 14999
close(4) = 0
clone(0x0000000001200011, 0x0000000000000000, 0x0000000000000000, 0x00007131a7730e50, 0x0000000000000000, 0x00007131a7776380) = 0
set_robust_list(0x00007131a7730e60, 0x0000000000000018) = 0
fstat(1, 0x00007ffe92405920) = 0
write(1, 0x0000643202f78480, 0x0000000000000017) = 23
socket(0x0000000000000002, 0x0000000000000001, 0x0000000000000000) = 4
connect(4, 0x00007ffe924056c0, 0x0000000000000010) = 0
sendto(4, 0x00006432020ff060, 0x0000000000000011, 0x0000000000000000) = 17
write(1, 0x0000643202f78480, 0x0000000000000013) = 19
read(4, 0x00007ffe924056d0, 0x0000000000000400) = 17
write(1, 0x0000643202f78480, 0x0000000000000012) = 18
exit_group(0x0000000000000000)
ap(0x0000000000000000, 0x000000000000003b, 0x0000000000000001, 0x0000000000000002, 4, 0x0000000000000000) = 0x00007d92d45aa000
close(4) = 0
openat(4294967196, 0x0000651e9a94ee50"/snap/code/161/usr/lib/locale/en_US.UTF-8/LC_ADDRESS", O_RDONLY | O_CLOEXEC) = -2 (No such file or directory)
openat(4294967196, 0x0000651e9a94ed70"/usr/lib/locale/en_US.UTF-8/LC_ADDRESS", O_RDONLY | O_CLOEXEC) = -2 (No such file or directory)
openat(4294967196, 0x0000651e9a94f3e0"/snap/code/161/usr/lib/locale/en_US.utf8/LC_ADDRESS", O_RDONLY | O_CLOEXEC) = 4
fstat(4, 0x00007ffd04b848e0) = 0
mmap(0x0000000000000000, 0x00000000000000a7, 0x0000000000000001, 0x0000000000000002, 4, 0x0000000000000000) = 0x00007d92d45a9000
close(4) = 0
openat(4294967196, 0x0000651e9a94fe00"/snap/code/161/usr/lib/locale/en_US.UTF-8/LC_NAME", O_RDONLY | O_CLOEXEC) = -2 (No such file or directory)
openat(4294967196, 0x0000651e9a94f9c0"/usr/lib/locale/en_US.UTF-8/LC_NAME", O_RDONLY | O_CLOEXEC) = -2 (No such file or directory)
openat(4294967196, 0x0000651e9a950050"/snap/code/161/usr/lib/locale/en_US.utf8/LC_NAME", O_RDONLY | O_CLOEXEC) = 4
fstat(4, 0x00007ffd04b848e0) = 0
mmap(0x0000000000000000, 0x000000000000004d, 0x0000000000000001, 0x0000000000000002, 4, 0x0000000000000000) = 0x00007d92d45a8000
close(4) = 0
openat(4294967196, 0x0000651e9a9509b0"/snap/code/161/usr/lib/locale/en_US.UTF-8/LC_PAPER", O_RDONLY | O_CLOEXEC) = -2 (No such file or directory)
openat(4294967196, 0x0000651e9a9506d0"/usr/lib/locale/en_US.UTF-8/LC_PAPER", O_RDONLY | O_CLOEXEC) = -2 (No such file or directory)
openat(4294967196, 0x0000651e9a950c00"/snap/code/161/usr/lib/locale/en_US.utf8/LC_PAPER", O_RDONLY | O_CLOEXEC) = 4
fstat(4, 0x00007ffd04b848e0) = 0
mmap(0x0000000000000000, 0x0000000000000022, 0x0000000000000001, 0x0000000000000002, 4, 0x0000000000000000) = 0x00007d92d45a7000
close(4) = 0
openat(4294967196, 0x0000651e9a9512b0"/snap/code/161/usr/lib/locale/en_US.UTF-8/LC_MESSAGES", O_RDONLY | O_CLOEXEC) = -2 (No such file or directory)
openat(4294967196, 0x0000651e9a951280"/usr/lib/locale/en_US.UTF-8/LC_MESSAGES", O_RDONLY | O_CLOEXEC) = -2 (No such file or directory)
openat(4294967196, 0x0000651e9a951a80"/snap/code/161/usr/lib/locale/en_US.utf8/LC_MESSAGES", O_RDONLY | O_CLOEXEC) = 4
fstat(4, 0x00007ffd04b848e0) = 0
close(4) = 0
openat(4294967196, 0x00007ffd04b84880"/snap/code/161/usr/lib/locale/en_US.utf8/LC_MESSAGES/SYS_LC_MESSAGES", O_RDONLY | O_CLOEXEC) = 4
fstat(4, 0x00007ffd04b848e0) = 0
mmap(0x0000000000000000, 0x0000000000000039, 0x0000000000000001, 0x0000000000000002, 4, 0x0000000000000000) = 0x00007d92d45a6000
close(4) = 0
openat(4294967196, 0x0000651e9a952420"/snap/code/161/usr/lib/locale/en_US.UTF-8/LC_MONETARY", O_RDONLY | O_CLOEXEC) = -2 (No such file or directory)
openat(4294967196, 0x0000651e9a952380"/usr/lib/locale/en_US.UTF-8/LC_MONETARY", O_RDONLY | O_CLOEXEC) = -2 (No such file or directory)
openat(4294967196, 0x0000651e9a9529b0"/snap/code/161/usr/lib/locale/en_US.utf8/LC_MONETARY", O_RDONLY | O_CLOEXEC) = 4
fstat(4, 0x00007ffd04b848e0) = 0
mmap(0x0000000000000000, 0x000000000000011e, 0x0000000000000001, 0x0000000000000002, 4, 0x0000000000000000) = 0x00007d92d45a5000
close(4) = 0
openat(4294967196, 0x0000651e9a953070"/snap/code/161/usr/lib/locale/en_US.UTF-8/LC_COLLATE", O_RDONLY | O_CLOEXEC) = -2 (No such file or directory)
openat(4294967196, 0x0000651e9a952f90"/usr/lib/locale/en_US.UTF-8/LC_COLLATE", O_RDONLY | O_CLOEXEC) = -2 (No such file or directory)
openat(4294967196, 0x0000651e9a953740"/snap/code/161/usr/lib/locale/en_US.utf8/LC_COLLATE", O_RDONLY | O_CLOEXEC) = 4
fstat(4, 0x00007ffd04b848e0) = 0
mmap(0x0000000000000000, 0x0000000000277932, 0x0000000000000001, 0x0000000000000002, 4, 0x0000000000000000) = 0x00007d92d3788000
close(4) = 0
openat(4294967196, 0x0000651e9a954190"/snap/code/161/usr/lib/locale/en_US.UTF-8/LC_TIME", O_RDONLY | O_CLOEXEC) = -2 (No such file or directory)
openat(4294967196, 0x0000651e9a953d20"/usr/lib/locale/en_US.UTF-8/LC_TIME", O_RDONLY | O_CLOEXEC) = -2 (No such file or directory)
openat(4294967196, 0x0000651e9a9543e0"/snap/code/161/usr/lib/locale/en_US.utf8/LC_TIME", O_RDONLY | O_CLOEXEC) = 4
fstat(4, 0x00007ffd04b848e0) = 0
mmap(0x0000000000000000, 0x0000000000000cd4, 0x0000000000000001, 0x0000000000000002, 4, 0x0000000000000000) = 0x00007d92d441a000
close(4) = 0
openat(4294967196, 0x0000651e9a954a90"/snap/code/161/usr/lib/locale/en_US.UTF-8/LC_NUMERIC", O_RDONLY | O_CLOEXEC) = -2 (No such file or directory)
openat(4294967196, 0x0000651e9a954a60"/usr/lib/locale/en_US.UTF-8/LC_NUMERIC", O_RDONLY | O_CLOEXEC) = -2 (No such file or directory)
openat(4294967196, 0x0000651e9a9554f0"/snap/code/161/usr/lib/locale/en_US.utf8/LC_NUMERIC", O_RDONLY | O_CLOEXEC) = 4
fstat(4, 0x00007ffd04b848e0) = 0
mmap(0x0000000000000000, 0x0000000000000036, 0x0000000000000001, 0x0000000000000002, 4, 0x0000000000000000) = 0x00007d92d4419000
close(4) = 0
openat(4294967196, 0x0000651e9a955ed0"/snap/code/161/usr/lib/locale/en_US.UTF-8/LC_CTYPE", O_RDONLY | O_CLOEXEC) = -2 (No such file or directory)
openat(4294967196, 0x0000651e9a955ad0"/usr/lib/locale/en_US.UTF-8/LC_CTYPE", O_RDONLY | O_CLOEXEC) = -2 (No such file or directory)
openat(4294967196, 0x0000651e9a956120"/snap/code/161/usr/lib/locale/en_US.utf8/LC_CTYPE", O_RDONLY | O_CLOEXEC) = 4
fstat(4, 0x00007ffd04b848e0) = 0
mmap(0x0000000000000000, 0x00000000000532a0, 0x0000000000000001, 0x0000000000000002, 4, 0x0000000000000000) = 0x00007d92d4051000
close(4) = 0
ioctl(1, 0x0000000000005401, 0x00007ffd04b84b20) = 0
ioctl(1, 0x0000000000005413, 0x00007ffd04b84c40) = 0
openat(4294967196, 0x0000651e9a95e600".", O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NONBLOCK) = 4
fstat(4, 0x00007ffd04b847f0) = 0
getdents64(4, 0x0000651e9a95e650, 0x0000000000008000) = 688
syscall(332, 0x00000000ffffff9c, 0x00007ffd04b84550, 0x0000000000000900, 0x0000000000000002, 0x00007ffd04b84420, 0x00) = 0x0000000000000000
syscall(332, 0x00000000ffffff9c, 0x00007ffd04b84550, 0x0000000000000900, 0x0000000000000002, 0x00007ffd04b84420, 0x00) = 0x0000000000000000
syscall(332, 0x00000000ffffff9c, 0x00007ffd04b84550, 0x0000000000000900, 0x0000000000000002, 0x00007ffd04b84420, 0x00) = 0x0000000000000000
syscall(332, 0x00000000ffffff9c, 0x00007ffd04b84550, 0x0000000000000900, 0x0000000000000002, 0x00007ffd04b84420, 0x00) = 0x0000000000000000
syscall(332, 0x00000000ffffff9c, 0x00007ffd04b84550, 0x0000000000000900, 0x0000000000000002, 0x00007ffd04b84420, 0x00) = 0x0000000000000000
syscall(332, 0x00000000ffffff9c, 0x00007ffd04b84550, 0x0000000000000900, 0x0000000000000002, 0x00007ffd04b84420, 0x00) = 0x0000000000000000
syscall(332, 0x00000000ffffff9c, 0x00007ffd04b84550, 0x0000000000000900, 0x0000000000000002, 0x00007ffd04b84420, 0x00) = 0x0000000000000000
syscall(332, 0x00000000ffffff9c, 0x00007ffd04b84560, 0x0000000000000900, 0x0000000000000002, 0x00007ffd04b84430, 0x00) = 0x0000000000000000
syscall(332, 0x00000000ffffff9c, 0x00007ffd04b84560, 0x0000000000000900, 0x0000000000000002, 0x00007ffd04b84430, 0x00) = 0x0000000000000000
syscall(332, 0x00000000ffffff9c, 0x00007ffd04b84550, 0x0000000000000900, 0x0000000000000002, 0x00007ffd04b84420, 0x00) = 0x0000000000000000
syscall(332, 0x00000000ffffff9c, 0x00007ffd04b84550, 0x0000000000000900, 0x0000000000000002, 0x00007ffd04b84420, 0x00) = 0x0000000000000000
syscall(332, 0x00000000ffffff9c, 0x00007ffd04b84550, 0x0000000000000900, 0x0000000000000002, 0x00007ffd04b84420, 0x00) = 0x0000000000000000
syscall(332, 0x00000000ffffff9c, 0x00007ffd04b84550, 0x0000000000000900, 0x0000000000000002, 0x00007ffd04b84420, 0x00) = 0x0000000000000000
syscall(332, 0x00000000ffffff9c, 0x00007ffd04b84550, 0x0000000000000900, 0x0000000000000002, 0x00007ffd04b84420, 0x00) = 0x0000000000000000
syscall(332, 0x00000000ffffff9c, 0x00007ffd04b84560, 0x0000000000000900, 0x0000000000000002, 0x00007ffd04b84430, 0x00) = 0x0000000000000000
syscall(332, 0x00000000ffffff9c, 0x00007ffd04b84560, 0x0000000000000900, 0x0000000000000002, 0x00007ffd04b84430, 0x00) = 0x0000000000000000
syscall(332, 0x00000000ffffff9c, 0x00007ffd04b84550, 0x0000000000000900, 0x0000000000000002, 0x00007ffd04b84420, 0x00) = 0x0000000000000000
syscall(332, 0x00000000ffffff9c, 0x00007ffd04b84550, 0x0000000000000900, 0x0000000000000002, 0x00007ffd04b84420, 0x00) = 0x0000000000000000
syscall(332, 0x00000000ffffff9c, 0x00007ffd04b84550, 0x0000000000000900, 0x0000000000000002, 0x00007ffd04b84420, 0x00) = 0x0000000000000000
getdents64(4, 0x0000651e9a95e650, 0x0000000000008000) = 0
close(4) = 0
ioctl(1, 0x000000000000540f, 0x00007ffd04b82764) = 0
rt_sigaction(0x0000000000000014, 0x0000000000000000, 0x00007ffd04b825e0) = 0
rt_sigaction(0x000000000000000e, 0x0000000000000000, 0x00007ffd04b825e0) = 0
rt_sigaction(0x0000000000000001, 0x0000000000000000, 0x00007ffd04b825e0) = 0
rt_sigaction(0x0000000000000002, 0x0000000000000000, 0x00007ffd04b825e0) = 0
rt_sigaction(0x000000000000000d, 0x0000000000000000, 0x00007ffd04b825e0) = 0
rt_sigaction(0x0000000000000003, 0x0000000000000000, 0x00007ffd04b825e0) = 0
rt_sigaction(0x000000000000000f, 0x0000000000000000, 0x00007ffd04b825e0) = 0
rt_sigaction(0x000000000000001d, 0x0000000000000000, 0x00007ffd04b825e0) = 0
rt_sigaction(0x000000000000001b, 0x0000000000000000, 0x00007ffd04b825e0) = 0
rt_sigaction(0x000000000000001a, 0x0000000000000000, 0x00007ffd04b825e0) = 0
rt_sigaction(0x0000000000000018, 0x0000000000000000, 0x00007ffd04b825e0) = 0
rt_sigaction(0x0000000000000019, 0x0000000000000000, 0x00007ffd04b825e0) = 0
rt_sigaction(0x0000000000000014, 0x00007ffd04b82540, 0x0000000000000000) = 0
rt_sigaction(0x000000000000000e, 0x00007ffd04b82540, 0x0000000000000000) = 0
rt_sigaction(0x0000000000000001, 0x00007ffd04b82540, 0x0000000000000000) = 0
rt_sigaction(0x0000000000000002, 0x00007ffd04b82540, 0x0000000000000000) = 0
rt_sigaction(0x000000000000000d, 0x00007ffd04b82540, 0x0000000000000000) = 0
rt_sigaction(0x0000000000000003, 0x00007ffd04b82540, 0x0000000000000000) = 0
rt_sigaction(0x000000000000000f, 0x00007ffd04b82540, 0x0000000000000000) = 0
rt_sigaction(0x000000000000001d, 0x00007ffd04b82540, 0x0000000000000000) = 0
rt_sigaction(0x000000000000001b, 0x00007ffd04b82540, 0x0000000000000000) = 0
rt_sigaction(0x000000000000001a, 0x00007ffd04b82540, 0x0000000000000000) = 0
rt_sigaction(0x0000000000000018, 0x00007ffd04b82540, 0x0000000000000000) = 0
rt_sigaction(0x0000000000000019, 0x00007ffd04b82540, 0x0000000000000000) = 0
fstat(1, 0x00007ffd04b825c0) = 0
write(1, 0x0000651e9a94b480, 0x00000000000000b8) = 184
write(1, 0x0000651e9a94b480, 0x000000000000009a) = 154
write(1, 0x0000651e9a94b480, 0x000000000000009a) = 154
rt_sigaction(0x0000000000000014, 0x00007ffd04b84840, 0x00007ffd04b848e0) = 0
rt_sigaction(0x000000000000000e, 0x00007ffd04b84840, 0x00007ffd04b848e0) = 0
rt_sigaction(0x0000000000000001, 0x00007ffd04b84840, 0x00007ffd04b848e0) = 0
rt_sigaction(0x0000000000000002, 0x00007ffd04b84840, 0x00007ffd04b848e0) = 0
rt_sigaction(0x000000000000000d, 0x00007ffd04b84840, 0x00007ffd04b848e0) = 0
rt_sigaction(0x0000000000000003, 0x00007ffd04b84840, 0x00007ffd04b848e0) = 0
rt_sigaction(0x000000000000000f, 0x00007ffd04b84840, 0x00007ffd04b848e0) = 0
rt_sigaction(0x000000000000001d, 0x00007ffd04b84840, 0x00007ffd04b848e0) = 0
rt_sigaction(0x000000000000001b, 0x00007ffd04b84840, 0x00007ffd04b848e0) = 0
rt_sigaction(0x000000000000001a, 0x00007ffd04b84840, 0x00007ffd04b848e0) = 0
rt_sigaction(0x0000000000000018, 0x00007ffd04b84840, 0x00007ffd04b848e0) = 0
rt_sigaction(0x0000000000000019, 0x00007ffd04b84840, 0x00007ffd04b848e0) = 0
close(1) = 0
close(2) = 0
exit_group(0x0000000000000000)

```

</details>


## Debug Environment ##

`listen` syscall without intercept library

```
$ gdb ./app
Reading symbols from ./app...
(gdb) b listen
Breakpoint 1 at 0x1280
(gdb) r
Breakpoint 1, __GI_listen () at ../sysdeps/unix/syscall-template.S:120
warning: 120    ../sysdeps/unix/syscall-template.S: No such file or directory
(gdb) disas
Dump of assembler code for function __GI_listen:
=> 0x00007ffff7d2bb20 <+0>:     endbr64
   0x00007ffff7d2bb24 <+4>:     mov    $0x32,%eax
   0x00007ffff7d2bb29 <+9>:     syscall ------> syscall is being called without intercept lib
   0x00007ffff7d2bb2b <+11>:    cmp    $0xfffffffffffff001,%rax
   0x00007ffff7d2bb31 <+17>:    jae    0x7ffff7d2bb34 <__GI_listen+20>
   0x00007ffff7d2bb33 <+19>:    ret
   0x00007ffff7d2bb34 <+20>:    mov    0xd72bd(%rip),%rcx        # 0x7ffff7e02df8
   0x00007ffff7d2bb3b <+27>:    neg    %eax
   0x00007ffff7d2bb3d <+29>:    mov    %eax,%fs:(%rcx)
   0x00007ffff7d2bb40 <+32>:    or     $0xffffffffffffffff,%rax
   0x00007ffff7d2bb44 <+36>:    ret

(gdb) set environment LD_PRELOAD=./intercept_lib.so
(gdb) b main
Breakpoint 1 at 0x19b1: file app.c, line 148.
(gdb) r
Starting program: /home/curly/Github/syscall_intercept/library/app 
                            
Breakpoint 1, main () at app.c:148
148         use_all_syscalls();
(gdb) disas listen
Dump of assembler code for function __GI_listen:
   0x00007ffff7d2bb20 <+0>:     endbr64
   0x00007ffff7d2bb24 <+4>:     mov    $0x32,%eax
   0x00007ffff7d2bb29 <+9>:     jmp    0x7ffff7d2bb47 ----> syscall is overwritten with jmp to address of trampoline
   0x00007ffff7d2bb2b <+11>:    cmp    $0xfffffffffffff001,%rax
   0x00007ffff7d2bb31 <+17>:    jae    0x7ffff7d2bb34 <__GI_listen+20>
   0x00007ffff7d2bb33 <+19>:    ret
   0x00007ffff7d2bb34 <+20>:    mov    0xd72bd(%rip),%rcx        # 0x7ffff7e02df8
   0x00007ffff7d2bb3b <+27>:    neg    %eax
   0x00007ffff7d2bb3d <+29>:    mov    %eax,%fs:(%rcx)
   0x00007ffff7d2bb40 <+32>:    or     $0xffffffffffffffff,%rax
   0x00007ffff7d2bb44 <+36>:    ret
```


# For RISCV #

## Build environment ##

For riscv we will use  gcc from [riscv toolchain](https://github.com/riscv-collab/riscv-gnu-toolchain) to compile and qemu+binfmt_misc  support to run riscv binaries. 

This section provides an overview and instructions on using the RISC-V toolchain to build GCC specifically for RISC-V64, compile applications using the built GCC, and run RISC-V64 binaries using QEMU and binfmt-support.

## Building GCC for RISC-V64

### Prerequisites

Ensure you have all the necessary dependencies installed:

```bash
sudo apt-get update
sudo apt-get install autoconf automake autotools-dev curl libmpc-dev libmpfr-dev libgmp-dev gawk build-essential bison flex texinfo gperf libtool patchutils bc zlib1g-dev libexpat-dev
```

### Clone the RISC-V GNU Toolchain Repository

```bash
git clone --recursive https://github.com/riscv/riscv-gnu-toolchain
cd riscv-gnu-toolchain
```

### Build the Toolchain

Configure and build the RISC-V GCC for the RV64 architecture:

```bash
./configure --prefix=/opt/riscv64 --with-arch=rv64gc --with-abi=lp64d
make linux
```

This process can take a considerable amount of time depending on your system's capabilities.

## Compiling `app.c` using RISC-V64 GCC

After successfully building the GCC, add it to your PATH:

```bash
export PATH=/opt/riscv64/bin:$PATH
```

Compile your application:

```bash
$ riscv64-unknown-linux-gnu-gcc -g -o app_risc64 app_riscv64.c

$ file app_riscv64
app_riscv64: ELF 64-bit LSB executable, UCB RISC-V, RVC, double-float ABI, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-riscv64-lp64d.so.1, for GNU/Linux 4.15.0, not stripped
```

## Installing QEMU and binfmt-support

### Install QEMU

QEMU is used for emulating different architectures, such as RISC-V64:

```bash
sudo apt-get install qemu qemu-user qemu-user-static
```

### Install binfmt-support

This package enables your system to recognize and run binaries for non-native architectures:

```bash
sudo apt-get install binfmt-support
```

## Running RISC-V64 Binaries

Once you have everything set up, you can run your RISC-V64 compiled binaries directly:

```bash
$ qemu-riscv64 -L<path to riscv toolchain sysroot> ./app_riscv64
total 196
-rwxrwxrwx 1 curly curly   686 Jun 15 19:41 Makefile
-rwxrwxr-x 1 curly curly 22312 Jun 17 05:45 app
-rwxrwxrwx 1 curly curly  4395 Jun 15 19:41 app.c
-rwxrwxrwx 1 curly curly  6528 Jun 15 19:41 app.o
-rwxrwxr-x 1 curly curly 20112 Jun 18 05:42 app_riscv64
-rwxrwxrwx 1 curly curly  4702 Jun 16 05:23 app_riscv64.c
drwxrwxrwx 7 curly curly  4096 Jun 15 19:41 build
-rwxrwxrwx 1 root  root  15608 Jun 16 19:36 examle.so
-rwxrwxrwx 1 curly curly  2021 Jun 17 06:38 example.c
-rwxrwxrwx 1 curly curly 15640 Jun 15 19:41 example.so
drwxrwxrwx 4 root  root   4096 Jun 16 19:18 install
-rwxrwxr-x 1 curly curly 17184 Jun 18 04:58 intercept_lib.so
-rwxrwxr-x 1 curly curly 17184 Jun 17 06:38 libexample.so
-rwx------ 1 curly curly 14140 Jun 17 23:10 log.txt
-rwxrwxrwx 1 curly curly  1123 Jun 15 19:41 ptrace_example.c
-rwxrwxrwx 1 curly curly 16280 Jun 15 19:41 ptrace_intercept
-rwxrwxrwx 1 curly curly    14 Jun 15 19:41 testfile.txt
Parent process (server)
Child process (client)
Hello from client
Hello message sent
Hello message sent
Hello from server
```
If you want to run the command without -L option, set this QEMU_LD_PREFIX env variable.
```sh
export QEMU_LD_PREFIX="path/to/riscv/toolchain/sysroot"
```

This command uses QEMU to emulate the RISC-V64 architecture and run your application.

If you don't wnat to use qemu-riscv64 and direclty run riscv64 binary with the help of binfmt-support.

You can add this env variable

```sh

$ ./app_riscv64
total 196
-rwxrwxrwx 1 curly curly   686 Jun 15 19:41 Makefile
-rwxrwxr-x 1 curly curly 22312 Jun 17 05:45 app
-rwxrwxrwx 1 curly curly  4395 Jun 15 19:41 app.c
-rwxrwxrwx 1 curly curly  6528 Jun 15 19:41 app.o
-rwxrwxr-x 1 curly curly 20112 Jun 18 05:42 app_riscv64
-rwxrwxrwx 1 curly curly  4702 Jun 16 05:23 app_riscv64.c
drwxrwxrwx 7 curly curly  4096 Jun 15 19:41 build
-rwxrwxrwx 1 root  root  15608 Jun 16 19:36 examle.so
-rwxrwxrwx 1 curly curly  2021 Jun 17 06:38 example.c
-rwxrwxrwx 1 curly curly 15640 Jun 15 19:41 example.so
drwxrwxrwx 4 root  root   4096 Jun 16 19:18 install
-rwxrwxr-x 1 curly curly 17184 Jun 18 04:58 intercept_lib.so
-rwxrwxr-x 1 curly curly 17184 Jun 17 06:38 libexample.so
-rwx------ 1 curly curly 14140 Jun 17 23:10 log.txt
-rwxrwxrwx 1 curly curly  1123 Jun 15 19:41 ptrace_example.c
-rwxrwxrwx 1 curly curly 16280 Jun 15 19:41 ptrace_intercept
-rwxrwxrwx 1 curly curly    14 Jun 15 19:41 testfile.txt
Parent process (server)
Child process (client)
Hello from client
Hello message sent
Hello message sent
Hello from server
```

## Debug Environment ##


For riscv we will have to use qemu and cross complied gdb to debug riscv binary remotely.

### Build gdb 

Step 1: Clone binutils-gdb
```sh
git clone --depth 1 git://sourceware.org/git/binutils-gdb.git
cd binutils-gdb

```
Step:2
```sh
mkdir build
cd build
../configure --target=riscv64-unknown-elf --prefix=/opt/riscv_gdb --enable-gdb --with-expat --with-system-zlib --disable-werror --enable-tui --enable-multilib

```

Step 3: Buidl and install
```sh
make -j$(nproc)
sudo make install

```
Step 4: Add toolchain to the path

```sh
echo 'export PATH=/opt/riscv_gdb/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

```

First we will run app_riscv64 with qemu with -g option and wait for riscv64-unknown-elf-gdb to atatch to this process.

```sh
$ qemu-riscv64 -g 1234 ./app_riscv64
```


```sh
$ riscv64-unknown-elf-gdb ./app_riscv64

Reading symbols from ./app_riscv64...
(gdb) target remote localhost:1234
Remote debugging using localhost:1234
warning: A handler for the OS ABI "GNU/Linux" is not built into this configuration
of GDB.  Attempting to continue with the default riscv:rv64 settings.

0x00002aaaab2bc27e in ?? ()
(gdb) disas listen
Dump of assembler code for function listen@plt:
   0x0000000000010bb0 <+0>:	auipc	t3,0x2
   0x0000000000010bb4 <+4>:	ld	t3,1240(t3) # 0x13088 <listen@got.plt>
   0x0000000000010bb8 <+8>:	jalr	t1,t3
   0x0000000000010bbc <+12>:	nop

```

