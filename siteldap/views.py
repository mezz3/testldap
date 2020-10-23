from django.shortcuts import render, redirect
import socket
import telnetlib
import ldap

group01 = 0
group02 = 0
group03 = 0

# Create your views here.
def index(request):
    global group01
    global group02
    global group03

    context = {}
    context['test'] = 'test'
    checkgroup = ""
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        usernamenew = username+"@pcnmanage.net"
        print(username+'  '+password)
        try:
            l = ldap.initialize("ldap://10.1.2.2")

            print(l.simple_bind_s(usernamenew, password))    
            ldap_base = "dc=pcnmanage,dc=net"
            query = "(cn="+username+")"
            result = l.search_s(ldap_base, ldap.SCOPE_SUBTREE, query)
            check = result[0][0].find("OU=")
            for i in range(result[0][0].find("OU=")+3, len(result[0][0])):
                checkgroup += (result[0][0][i])
                if result[0][0][i+1] == ",":
                    break
            print(checkgroup)
            context['test'] = username
            context['group'] = checkgroup
            context['ip'] = get_client_ip(request)

            runLogin(context['ip'], checkgroup)

            if checkgroup == "01_Neighbor":
                group01 += 1
            elif checkgroup == "02_Server":
                group02 += 1
            elif checkgroup == "03_Internet":
                group03 += 1
            
            print("Intranet Group : "+str(group01)+" User")
            print("Server Group : "+str(group02)+" User")
            print("Internet Group : "+str(group03)+" User")


            return render(request, template_name='siteldap/home.html', context=context)
        except ldap.LDAPError:
            context['error'] = 'username or password incorrect'
            return render(request, template_name='siteldap/index.html', context=context)

    else:
        return render(request, template_name='siteldap/index.html', context=context)

def check(request):
    context= {}
    context['test'] = 'test'
    return render(request, template_name='siteldap/index.html', context=context)

def my_logout(request, group):
    print(group)
    global group01
    global group02
    global group03

    if group == "01_Neighbor":
        group01 -= 1
        if group01 == 0:
            print('test')
            runLogOut(group)
            print('test2')
    elif group == "02_Server":
        group02 -= 1
        if group02 == 0:
            runLogOut(group)
    elif group == "03_Internet":
        group03 -= 1
        if group03 == 0:
            runLogOut(group)

    print("Intranet Group : "+str(group01)+" User")
    print("Server Group : "+str(group02)+" User")
    print("Internet Group : "+str(group03)+" User")

    return redirect('index')

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def home(request,username):
    context = {}
    context['test'] = username

    return render(request, template_name='siteldap/home.html', context=context)

def runLogin(ip_source, group):
    host = "10.1.1.1" #ใส่ipของrouter
    username = "cisco" #username
    password = "ciscopass" #pass

    # telnet to router
    tn = telnetlib.Telnet(host)

    # enter user to config router
    tn.read_until(b"Username: ")
    tn.write(username.encode('ascii') + b"\n")

    if password:
        tn.read_until(b"Password: ")
        tn.write(password.encode('ascii') + b"\n")

    tn.read_until(b">")
    tn.write(b"enable\n")

    tn.read_until(b"Password: ")
    tn.write(password.encode('ascii') + b"\n")

    tn.read_until(b"#")
    tn.write(b"terminal length 0\n")

    tn.read_until(b"#")
    tn.write(b"conf t\n")

    if group == "01_Neighbor":
        # if check user in group neighbor ----------------------
        tn.read_until(b"(config)#")
        tn.write(b"ip access-list extended Neighbor\n")
        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"remark Allow ping PC\n")
        print("User Found")

        # can ping to pc with ip, icmp
        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"permit tcp any host 10.1.2.3 eq 80\n")
        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"permit tcp host " + ip_source.encode('ascii') + b" host 10.1.2.3 eq 80\n")
        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"permit icmp host " + ip_source.encode('ascii') + b" host 10.1.1.3\n") #กำหนดip dest pc

        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"int f0/0\n")
        tn.read_until(b"(config-if)#")
        tn.write(b"ip access-group Neighbor in\n")
        tn.read_until(b"(config-if)#")
        tn.write(b"exit\n")
        print("User can ping with ICMP")

        # response from webserver for logout
        tn.read_until(b"(config)#")
        tn.write(b"ip access-list extended FromNb\n")

        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"remark Allow response from Nb\n")

        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"permit tcp host 10.1.2.3 host " + ip_source.encode('ascii') + b" eq 80\n") 

        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"int f0/1\n")

        tn.read_until(b"(config-if)#")
        tn.write(b"ip access-group FromNb in\n")
        print("Success")

        tn.close()

    elif group == "02_Server":

        # if check user in group Server ---------------------
        tn.read_until(b"(config)#")
        tn.write(b"ip access-list extended ToServer\n")

        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"remark Allow connect to server\n")
        print("User Found")

        # connect to server http, https
        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"permit tcp any host 10.1.2.3 eq 80\n")
        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"permit tcp host " + ip_source.encode('ascii') + b" host 10.1.2.3 eq 80\n") #กำหนดip dest server
        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"permit udp host " + ip_source.encode('ascii') + b" host 10.1.2.3 eq 80\n") #กำหนดip dest server

        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"int f0/0\n")

        tn.read_until(b"(config-if)#")
        tn.write(b"ip access-group ToServer in\n")

        tn.read_until(b"(config-if)#")
        tn.write(b"exit\n")
        print("User can connect to Server Farm")

        # response from server http, https

        tn.read_until(b"(config)#")
        tn.write(b"ip access-list extended FromServer\n")

        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"remark Allow response from server\n")

        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"permit tcp host 10.1.2.3 host " + ip_source.encode('ascii') + b" eq 80 established\n")
        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"permit udp host 10.1.2.3 host " + ip_source.encode('ascii') + b" eq 80 established\n")

        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"int f0/1\n")

        tn.read_until(b"(config-if)#")
        tn.write(b"ip access-group FromServer in\n")
        print("Success")

        tn.close()

    elif group == "03_Internet":

        # if check user in group Internet ---------------------
        tn.read_until(b"(config)#")
        tn.write(b"ip access-list extended ToInternet\n")

        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"remark Allow connect to Internet\n")
        print("User Found")

        # connect to internet http, https
        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"permit tcp any host 10.1.2.3 eq 80\n")
        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"deny tcp host " + ip_source.encode('ascii') + b" host 157.240.25.35 eq 443\n")
        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"permit tcp host " + ip_source.encode('ascii') + b" any eq 80\n")
        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"permit tcp host " + ip_source.encode('ascii') + b" any eq 443\n")

        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"int f0/0\n")

        tn.read_until(b"(config-if)#")
        tn.write(b"ip access-group ToInternet in\n")

        tn.read_until(b"(config-if)#")
        tn.write(b"exit\n")
        print("User can connect with TCP")

        # response from internet http, https

        tn.read_until(b"(config)#")
        tn.write(b"ip access-list extended FromInternet\n")

        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"remark Allow response from internet\n")

        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"permit tcp any host " + ip_source.encode('ascii') + b" eq 80 established\n")
        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"permit tcp any host " + ip_source.encode('ascii') + b" eq 443 established\n")
        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"permit udp any host " + ip_source.encode('ascii') + b" eq 80 established\n")
        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"permit udp any host " + ip_source.encode('ascii') + b" eq 443 established\n")

        tn.read_until(b"(config-ext-nacl)#")
        tn.write(b"int f1/0\n")

        tn.read_until(b"(config-if)#")
        tn.write(b"ip access-group FromInternet in\n")
        print("Success")

        tn.close()

def runLogOut(group):
    host = "10.1.1.1" #ใส่ipของrouter
    username = "cisco" #username
    password = "ciscopass" #pass

    # telnet to router
    tn = telnetlib.Telnet(host)

    # enter user to config router
    tn.read_until(b"Username: ")
    tn.write(username.encode('ascii') + b"\n")

    if password:
        tn.read_until(b"Password: ")
        tn.write(password.encode('ascii') + b"\n")

    tn.read_until(b">")
    tn.write(b"enable\n")

    tn.read_until(b"Password: ")
    tn.write(password.encode('ascii') + b"\n")

    tn.read_until(b"#")
    tn.write(b"terminal length 0\n")

    tn.read_until(b"#")
    tn.write(b"conf t\n")

    if group == "01_Neighbor":

        tn.read_until(b"(config)#")
        tn.write(b"int f0/0\n")

        tn.read_until(b"(config-if)#")
        tn.write(b"no ip access-group Neighbor in\n")

        tn.read_until(b"(config-if)#")
        tn.write(b"exit\n")

        tn.read_until(b"(config)#")
        tn.write(b"no ip access-list extended Neighbor\n")

        tn.read_until(b"(config)#")
        tn.write(b"int f0/1\n")

        tn.read_until(b"(config-if)#")
        tn.write(b"no ip access-group FromNb in\n")

        tn.read_until(b"(config-if)#")
        tn.write(b"exit\n")

        tn.read_until(b"(config)#")
        tn.write(b"no ip access-list extended FromNb\n")

        tn.close()

    elif group == "02_Server":

        tn.read_until(b"(config)#")
        tn.write(b"int f0/0\n")

        tn.read_until(b"(config-if)#")
        tn.write(b"no ip access-group ToServer in\n")

        tn.read_until(b"(config-if)#")
        tn.write(b"exit\n")

        tn.read_until(b"(config)#")
        tn.write(b"no ip access-list extended ToServer\n")

        tn.read_until(b"(config)#")
        tn.write(b"int f0/1\n")

        tn.read_until(b"(config-if)#")
        tn.write(b"no ip access-group FromServer in\n")

        tn.read_until(b"(config-if)#")
        tn.write(b"exit\n")

        tn.read_until(b"(config)#")
        tn.write(b"no ip access-list extended FromServer\n")

        tn.close()

    elif group == "03_Internet":

        tn.read_until(b"(config)#")
        tn.write(b"int f0/0\n")

        tn.read_until(b"(config-if)#")
        tn.write(b"no ip access-group ToInternet in\n")

        tn.read_until(b"(config-if)#")
        tn.write(b"exit\n")

        tn.read_until(b"(config)#")
        tn.write(b"no ip access-list extended ToInternet\n")

        tn.read_until(b"(config)#")
        tn.write(b"int f1/0\n")

        tn.read_until(b"(config-if)#")
        tn.write(b"no ip access-group FromInternet in\n")

        tn.read_until(b"(config-if)#")
        tn.write(b"exit\n")

        tn.read_until(b"(config)#")
        tn.write(b"no ip access-list extended FromInternet\n")

        tn.close()
