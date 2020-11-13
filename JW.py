import os
import struct
#0 Client Hello
#1 Client Key Exchange
#2 Server Hello
#3 Certificate
#4 Server Key Exchange
def get_field(filename):
    command = {}

    command[0] = 'tshark -r ' + filename + ' -Y "ssl.handshake.type==1" '
    command[0]+= '-Tfields -e ip.src -e ip.dst -e tcp.dstport -e tcp.srcport '
    command[0]+= '-e ssl.record.version -e ssl.handshake.session_id_length '
    command[0]+= '-e ssl.handshake.cipher_suites_length -e ssl.handshake.ciphersuite '
    command[0]+= '-e ssl.handshake.comp_method -e ssl.handshake.extensions_length '
    command[0]+= '-e ssl.handshake.extension.type -e ssl.handshake.extension.len '
    command[0]+= '-e ssl.handshake.extensions_reneg_info_len -e ssl.handshake.extensions_server_name_list_len '
    command[0]+= '-e ssl.handshake.extensions_server_name -e ssl.handshake.extensions_elliptic_curves_length '
    command[0]+= '-e ssl.handshake.extensions_elliptic_curve -e ssl.handshake.extensions_ec_point_formats_length '
    command[0]+= '-e ssl.handshake.extensions_ec_point_format > 0.txt'

    command[1] = 'tshark -r ' + filename + ' -Y "ssl.handshake.type==16" '
    command[1]+= '-Tfields -e ip.src -e ip.dst -e tcp.dstport -e tcp.srcport '
    command[1]+= '-e ssl.handshake.client_point_len -e ssl.handshake.client_point > 1.txt'

    command[2] = 'tshark -r ' + filename + ' -Y "ssl.handshake.type==2" '
    command[2]+= '-Tfields -e ip.src -e ip.dst -e tcp.dstport -e tcp.srcport '
    command[2]+= '-e ssl.handshake.session_id_length -e ssl.handshake.session_id '
    command[2]+= '-e ssl.handshake.ciphersuite -e ssl.handshake.comp_method '
    command[2]+= '-e ssl.handshake.extensions_length -e ssl.handshake.extension.type '
    command[2]+= '-e ssl.handshake.extension.len -e ssl.handshake.extensions_reneg_info_len '
    command[2]+= '-e ssl.handshake.extensions_ec_point_formats_length -e ssl.handshake.extensions_ec_point_format '
    command[2]+= '> 2.txt'

    command[3] = 'tshark -r ' + filename + ' -Y "ssl.handshake.type==11" '
    command[3]+= '-Tfields -e ip.src -e ip.dst -e tcp.dstport -e tcp.srcport '
    command[3]+= '-e ssl.handshake.certificate > 3.txt'

    command[4] = 'tshark -r ' + filename + ' -Y "ssl.handshake.type==12" '
    command[4]+= '-Tfields -e ip.src -e ip.dst -e tcp.dstport -e tcp.srcport '
    command[4]+= '-e ssl.handshake.server_curve_type -e ssl.handshake.server_named_curve '
    command[4]+= '-e ssl.handshake.server_point_len -e ssl.handshake.server_point '
    command[4]+= '-e ssl.handshake.sig_len -e ssl.handshake.sig > 4.txt'

    for i in range(5):
        os.system(command[i])

def get_data():
    #data[ip:port:ip:port][handsake_type][option] = value
    data = {}
   
    #client Hello
    f = open('./0.txt')
    temp = f.read().split('\n')[:-1]
    f.close()
    for line in temp:
        temp2 = line.split('\t')
        data[temp2[0]+temp2[1]+temp2[2]+temp2[3]] = {}
        data[temp2[0]+temp2[1]+temp2[2]+temp2[3]][0] = {}
        for i in range(4,len(temp2)):
            if(temp2[i] == ''):
                temp2[i] = '0'
            data[temp2[0]+temp2[1]+temp2[2]+temp2[3]][0][i-4] = temp2[i]

    #client keyexchange
    f = open('./1.txt')
    temp = f.read().split('\n')[:-1]
    f.close()
    for line in temp:
        temp2 = line.split('\t')
        data[temp2[0]+temp2[1]+temp2[2]+temp2[3]][1] = {}
        for i in range(4,len(temp2)):
            if(temp2[i] == ''):
                temp2[i] = '0'
            data[temp2[0]+temp2[1]+temp2[2]+temp2[3]][1][i-4] = temp2[i]

    #server Hello
    f = open('./2.txt')
    temp = f.read().split('\n')[:-1]
    f.close()
    for line in temp:
        temp2 = line.split('\t')
        #data[temp2[0]+temp2[1]+temp2[2]+temp2[3]] = {}
        data[temp2[1]+temp2[0]+temp2[3]+temp2[2]][2] = {}
        for i in range(4,len(temp2)):
            if(temp2[i] == ''):
                temp2[i] = '0'
            data[temp2[1]+temp2[0]+temp2[3]+temp2[2]][2][i-4] = temp2[i]

    #certificate
    f = open('./3.txt')
    temp = f.read().split('\n')[:-1]
    f.close()
    for line in temp:
        temp2 = line.split('\t')
        #data[temp2[0]+temp2[1]+temp2[2]+temp2[3]] = {}
        data[temp2[1]+temp2[0]+temp2[3]+temp2[2]][3] = {}
        for i in range(4,len(temp2)):
            data[temp2[1]+temp2[0]+temp2[3]+temp2[2]][3][i-4] = temp2[i]

   #server key exchange
    f = open('./4.txt')
    temp = f.read().split('\n')[:-1]
    f.close()
    for line in temp:
        temp2 = line.split('\t')
        #data[temp2[0]+temp2[1]+temp2[2]+temp2[3]] = {}
        data[temp2[1]+temp2[0]+temp2[3]+temp2[2]][4] = {}
        for i in range(4,len(temp2)):
            if(temp2[i] == ''):
                temp2[i] = '0'
            data[temp2[1]+temp2[0]+temp2[3]+temp2[2]][4][i-4] = temp2[i]

    return data

def data_set(data,name):
    for ip_port in data:
        result = ''
        #cilent Hello
        if(data[ip_port].has_key(1) == False):
            return
        if(data[ip_port].has_key(2) == False):
            return
        if(data[ip_port].has_key(3) == False):
            return
        if(data[ip_port].has_key(4) == False):
            return

        for op in data[ip_port][0]:
            if(',' in data[ip_port][0][op]):
                temp = data[ip_port][0][op].split(',')
                for value in temp:
                    if('0x' in value):
                        result += struct.pack(">I",int(value,16))
                    else:
                        result += struct.pack(">I",int(value))
            else:
                if('0x' in data[ip_port][0][op]):
                    result += struct.pack(">I",int(data[ip_port][0][op],16))
                elif('.' in data[ip_port][0][op]):
                    result += data[ip_port][0][op]
                else:
                    result += struct.pack(">I",int(data[ip_port][0][op]))

        #client key exchange
        result += struct.pack(">I",int(data[ip_port][1][0]))
        temp = data[ip_port][1][1].split(':')
        for value in temp:
            result += struct.pack(">B",int(value,16))

        #server Hello
        for op in data[ip_port][2]:
            if(',' in data[ip_port][2][op]):
                temp = data[ip_port][2][op].split(',')
                for value in temp:
                    if('0x' in value):
                        result += struct.pack(">I",int(value,16))
                    else:
                        result += struct.pack(">I",int(value))
            elif(':' in data[ip_port][2][op]):
                temp = data[ip_port][2][op].split(':')
                for value in temp:
                    result += struct.pack(">B",int(value,16))
            else:
                if('0x' in data[ip_port][2][op]):
                    result += struct.pack(">I",int(data[ip_port][2][op],16))
                else:
                    result += struct.pack(">I",int(data[ip_port][2][op]))

        #certificate
        temp = data[ip_port][3][0].replace(',',':').split(':') #check 2 certificate replace
        for value in temp:
            result += struct.pack(">B",int(value,16))

        #server key exchange
        for op in data[ip_port][4]:
            if(':' in data[ip_port][4][op]):
                temp = data[ip_port][4][op].split(':')
                for value in temp:
                    result += struct.pack(">B",int(value,16))
            else:
                if('0x' in data[ip_port][4][op]):
                    result += struct.pack(">I",int(data[ip_port][4][op],16))
                else:
                    result += struct.pack(">I",int(data[ip_port][4][op]))

        make_file(name+ip_port,result)

def make_file(name,data):
    f = open(name+'_binary','wb')
    f.write(data)
    f.close()

if __name__ =='__main__':
    os.system('ls | grep .pcap > filelist')
    f = open('filelist')
    filelist = f.read()[:-1].split('\n')
    f.close()
    for name in filelist:
        print name
        get_field(name)
        data = get_data()
        set_data = data_set(data,name)
        os.system('mv '+name+' ./pcap/'+name)
