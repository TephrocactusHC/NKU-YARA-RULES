
'''
#小端存储，有点恶心
with open("D:\\yara64.exe", 'rb') as fp:
    flag1 = fp.read(2) #读取文件前两个字节
    fp.seek(0x3c,0)
    flag2 = fp.read(1)
    a=ord(flag2)
    fp.seek(0x3d,0)
    flag2 = fp.read(1)
    b=ord(flag2)
    x=(b*16*16)+a
    fp.seek(x)
    flag3=fp.read(4)
if flag1==b'MZ' and flag3==b'PE\x00\x00':
    print("ispe")
'''
import binascii,functools,os
def judgePE(path):
    with open(path, 'rb') as fp:
        flag1 = fp.read(2)
        print(flag1)
        fp.seek(0x3c,0)
        flag2 = fp.read(2)
        print(flag2)
        newflag=binascii.hexlify(flag2[::-1])
        newflag=newflag.decode(encoding='utf-8')
        if newflag=='':
            pass
        else:
            newflag=int(newflag,16)
            fp.seek(newflag)
            flag3 = fp.read(4)
            print(flag3)
            if flag1 == b'MZ' and flag3 == b'PE\x00\x00':
                print('ispe')
            else:
                pass

if __name__=='__main__':
    thdpath=input('please input a path:')
    judgePE(thdpath)



