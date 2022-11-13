import os, time
# output= subprocess.check_output([r'C:\Users\Despacito\Desktop\yara64.exe',r'C:\Users\Despacito\Desktop\demo_regedit.yara',r'C:\Users\Despacito\Desktop\virus'])
#得到bytes类型的，需要转换成为str类型，来使用str的统计函数count
begin_time = time.time()
os.system(r"yara64.exe -r rules.yar C:\\")
end_time = time.time()
print(end_time - begin_time)