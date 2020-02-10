import json

import chardet
import requests
import xlwt
import time
import random
import json

file_name = '微博数据2.xls'
def processing_data(content_list):
    # 创建一个workbook 设置编码
    workbook = xlwt.Workbook(encoding='utf-8')
    # 创建一个worksheet
    worksheet = workbook.add_sheet('My Worksheet')
    # 写入excel
    for i, content in enumerate(content_list):
        for x, info in enumerate(content):
            worksheet.write(i, x, label=info)  # 将数据存入excel
    # 保存
    workbook.save(file_name)


def get_user_address(uid):
    url = 'https://m.weibo.cn/api/container/getIndex?&type=uid&value='+ str(uid)+ '&filter=hot&sum_comment_number=265&filter_tips_before=0&from=singleWeiBo&__rnd=1581266843777'
    print(url)
    ret1 = requests.get(url)
    ret1 = json.loads(ret1.text)['data']
    containid = ret1['tabsInfo']['tabs'][0]['containerid']
    # print(ret1)
    gender = ret1['userInfo']['gender']
    url = url+'&containerid='+ containid
    # print(url)
    ret2 = requests.get(url)
    ret2 = json.loads(ret2.text)['data']
    address = ret2['cards'][0]['card_group'][0]['item_content']
    print(address, gender)
    time.sleep(random.randint(2,3))
    return address, gender


with open('shuju.txt', 'r', encoding='utf-8')as f:
    content = f.read()
ret = content.split('\n')
all_info = []

for one in ret:
    one_info = one.split('***')
    print(one_info)
    try:
        address, gender = get_user_address(one_info[0])
        one_info.append(address)
        one_info.append(gender)
        all_info.append(one_info)
    except:
        #运行出误提交
        processing_data(all_info)
# 没问题爬完提交
processing_data(all_info)
