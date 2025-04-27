# FAEST - Reference implementation

## Dependencies

For building:
* `meson` version 0.57 or newer
* `ninja` (depending on the build system generator selected via `meson`)

For tests:
* `boost` (unit test framework)
* `NTL`

On Debian-based Linux distributions:
```sh
apt install meson ninja-build # for build dependencies
apt install libboost-test-dev libntl-dev # for test dependencies
```

Both `meson` and `ninja` are also available via PyPI:
```sh
pip install meson ninja
```

## Building

```sh
mkdir build
cd build
meson ..
ninja
ninja test
```

building 过程中使用到的工具的关系：

> 你写 `meson.build` ➔ 用 `meson` 解释 ➔ 生成 `.ninja` 文件 ➔ 用 `ninja` 执行编译

上面的building过程就是：

在根目录下找到meson.build 文件，然后按照这个文件在build目录下写好ninja指令，接着用ninja编译这些指令，最后执行生成的test。



meson文件的结构如下：

1. 项目基本信息
2. 编译器特性检测
3. 参数集设置（`After changing the parameter sets, be sure to run crypto_sign_generator.py to create the corresponding meson files.`）





# 修改faest_sign函数

AES 128 指的是密钥长度是128比特/位，16字节（➗8）

每一块明文都要求是16字节，所以我sha256的输入也是16字节，保证 “秘密的长度大小是一致的”。

原本的使用的哈希事shake（也不知道这是个啥



每次test的时候都把输出写进 `/Users/bingwu/Downloads/毕业论文/code/canteen/faest-ref-main/build/meson-logs/testlog.txt`



## 参数

ell 明文长度，可以去参数集中改为0（对替换复合函数后）

faest_sign 的输入函数里面，有一个 rho，这个是为了根据确定性签名和非确定性签名来定的，无所谓，简单起见可以定为0.

| 变量            | 含义                      | 中文解释                                                     | 备注       |
| --------------- | ------------------------- | ------------------------------------------------------------ | ---------- |
| `ell`           | 明文长度参数（L）         | 明文长度，VOLE输入的比特数，通常对应一个编码块大小           | 单位：bit  |
| `ell_bytes`     | 明文长度对应的字节数      | `ell` 除以8，单位换算成byte（字节）                          | 单位：byte |
| `lambda`        | 安全参数                  | 安全级别（比如128/192/256位），影响签名抗攻击性              | 单位：bit  |
| `tau`           | 解码器参数（subset size） | challenge解码时选取的子集大小，影响解码策略和效率            |            |
| `ell_hat`       | 扩展明文长度              | `ell` 加上3倍 `lambda` 再加通用哈希的扩展位数 `UNIVERSAL_HASH_B_BITS`，用于VOLE扩展 | 单位：bit  |
| `ell_hat_bytes` | 扩展明文字节数            | `ell_hat` 除以8，单位换算成byte（字节）                      | 单位：byte |
| `w_grind`       | Grind难度参数             | 控制 challenge3 grind 需要满足的最小Hamming权重条件（更安全但增加签名时间） |            |

## 不需要修改

vole_commit 不需要修改



## 修改

太好啦 这样看起来我的sign函数要改的地方很少，要改的地方主要是witness生成和owf证明

params->owf_output_size 这个也要修改，ripemd160的输出是160比特（20字节）



xor_u8_array 这个地方可能要修改，因为输入中有witness（我们做的proof会有问题）



aes_proof 需要重点修改的地方，先看懂这里的逻辑。这里和quicksilver有关系，可以看看 v2里面的OWF prove函数是怎么做的。（所以预备知识应该要补充quick silver的内容）

需要搞清楚做 extended_witness 的作用是什么，直接witness不行吗？搞清楚了才知道我们要对sha256和ripemd160做什么extend的操作

所以我现在先去quicksilver看看有没有对于extended witness的描述（没找到）

问问GPT，GPT没解释的话就要问问学姐，然后看看视频看看有没有解答。



quicksilver的作用就是证明：某个电路的计算是正确的。



先去看看证明是怎么做的？
