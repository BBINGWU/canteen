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

aes_proof -> aes_128_prover -> aes_sss_constraints_prover

需要搞清楚做 extended_witness 的作用是什么，直接witness不行吗？搞清楚了才知道我们要对sha256和ripemd160做什么extend的操作

所以我现在先去quicksilver看看有没有对于extended witness的描述（没找到）

问问GPT，GPT没解释的话就要问问学姐，然后看看视频看看有没有解答。



quicksilver的作用就是证明：某个电路的计算是正确的。



先去看看证明是怎么做的？



# aes_sss_constraints_prover

## 参数

| 参数        | 来源              | 代表什么                        | 解释                                                         |
| ----------- | ----------------- | ------------------------------- | ------------------------------------------------------------ |
| `Lke`       | 参数集 (`params`) | key expansion的比特长度         | OWF中扩展密钥（KeyExpansion）的总bit数                       |
| `Lenc`      | 参数集 (`params`) | 加密过程的中间状态bit数         | OWF中各轮加密运算使用的state总bit数                          |
| `Nst`       | 参数集 (`params`) | AES state大小（32-bit元素数量） | OWF仿AES中，state矩阵的列数（通常=4），控制block大小         |
| `blocksize` | 计算得出          | 每个block的bit数                | 每个处理块的大小 = 32bit × Nst（一般是128bit, 160bit, 192bit等） |
| `beta`      | 计算得出          | block数                         | 需要多少个block来cover FAEST_SSS_LAMBDA比特量                |





有个不成熟的小疑惑，我没有key expand 的过程

## 调用函数

其中，2-3是else里面的

1. zk_hash_sss_3_raise_and_ipdate
2. constant_to_vole_sss_prover
3. constant_to_vole_sss_prover ： 和上面是同一个函数，第二次调用
4. aes_sss_expkey__constraints_prover（不用改
5. aes_sss_enc_constraints_prover（大概率要改







# aes_sss_enc_constraints_prover

突然感觉我是不是只要测一下 sha256的生成quicksilver的速度和ripemd的quicksilver的速度，对比aes的quicksilver的速度就可以了。

因为签名的主要时间差别在这里

连验证签名都不想写了。

# 参数



## 作用

因为aes首轮和尾轮不一样，所以这边要分三类。

- FAEST 的设计里，两轮AES变换算作一个小阶段处理，所以这里遍历的是 `FAEST_SSS_R / 2` 个阶段。





# 调用

1. aes_SSS_add_round_key_prover（要改，对AES第一轮
2. 

# aes_SSS_add_round_key_prover （AES第一轮）

是线性的操作，对应的sha256的第一轮也全部都是线性的操作，好改



# aes_extend_witness

在ase.c文件里

docker build -f Dockerfile2 . -t emp:0.1
docker-compose up





**Zero-Knowledge Proof Frameworks: A Survey**

- [Sheybani, N., Ahmed, A., Kinsy, M. (2025). arXiv.](https://arxiv.org/pdf/2502.07063)
- 概述了包括**SHA-256**的ZKP实现，并且提到**QuickSilver**作为高效框架之一。
- [作者还建立了一个网站](https://practical-zk.github.io/)



[ripemd document](https://homes.esat.kuleuven.be/~bosselae/ripemd160.html#Outline)



[有人做了一个MPC的电路汇总](https://github.com/MPC-SoK/frameworks)

里面有：

To run a secure computation, you must use an outside library. CBMC-GC includes support to **export** circuits to ABY, **Bristol**, Fairplay's SHDL, or the JustGarble format. We have not (yet) explored this functionality.



提问话术：

```
我的emp-zk/test/bool下面有个sha256.cpp:#include <emp-zk/emp-zk.h>
#include <emp-tool/emp-tool.h> // 这个头文件里面有clock_start和time_from

#include <iostream>
using namespace std;
const string circuit_file_location =
    macro_xstr(EMP_CIRCUIT_PATH) + string("bristol_format/");
const int threads = 1;

// 明文执行 SHA-256 电路得到正确的参考输出
void get_plain(bool *res, bool *wit, const char *file) {
  setup_plain_prot(false, "");
  BristolFormat cf(file);
  vector<Bit> W, P, O;
  W.resize(cf.n1);
  for (int i = 0; i < cf.n1; ++i)
    W[i] = Bit(wit[i], PUBLIC);
  O.resize(cf.n1);
  for (int i = 0; i < cf.n1; ++i)
    O[i] = Bit(false, PUBLIC);
  cf.compute(O.data(), W.data(), P.data());
  for (int i = 0; i < 64; ++i)
    cf.compute(O.data(), O.data(), P.data());
  for (int i = 0; i < cf.n3; ++i) {
    res[i] = O[i].reveal<bool>(PUBLIC);
  }
  finalize_plain_prot();
}

//
int main(int argc, char **argv) {
  int party, port;
  parse_party_and_port(argv, &party, &port);
  string filename = circuit_file_location + string("sha-256.txt");
  bool *witness = new bool[512];
  memset(witness, false, 512);
  bool *output = new bool[256];
  get_plain(output, witness, filename.c_str());
  BoolIO<NetIO> *ios[threads];
  for (int i = 0; i < threads; ++i)
    ios[i] = new BoolIO<NetIO>(
        new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i),
        party == ALICE);

  // // original 
  // setup_zk_bool<BoolIO<NetIO>>(ios, threads, party);
  // vector<Bit> W, O;
  // for (int i = 0; i < 512; ++i)
  //   W.push_back(Bit(witness[i], ALICE));
  // O.resize(512);
  // for (int i = 0; i < 512; ++i)
  //   O[i] = Bit(false, PUBLIC);

  // BristolFormat cf(filename.c_str());
  // cf.compute((block *)O.data(), (block *)W.data(), nullptr);
  // for (int i = 0; i < 64; ++i)
  //   cf.compute(O.data(), O.data(), nullptr);
  // for (int i = 0; i < 256; ++i) {
  //   bool tmp = O[i].reveal<bool>(PUBLIC);
  //   if (tmp != output[i])
  //     error("wrong");
  // }

  // bool cheated = finalize_zk_bool<BoolIO<NetIO>>();
  // if (cheated)
  //   error("cheated\n");

  // change
  setup_zk_bool<BoolIO<NetIO>>(ios, threads, party);
  vector<Bit> W, O;
  for (int i = 0; i < 512; ++i)
      W.push_back(Bit(witness[i], ALICE));
  O.resize(512);
  for (int i = 0; i < 512; ++i)
      O[i] = Bit(false, PUBLIC);
  
  BristolFormat cf(filename.c_str());
  
  auto proof_start = clock_start();
  cf.compute((block *)O.data(), (block *)W.data(), nullptr);
  for (int i = 0; i < 64; ++i)
      cf.compute(O.data(), O.data(), nullptr);
  cout << "Proof generation time: " << time_from(proof_start) << " us" << endl;
  
  auto verify_start = clock_start();
  for (int i = 0; i < 256; ++i) {
      bool tmp = O[i].reveal<bool>(PUBLIC);
      if (tmp != output[i])
          error("wrong");
  }
  cout << "Verification time: " << time_from(verify_start) << " us" << endl;
  
  bool cheated = finalize_zk_bool<BoolIO<NetIO>>();
  if (cheated)
      error("cheated\n");
  

  for (int i = 0; i < threads; ++i) {
    delete ios[i]->io;
    delete ios[i];
  }

  return 0;
}现在我想搞一个类似的ripemd的测一下时间，我要怎么做？一步一步教我。
```

./run ./bin/test_bool_sha256





export 指令

```
root@4f5a3b915300:~/CBMC-GC-2/examples/ripemd160# circuit-utils --remove-or-gates --as-bristol bristol_circuit.txt 
Replacing all (A or B) gates by -(-A and -B)
Number of gates before: 14976
Number of gates after: 16548
```

```
~/Downloads/毕业论文/code/zhubo/emp-zk on  master! ⌚ 10:12:53
$ ./run ./bin/test_bool_ripemd
connected
connected
Proof size (communication): 37057 bytes
=== PROVER (ALICE) ===
Proof generation took 0.006033 seconds.
Verification took 0.009059 seconds.
✅ Zero-Knowledge Proof Verified Successfully!
Proof size (communication): 553009 bytes
=== VERIFIER (BOB) ===
Proof checking took 0.005379 seconds.
Verification took 0.008301 seconds.
✅ Zero-Knowledge Proof Verified Successfully!
```

左边

```
~/Downloads/毕业论文/code/zhubo/emp-zk on  master! ⌚ 10:06:50
$ ./bin/test_bool_sha256 1 12345

connected
Proof size (communication): 188641 bytes
=== PROVER (ALICE) ===
Proof generation took 0.050567 seconds.
Verification took 0.011801 seconds.
Zero-Knowledge Proof Verified Successfully!
```

右边

```
~/Downloads/毕业论文/code/zhubo/emp-zk on  master! ⌚ 10:06:50
$ ./bin/test_bool_sha256 2 12345

connected
Proof size (communication): 553009 bytes
=== VERIFIER (BOB) ===
Proof checking took 0.046496 seconds.
Verification took 0.009920 seconds.
Zero-Knowledge Proof Verified Successfully!
```



问话

~/Downloads/毕业论文/code/zhubo/emp-tool/emp-tool/circuits/files on  master! ⌚ 3:09:17 $ tree . ├── bristol_fashion │  ├── Keccak_f.txt │  ├── aes_128.txt │  ├── aes_192.txt │  ├── aes_256.txt │  ├── sha256.txt │  └── sha512.txt └── bristol_format    ├── AES-non-expanded.txt    ├── adder_32bit.txt    ├── sha-1.txt    ├── sha-256-big.txt    └── sha-256.txt 3 directories, 11 files 有这些文件，能不能跑一个aes_128的时间来看看

###### ChatGPT 说：



~/Downloads/毕业论文/code/zhubo/emp-zk on  master! ⌚ 3:00:43
$ ./run ./bin/test_bool_sha256
connected
connected
Proof generation time: 52323 us
Verification time: 3 us
Proof generation time: 43552 us
Verification time: 3 us



~/Downloads/毕业论文/code/zhubo/emp-zk on  master! ⌚ 2:59:49
$ ./run ./bin/test_bool_ripemd 
connected
connected
Proof generation time: 54771 us
Verification time: 3 us
Proof generation time: 41066 us
Verification time: 2 us



有个奇妙的文件在这里

```
$ sudo cp ~/Downloads/毕业论文/code/zhubo/emp-tool/emp-tool/circuits/files/bristol_format/aes128.txt aes128.txt
```



txt文件位置

```

~/Downloads/毕业论文/code/zhubo/emp-tool/emp-tool/circuits/files on  master! ⌚ 10:32:12
$ TREE
.
├── bristol_fashion
│   ├── Keccak_f.txt
│   ├── aes_128.txt
│   ├── aes_192.txt
│   ├── aes_256.txt
│   ├── ripemd160.txt
│   ├── sha256.txt
│   └── sha512.txt
└── bristol_format
    ├── AES-non-expanded.txt
    ├── adder_32bit.txt
    ├── aes128.txt
    ├── ripemd160.txt
    ├── sha-1.txt
    ├── sha-256-big.txt
    └── sha-256.txt

3 directories, 14 files
```





# 参考学习

[emp 指南](https://emp-toolkit.github.io/emp-doc/html/md___users_wangxiao_git_emp-toolkit_emp-sh2pc__r_e_a_d_m_e.html)

[知道cbmc-gc的使用，export电路方法](https://gitlab.com/securityengineering/CBMC-GC-2)

[FETA 这篇论文里有AES 和sha256的 对比 可以比照一下自己实现的差异](https://dl.acm.org/doi/pdf/10.1145/3548606.3559354)
