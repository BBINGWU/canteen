#include <emp-tool/emp-tool.h>
#include "ripemd160_emp.cpp" // 或者 #include "ripemd160_emp.h"
#include <emp-sh2pc/emp-sh2pc.h>

using namespace emp;
using namespace std;

int main(int argc, char** argv) {
    // emp 初始化，模拟单机模式
    int party = ALICE;
    NetIO * io = new NetIO(nullptr, 12345);
    setup_semi_honest(io, party);

    // 测试输入："abc"
    string test_str = "abc";
    vector<Bit> input_bits;
    for (auto ch : test_str) {
        for (int i = 0; i < 8; ++i)
            input_bits.push_back(Bit((ch >> i) & 1, PUBLIC));  // PUBLIC测试
    }
    // padding补到512bit
    while (input_bits.size() < 512) {
        input_bits.push_back(Bit(0, PUBLIC));
    }

    // 调用ripemd160
    vector<Bit> hash_bits = ripemd160(input_bits);

    // 输出结果
    cout << "RIPEMD-160 Hash (bit-by-bit): ";
    for (int i = 0; i < hash_bits.size(); ++i) {
        cout << hash_bits[i].reveal<bool>();
    }
    cout << endl;

    delete io;
}
