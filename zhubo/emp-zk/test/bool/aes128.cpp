#include <emp-zk/emp-zk.h>
#include <emp-tool/emp-tool.h>
#include <iostream>
using namespace std;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH) + string("bristol_format/");
const int threads = 1;

// 明文执行 AES-128 电路得到参考输出
void get_plain(bool *res, bool *wit, const char *file) {
    setup_plain_prot(false, "");
    BristolFormat cf(file);
    vector<Bit> W, P, O;

    W.resize(cf.n1);
    for (int i = 0; i < cf.n1; ++i)
        W[i] = Bit(wit[i], PUBLIC);

    O.resize(cf.n3);
    for (int i = 0; i < cf.n3; ++i)
        O[i] = Bit(false, PUBLIC);

    cf.compute(O.data(), W.data(), P.data());

    for (int i = 0; i < cf.n3; ++i)
        res[i] = O[i].reveal<bool>(PUBLIC);

    finalize_plain_prot();
}

int main(int argc, char** argv) {
    int party, port;
    parse_party_and_port(argv, &party, &port);

    string filename = circuit_file_location + string("aes128.txt");
    cout << "[main] Circuit file path: " << filename << endl;

    // 读取文件并打印前5行，检查是否正确
    ifstream fin(filename.c_str());
    if (!fin.is_open()) {
        cerr << "Error opening file: " << filename << endl;
        return -1;
    }
    cout << "[main] --- Circuit file content start ---" << endl;
    string line;
    int line_cnt = 0;
    while (getline(fin, line) && line_cnt < 5) {
        cout << line << endl;
        line_cnt++;
    }
    cout << "[main] --- Circuit file content end ---" << endl;
    fin.close();

    // 原来的逻辑继续执行
    bool *witness = new bool[128];
    memset(witness, false, 128);
    bool *output = new bool[128];

    get_plain(output, witness, filename.c_str());




    BoolIO<NetIO> *ios[threads];
    for (int i = 0; i < threads; ++i)
        ios[i] = new BoolIO<NetIO>(
            new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i),
            party == ALICE
        );

    setup_zk_bool<BoolIO<NetIO>>(ios, threads, party);

    vector<Bit> W, O;
    for (int i = 0; i < 128; ++i)
        W.push_back(Bit(witness[i], ALICE));

    O.resize(128);
    for (int i = 0; i < 128; ++i)
        O[i] = Bit(false, PUBLIC);

    BristolFormat cf(filename.c_str());

    // Proof generation
    auto proof_start = clock_start();
    cf.compute((block *)O.data(), (block *)W.data(), nullptr);
    printf("Proof size (communication): %lld bytes\n", ios[0]->io->counter);

    cout << "Proof generation time: " << time_from(proof_start) << " us" << endl;

    // Verification
    auto verify_start = clock_start();
    for (int i = 0; i < 128; ++i) {
        bool tmp = O[i].reveal<bool>(PUBLIC);
        if (tmp != output[i])
            error("Mismatch at output bit %d\n", i);
    }
    cout << "Verification time: " << time_from(verify_start) << " us" << endl;

    bool cheated = finalize_zk_bool<BoolIO<NetIO>>();
    if (cheated)
        error("Cheating detected!\n");


    for (int i = 0; i < threads; ++i) {
        delete ios[i]->io;
        delete ios[i];
    }

    delete[] witness;
    delete[] output;

    return 0;
}
