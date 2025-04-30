// #include <emp-zk/emp-zk.h>
// #include <emp-tool/emp-tool.h> // 这个头文件里面有clock_start和time_from

// #include <iostream>
// using namespace std;
// const string circuit_file_location =
//     macro_xstr(EMP_CIRCUIT_PATH) + string("bristol_format/");
// const int threads = 1;

// // 明文执行 SHA-256 电路得到正确的参考输出
// void get_plain(bool *res, bool *wit, const char *file) {
//   setup_plain_prot(false, "");
//   BristolFormat cf(file);
//   vector<Bit> W, P, O;
//   W.resize(cf.n1);
//   for (int i = 0; i < cf.n1; ++i)
//     W[i] = Bit(wit[i], PUBLIC);
//   O.resize(cf.n1);
//   for (int i = 0; i < cf.n1; ++i)
//     O[i] = Bit(false, PUBLIC);
//   cf.compute(O.data(), W.data(), P.data());
//   for (int i = 0; i < 64; ++i)
//     cf.compute(O.data(), O.data(), P.data());
//   for (int i = 0; i < cf.n3; ++i) {
//     res[i] = O[i].reveal<bool>(PUBLIC);
//   }
//   finalize_plain_prot();
// }

// // original
// // int main(int argc, char **argv) {
// //   int party, port;
// //   parse_party_and_port(argv, &party, &port);
// //   string filename = circuit_file_location + string("sha-256.txt");
// //   bool *witness = new bool[512];
// //   memset(witness, false, 512);
// //   bool *output = new bool[256];
// //   get_plain(output, witness, filename.c_str());
// //   BoolIO<NetIO> *ios[threads];
// //   for (int i = 0; i < threads; ++i)
// //     ios[i] = new BoolIO<NetIO>(
// //         new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i),
// //         party == ALICE);

// //   // // original 
// //   // setup_zk_bool<BoolIO<NetIO>>(ios, threads, party);
// //   // vector<Bit> W, O;
// //   // for (int i = 0; i < 512; ++i)
// //   //   W.push_back(Bit(witness[i], ALICE));
// //   // O.resize(512);
// //   // for (int i = 0; i < 512; ++i)
// //   //   O[i] = Bit(false, PUBLIC);

// //   // BristolFormat cf(filename.c_str());
// //   // cf.compute((block *)O.data(), (block *)W.data(), nullptr);
// //   // for (int i = 0; i < 64; ++i)
// //   //   cf.compute(O.data(), O.data(), nullptr);
// //   // for (int i = 0; i < 256; ++i) {
// //   //   bool tmp = O[i].reveal<bool>(PUBLIC);
// //   //   if (tmp != output[i])
// //   //     error("wrong");
// //   // }

// //   // bool cheated = finalize_zk_bool<BoolIO<NetIO>>();
// //   // if (cheated)
// //   //   error("cheated\n");

// //   // change
// //   setup_zk_bool<BoolIO<NetIO>>(ios, threads, party);
// //   vector<Bit> W, O;
// //   for (int i = 0; i < 512; ++i)
// //       W.push_back(Bit(witness[i], ALICE));
// //   O.resize(512);
// //   for (int i = 0; i < 512; ++i)
// //       O[i] = Bit(false, PUBLIC);
  
// //   BristolFormat cf(filename.c_str());
  
// //   // auto proof_start = clock_start();
// //   // cf.compute((block *)O.data(), (block *)W.data(), nullptr);
// //   // for (int i = 0; i < 64; ++i)
// //   //     cf.compute(O.data(), O.data(), nullptr);
// //   // cout << "Proof generation time: " << time_from(proof_start) << " us" << endl;

// //   clock_t proof_start, proof_end;
// //   double proof_time_used;
  
// //   proof_start = clock();
  
// //   cf.compute((block *)O.data(), (block *)W.data(), nullptr);
// //   for (int i = 0; i < 64; ++i)
// //       cf.compute(O.data(), O.data(), nullptr);
  
// //   proof_end = clock();
// //   proof_time_used = ((double)(proof_end - proof_start)) / CLOCKS_PER_SEC;
// //   printf("Proof generation took %f seconds.\n", proof_time_used);
  
  
// //   // auto verify_start = clock_start();
// //   // for (int i = 0; i < 256; ++i) {
// //   //     bool tmp = O[i].reveal<bool>(PUBLIC);
// //   //     if (tmp != output[i])
// //   //         error("wrong");
// //   // }
// //   // cout << "Verification time: " << time_from(verify_start) << " us" << endl;

// //   clock_t verify_start, verify_end;
// //   double verify_time_used;

// //   verify_start = clock();

// //   for (int i = 0; i < 256; ++i) {
// //       bool tmp = O[i].reveal<bool>(PUBLIC);
// //       if (tmp != output[i])
// //           error("wrong");
// //   }

// //   verify_end = clock();
// //   verify_time_used = ((double)(verify_end - verify_start)) / CLOCKS_PER_SEC;
// //   printf("Verification took %f seconds.\n", verify_time_used);

  
// //   bool cheated = finalize_zk_bool<BoolIO<NetIO>>();
// //   if (cheated)
// //       error("cheated\n");
  

// //   for (int i = 0; i < threads; ++i) {
// //     delete ios[i]->io;
// //     delete ios[i];
// //   }

// //   return 0;
// // }

// new new new
#include <emp-zk/emp-zk.h>
#include <emp-tool/emp-tool.h> // clock_start, time_from
#include <iostream>
using namespace std;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH) + string("bristol_format/");
const int threads = 1;

// 明文执行SHA-256电路，得到正确参考输出（仅开发测试用）
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

    for (int i = 0; i < cf.n3; ++i)
        res[i] = O[i].reveal<bool>(PUBLIC);

    finalize_plain_prot();
}

int main(int argc, char **argv) {
    int party, port;
    parse_party_and_port(argv, &party, &port);

    string filename = circuit_file_location + string("sha-256.txt");

    bool *witness = new bool[512];
    memset(witness, false, 512);
    bool *output = new bool[256];  // 注意 sha256 输出256位

    get_plain(output, witness, filename.c_str());

    BoolIO<NetIO> *ios[threads];
    for (int i = 0; i < threads; ++i)
        ios[i] = new BoolIO<NetIO>(
            new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i),
            party == ALICE
        );

    setup_zk_bool<BoolIO<NetIO>>(ios, threads, party);

    vector<Bit> W, O;
    for (int i = 0; i < 512; ++i)
        W.push_back(Bit(witness[i], ALICE));
    O.resize(512);
    for (int i = 0; i < 512; ++i)
        O[i] = Bit(false, PUBLIC);

    BristolFormat cf(filename.c_str());

    // Proof generation
    auto proof_start = clock_start();
    cf.compute((block *)O.data(), (block *)W.data(), nullptr);
    for (int i = 0; i < 64; ++i)
        cf.compute(O.data(), O.data(), nullptr);
    printf("Proof size (communication): %lld bytes\n", ios[0]->io->counter);

    cout << "Proof generation time: " << time_from(proof_start) << " us" << endl;

    // Verification
    auto verify_start = clock_start();
    for (int i = 0; i < 256; ++i) {
        bool tmp = O[i].reveal<bool>(PUBLIC);
        if (tmp != output[i])
            error(("Mismatch at output bit " + std::to_string(i) + "\n").c_str());
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
