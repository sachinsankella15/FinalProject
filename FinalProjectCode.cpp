#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>

using namespace std;

class SHA256 {
public:
    SHA256() { reset(); }

    string compute(const string& input) {
        reset();
        update(reinterpret_cast<const uint8_t*>(input.data()), input.size());
        finalize();
        return hex_digest();
    }

private:
    static const uint32_t K[64];
    uint32_t hash[8];
    uint8_t buffer[64];
    size_t buffer_size;
    uint64_t total_size;

    #define ROTR(x,n) ((x >> n) | (x << (32 - n)))
    #define CH(x,y,z) ((x & y) ^ (~x & z))
    #define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
    #define EP0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
    #define EP1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
    #define SIG0(x) (ROTR(x,7) ^ ROTR(x,18) ^ (x >> 3))
    #define SIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ (x >> 10))

    void reset() {
        hash[0] = 0x6a09e667; hash[1] = 0xbb67ae85; hash[2] = 0x3c6ef372; hash[3] = 0xa54ff53a;
        hash[4] = 0x510e527f; hash[5] = 0x9b05688c; hash[6] = 0x1f83d9ab; hash[7] = 0x5be0cd19;
        buffer_size = 0;
        total_size = 0;
    }

    void update(const uint8_t* data, size_t length) {
        size_t i = 0;
        while (i < length) {
            buffer[buffer_size++] = data[i++];
            if (buffer_size == 64) {
                process_block();
                buffer_size = 0;
            }
        }
        total_size += length;
    }

    void finalize() {
        buffer[buffer_size++] = 0x80;
        while (buffer_size != 56) {
            if (buffer_size > 56) {
                process_block();
                buffer_size = 0;
            }
            buffer[buffer_size++] = 0;
        }
        for (int i = 7; i >= 0; --i) buffer[buffer_size++] = (total_size * 8 >> (i * 8)) & 0xFF;
        process_block();
    }

    void process_block() {
        uint32_t w[64], a, b, c, d, e, f, g, h;
        for (int i = 0; i < 16; ++i)
            w[i] = (buffer[i * 4] << 24) | (buffer[i * 4 + 1] << 16) | (buffer[i * 4 + 2] << 8) | buffer[i * 4 + 3];
        for (int i = 16; i < 64; ++i)
            w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];

        a = hash[0], b = hash[1], c = hash[2], d = hash[3], e = hash[4], f = hash[5], g = hash[6], h = hash[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t temp1 = h + EP1(e) + CH(e, f, g) + K[i] + w[i];
            uint32_t temp2 = EP0(a) + MAJ(a, b, c);
            h = g, g = f, f = e, e = d + temp1, d = c, c = b, b = a, a = temp1 + temp2;
        }
        hash[0] += a, hash[1] += b, hash[2] += c, hash[3] += d;
        hash[4] += e, hash[5] += f, hash[6] += g, hash[7] += h;
    }

    string hex_digest() {
        stringstream ss;
        for (int i = 0; i < 8; ++i) ss << hex << setw(8) << setfill('0') << hash[i];
        return ss.str();
    }
};

const uint32_t SHA256::K[64] = { };

int main() {
    ifstream file("test.txt");
    if (!file) {
        cerr << "Error opening file." << endl;
        return 1;
    }
    
    stringstream buffer;
    buffer << file.rdbuf();
    string file_content = buffer.str();
    
    SHA256 sha256;
    string hash_result = sha256.compute(file_content);
    cout << "SHA-256 Hash of file content: " << hash_result << endl;
    return 0;
}
