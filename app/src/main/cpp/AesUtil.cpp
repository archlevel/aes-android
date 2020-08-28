#include <jni.h>

#include <stdint.h>
#include <iostream>
#include <stdlib.h>
using namespace std;

#include <vector>

typedef std::vector<unsigned char> ByteArray;

#define BLOCK_SIZE 16

class Aes256 {

public:
    Aes256(const ByteArray& key);
    ~Aes256();

    static ByteArray::size_type encrypt(const ByteArray& key, const ByteArray& plain, ByteArray& encrypted);
    static ByteArray::size_type encrypt(const ByteArray& key, const unsigned char* plain, const ByteArray::size_type plain_length, ByteArray& encrypted);
    static ByteArray::size_type decrypt(const ByteArray& key, const ByteArray& encrypted, ByteArray& plain);
    static ByteArray::size_type decrypt(const ByteArray& key, const unsigned char* encrypted, const ByteArray::size_type encrypted_length, ByteArray& plain);

    ByteArray::size_type encrypt_start(const ByteArray::size_type plain_length, ByteArray& encrypted);
    ByteArray::size_type encrypt_continue(const ByteArray& plain, ByteArray& encrypted);
    ByteArray::size_type encrypt_continue(const unsigned char* plain, const ByteArray::size_type plain_length, ByteArray& encrypted);
    ByteArray::size_type encrypt_end(ByteArray& encrypted);

    ByteArray::size_type decrypt_start(const ByteArray::size_type encrypted_length);
    ByteArray::size_type decrypt_continue(const ByteArray& encrypted, ByteArray& plain);
    ByteArray::size_type decrypt_continue(const unsigned char* encrypted, const ByteArray::size_type encrypted_length, ByteArray& plain);
    ByteArray::size_type decrypt_end(ByteArray& plain);

private:
    ByteArray            m_key;
    ByteArray            m_salt;
    ByteArray            m_rkey;

    unsigned char        m_buffer[3 * BLOCK_SIZE];
    unsigned char        m_buffer_pos;
    ByteArray::size_type m_remainingLength;

    bool                 m_decryptInitialized;

    void check_and_encrypt_buffer(ByteArray& encrypted);
    void check_and_decrypt_buffer(ByteArray& plain);

    void encrypt(unsigned char *buffer);
    void decrypt(unsigned char *buffer);

    void expand_enc_key(unsigned char *rc);
    void expand_dec_key(unsigned char *rc);

    void sub_bytes(unsigned char *buffer);
    void sub_bytes_inv(unsigned char *buffer);

    void copy_key();

    void add_round_key(unsigned char *buffer, const unsigned char round);

    void shift_rows(unsigned char *buffer);
    void shift_rows_inv(unsigned char *buffer);

    void mix_columns(unsigned char *buffer);
    void mix_columns_inv(unsigned char *buffer);
};

#include <iostream>
#include <stdlib.h>

#define FE(x)  (((x) << 1) ^ ((((x)>>7) & 1) * 0x1b))
#define FD(x)  (((x) >> 1) ^ (((x) & 1) ? 0x8d : 0))

#define KEY_SIZE   32
#define NUM_ROUNDS 14

unsigned char rj_xtime(unsigned char x);

const unsigned char sbox[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
        0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
        0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
        0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
        0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
        0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
const unsigned char sboxinv[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
        0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
        0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
        0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
        0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
        0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
        0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
        0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
        0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
        0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
        0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
        0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
        0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
        0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

Aes256::Aes256(const ByteArray& key)
        : m_key(ByteArray(key.size() > KEY_SIZE ? KEY_SIZE : key.size(), 0))
        , m_salt(ByteArray(KEY_SIZE - m_key.size(), 0))
        , m_rkey(ByteArray(KEY_SIZE, 0))
        , m_buffer_pos(0)
        , m_remainingLength(0)
        , m_decryptInitialized(false)
{
    for(ByteArray::size_type i = 0; i < m_key.size(); ++i)
        m_key[i] = key[i];
}

Aes256::~Aes256()
{}

ByteArray::size_type Aes256::encrypt(const ByteArray& key, const ByteArray& plain, ByteArray& encrypted)
{
    Aes256 aes(key);

    aes.encrypt_start(plain.size(), encrypted);
    aes.encrypt_continue(plain, encrypted);
    aes.encrypt_end(encrypted);

    return encrypted.size();
}

ByteArray::size_type Aes256::encrypt(const ByteArray& key, const unsigned char* plain, const ByteArray::size_type plain_length, ByteArray& encrypted)
{
    Aes256 aes(key);

    aes.encrypt_start(plain_length, encrypted);
    aes.encrypt_continue(plain, plain_length, encrypted);
    aes.encrypt_end(encrypted);

    return encrypted.size();
}

ByteArray::size_type Aes256::decrypt(const ByteArray& key, const ByteArray& encrypted, ByteArray& plain)
{
    Aes256 aes(key);

    aes.decrypt_start(encrypted.size());
    aes.decrypt_continue(encrypted, plain);
    aes.decrypt_end(plain);

    return plain.size();
}

ByteArray::size_type Aes256::decrypt(const ByteArray& key, const unsigned char* encrypted, const ByteArray::size_type encrypted_length, ByteArray& plain)
{
    Aes256 aes(key);

    aes.decrypt_start(encrypted_length);
    aes.decrypt_continue(encrypted, encrypted_length, plain);
    aes.decrypt_end(plain);

    return plain.size();
}

ByteArray::size_type Aes256::encrypt_start(const ByteArray::size_type plain_length, ByteArray& encrypted)
{
    m_remainingLength = plain_length;

    // Generate salt
    ByteArray::iterator it = m_salt.begin(), itEnd = m_salt.end();
    while (it != itEnd)
        *(it++) = (rand() & 0xFF);

    // Calculate padding
    ByteArray::size_type padding = 0;
    if (m_remainingLength % BLOCK_SIZE != 0)
        padding = (BLOCK_SIZE - (m_remainingLength % BLOCK_SIZE));
    m_remainingLength += padding;

    // Add salt
    encrypted.insert(encrypted.end(), m_salt.begin(), m_salt.end());
    m_remainingLength += m_salt.size();

    // Add 1 bytes for padding size
    encrypted.push_back(padding & 0xFF);
    ++m_remainingLength;

    // Reset buffer
    m_buffer_pos = 0;

    return encrypted.size();
}

ByteArray::size_type Aes256::encrypt_continue(const ByteArray& plain, ByteArray& encrypted)
{
    ByteArray::const_iterator it = plain.begin(), itEnd = plain.end();

    while(it != itEnd) {
        m_buffer[m_buffer_pos++] = *(it++);

        check_and_encrypt_buffer(encrypted);
    }

    return encrypted.size();
}

ByteArray::size_type Aes256::encrypt_continue(const unsigned char* plain, const ByteArray::size_type plain_length, ByteArray& encrypted)
{
    ByteArray::size_type i = 0;

    while(i < plain_length) {
        m_buffer[m_buffer_pos++] = plain[i++];

        check_and_encrypt_buffer(encrypted);
    }

    return encrypted.size();
}

void Aes256::check_and_encrypt_buffer(ByteArray& encrypted)
{
    if (m_buffer_pos == BLOCK_SIZE) {
        encrypt(m_buffer);

        for (m_buffer_pos = 0; m_buffer_pos < BLOCK_SIZE; ++m_buffer_pos) {
            encrypted.push_back(m_buffer[m_buffer_pos]);
            --m_remainingLength;
        }

        m_buffer_pos = 0;
    }
}

ByteArray::size_type Aes256::encrypt_end(ByteArray& encrypted)
{
    if (m_buffer_pos > 0) {
        while (m_buffer_pos < BLOCK_SIZE)
            m_buffer[m_buffer_pos++] = 0;

        encrypt(m_buffer);

        for (m_buffer_pos = 0; m_buffer_pos < BLOCK_SIZE; ++m_buffer_pos) {
            encrypted.push_back(m_buffer[m_buffer_pos]);
            --m_remainingLength;
        }

        m_buffer_pos = 0;
    }

    return encrypted.size();
}

void Aes256::encrypt(unsigned char* buffer)
{
    unsigned char i, rcon;

    copy_key();
    add_round_key(buffer, 0);
    for(i = 1, rcon = 1; i < NUM_ROUNDS; ++i)
    {
        sub_bytes(buffer);
        shift_rows(buffer);
        mix_columns(buffer);
        if( !(i & 1) )
            expand_enc_key(&rcon);
        add_round_key(buffer, i);
    }
    sub_bytes(buffer);
    shift_rows(buffer);
    expand_enc_key(&rcon);
    add_round_key(buffer, i);
}

ByteArray::size_type Aes256::decrypt_start(const ByteArray::size_type encrypted_length)
{
    register unsigned char j;

    m_remainingLength = encrypted_length;

    // Reset salt
    for(j = 0; j < m_salt.size(); ++j)
        m_salt[j] = 0;
    m_remainingLength -= m_salt.size();

    // Reset buffer
    m_buffer_pos = 0;

    m_decryptInitialized = false;

    return m_remainingLength;
}

ByteArray::size_type Aes256::decrypt_continue(const ByteArray& encrypted, ByteArray& plain)
{
    ByteArray::const_iterator it = encrypted.begin(), itEnd = encrypted.end();

    while(it != itEnd) {
        m_buffer[m_buffer_pos++] = *(it++);

        check_and_decrypt_buffer(plain);
    }

    return plain.size();
}

ByteArray::size_type Aes256::decrypt_continue(const unsigned char* encrypted, const ByteArray::size_type encrypted_length, ByteArray& plain)
{
    ByteArray::size_type i = 0;

    while(i < encrypted_length) {
        m_buffer[m_buffer_pos++] = encrypted[i++];

        check_and_decrypt_buffer(plain);
    }

    return plain.size();
}

void Aes256::check_and_decrypt_buffer(ByteArray& plain)
{
    if (!m_decryptInitialized && m_buffer_pos == m_salt.size() + 1) {
        register unsigned char j;
        ByteArray::size_type padding;

        // Get salt
        for(j = 0; j < m_salt.size(); ++j)
            m_salt[j] = m_buffer[j];

        // Get padding
        padding = (m_buffer[j] & 0xFF);
        m_remainingLength -= padding + 1;

        // Start decrypting
        m_buffer_pos = 0;

        m_decryptInitialized = true;
    }
    else if (m_decryptInitialized && m_buffer_pos == BLOCK_SIZE) {
        decrypt(m_buffer);

        for (m_buffer_pos = 0; m_buffer_pos < BLOCK_SIZE; ++m_buffer_pos)
            if (m_remainingLength > 0) {
                plain.push_back(m_buffer[m_buffer_pos]);
                --m_remainingLength;
            }

        m_buffer_pos = 0;
    }
}

ByteArray::size_type Aes256::decrypt_end(ByteArray& plain)
{
    return plain.size();
}

void Aes256::decrypt(unsigned char* buffer)
{
    unsigned char i, rcon = 1;

    copy_key();
    for (i = NUM_ROUNDS / 2; i > 0; --i)
        expand_enc_key(&rcon);

    add_round_key(buffer, NUM_ROUNDS);
    shift_rows_inv(buffer);
    sub_bytes_inv(buffer);

    for (i = NUM_ROUNDS, rcon = 0x80; --i;)
    {
        if( (i & 1) )
            expand_dec_key(&rcon);
        add_round_key(buffer, i);
        mix_columns_inv(buffer);
        shift_rows_inv(buffer);
        sub_bytes_inv(buffer);
    }
    add_round_key(buffer, i);
}

void Aes256::expand_enc_key(unsigned char* rc)
{
    register unsigned char i;

    m_rkey[0] = m_rkey[0] ^ sbox[m_rkey[29]] ^ (*rc);
    m_rkey[1] = m_rkey[1] ^ sbox[m_rkey[30]];
    m_rkey[2] = m_rkey[2] ^ sbox[m_rkey[31]];
    m_rkey[3] = m_rkey[3] ^ sbox[m_rkey[28]];
    *rc = FE(*rc);

    for(i = 4; i < 16; i += 4) {
        m_rkey[i] = m_rkey[i] ^ m_rkey[i-4];
        m_rkey[i+1] = m_rkey[i+1] ^ m_rkey[i-3];
        m_rkey[i+2] = m_rkey[i+2] ^ m_rkey[i-2];
        m_rkey[i+3] = m_rkey[i+3] ^ m_rkey[i-1];
    }
    m_rkey[16] = m_rkey[16] ^ sbox[m_rkey[12]];
    m_rkey[17] = m_rkey[17] ^ sbox[m_rkey[13]];
    m_rkey[18] = m_rkey[18] ^ sbox[m_rkey[14]];
    m_rkey[19] = m_rkey[19] ^ sbox[m_rkey[15]];

    for(i = 20; i < 32; i += 4) {
        m_rkey[i] = m_rkey[i] ^ m_rkey[i-4];
        m_rkey[i+1] = m_rkey[i+1] ^ m_rkey[i-3];
        m_rkey[i+2] = m_rkey[i+2] ^ m_rkey[i-2];
        m_rkey[i+3] = m_rkey[i+3] ^ m_rkey[i-1];
    }
}

void Aes256::expand_dec_key(unsigned char* rc)
{
    unsigned char i;

    for(i = 28; i > 16; i -= 4) {
        m_rkey[i+0] = m_rkey[i+0] ^ m_rkey[i-4];
        m_rkey[i+1] = m_rkey[i+1] ^ m_rkey[i-3];
        m_rkey[i+2] = m_rkey[i+2] ^ m_rkey[i-2];
        m_rkey[i+3] = m_rkey[i+3] ^ m_rkey[i-1];
    }

    m_rkey[16] = m_rkey[16] ^ sbox[m_rkey[12]];
    m_rkey[17] = m_rkey[17] ^ sbox[m_rkey[13]];
    m_rkey[18] = m_rkey[18] ^ sbox[m_rkey[14]];
    m_rkey[19] = m_rkey[19] ^ sbox[m_rkey[15]];

    for(i = 12; i > 0; i -= 4) {
        m_rkey[i+0] = m_rkey[i+0] ^ m_rkey[i-4];
        m_rkey[i+1] = m_rkey[i+1] ^ m_rkey[i-3];
        m_rkey[i+2] = m_rkey[i+2] ^ m_rkey[i-2];
        m_rkey[i+3] = m_rkey[i+3] ^ m_rkey[i-1];
    }

    *rc = FD(*rc);
    m_rkey[0] = m_rkey[0] ^ sbox[m_rkey[29]] ^ (*rc);
    m_rkey[1] = m_rkey[1] ^ sbox[m_rkey[30]];
    m_rkey[2] = m_rkey[2] ^ sbox[m_rkey[31]];
    m_rkey[3] = m_rkey[3] ^ sbox[m_rkey[28]];
}

void Aes256::sub_bytes(unsigned char* buffer)
{
    register unsigned char i = KEY_SIZE / 2;

    while (i--)
        buffer[i] = sbox[buffer[i]];
}

void Aes256::sub_bytes_inv(unsigned char* buffer)
{
    register unsigned char i = KEY_SIZE / 2;

    while (i--)
        buffer[i] = sboxinv[buffer[i]];
}

void Aes256::copy_key()
{
    ByteArray::size_type i;

    for (i = 0; i < m_key.size(); ++i)
        m_rkey[i] = m_key[i];
    for (i = 0; i < m_salt.size(); ++i)
        m_rkey[i + m_key.size()] = m_salt[i];
}

void Aes256::add_round_key(unsigned char* buffer, const unsigned char round)
{
    register unsigned char i = KEY_SIZE / 2;

    while (i--)
        buffer[i] ^= m_rkey[ (round & 1) ? i + 16 : i ];
}

void Aes256::shift_rows(unsigned char* buffer)
{
    register unsigned char i, j, k, l; /* to make it potentially parallelable :) */

    i          = buffer[1];
    buffer[1]  = buffer[5];
    buffer[5]  = buffer[9];
    buffer[9]  = buffer[13];
    buffer[13] = i;

    j          = buffer[10];
    buffer[10] = buffer[2];
    buffer[2]  = j;

    k          = buffer[3];
    buffer[3]  = buffer[15];
    buffer[15] = buffer[11];
    buffer[11] = buffer[7];
    buffer[7]  = k;

    l          = buffer[14];
    buffer[14] = buffer[6];
    buffer[6]  = l;
}

void Aes256::shift_rows_inv(unsigned char* buffer)
{
    register unsigned char i, j, k, l; /* same as above :) */

    i          = buffer[1];
    buffer[1]  = buffer[13];
    buffer[13] = buffer[9];
    buffer[9]  = buffer[5];
    buffer[5]  = i;

    j          = buffer[2];
    buffer[2]  = buffer[10];
    buffer[10] = j;

    k          = buffer[3];
    buffer[3]  = buffer[7];
    buffer[7]  = buffer[11];
    buffer[11] = buffer[15];
    buffer[15] = k;

    l          = buffer[6];
    buffer[6]  = buffer[14];
    buffer[14] = l;
}

void Aes256::mix_columns(unsigned char* buffer)
{
    register unsigned char i, a, b, c, d, e;

    for (i = 0; i < 16; i += 4)
    {
        a = buffer[i];
        b = buffer[i + 1];
        c = buffer[i + 2];
        d = buffer[i + 3];

        e = a ^ b ^ c ^ d;

        buffer[i    ] ^= e ^ rj_xtime(a^b);
        buffer[i + 1] ^= e ^ rj_xtime(b^c);
        buffer[i + 2] ^= e ^ rj_xtime(c^d);
        buffer[i + 3] ^= e ^ rj_xtime(d^a);
    }
}

void Aes256::mix_columns_inv(unsigned char* buffer)
{
    register unsigned char i, a, b, c, d, e, x, y, z;

    for (i = 0; i < 16; i += 4)
    {
        a = buffer[i];
        b = buffer[i + 1];
        c = buffer[i + 2];
        d = buffer[i + 3];

        e = a ^ b ^ c ^ d;
        z = rj_xtime(e);
        x = e ^ rj_xtime(rj_xtime(z^a^c));  y = e ^ rj_xtime(rj_xtime(z^b^d));

        buffer[i    ] ^= x ^ rj_xtime(a^b);
        buffer[i + 1] ^= y ^ rj_xtime(b^c);
        buffer[i + 2] ^= x ^ rj_xtime(c^d);
        buffer[i + 3] ^= y ^ rj_xtime(d^a);
    }
}

inline unsigned char rj_xtime(unsigned char x)
{
    return (x & 0x80) ? ((x << 1) ^ 0x1b) : (x << 1);
}

#define KEY_LEN    32


unsigned char sec_key[KEY_LEN] =   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

// Test vectors
#define VECTOR_NUM   4
#define VECTOR_SIZE 16

unsigned char secv_key[KEY_LEN] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                                    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };

unsigned char sectv_dec[VECTOR_SIZE][VECTOR_SIZE] = {
        { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a },
        { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 },
        { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef },
        { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 }
};


void init_key(ByteArray& key) {
    for (unsigned char i = 0; i < KEY_LEN;i++)
        key.push_back(sec_key[i]);
}

void init_key(ByteArray& key, unsigned char index) {
    for (unsigned char i = 0; i < KEY_LEN;i++) {
        if (index < VECTOR_NUM)
            key.push_back(secv_key[i]);
        else
            key.push_back(0);
    }
}

void init_txt(ByteArray& txt, unsigned char index) {
    for (unsigned char i = 0; i < VECTOR_SIZE; ++i) {
        if (index < VECTOR_NUM)
            txt.push_back(sectv_dec[index][i]);
        else
            txt.push_back(0);
    }
}

unsigned char* encrypts(unsigned char *data, int len) {
    std::cout << "Starting test encrypts bytearray..." << std::endl;

    ByteArray key;
    init_key(key);
    std::cout << " Key initialized..." << std::endl;

    //unsigned  char txt[100];
    ByteArray enc;
    //init_txt(txt);
    //std::cout << " Text initialized..." << std::endl;

    ByteArray::size_type enc_len = Aes256::encrypt(key, (const unsigned char*)data, len, enc);
    std::cout << " Encrypted..." << std::endl;

    unsigned  char *result = (unsigned char*)malloc(sizeof(unsigned char) * enc_len);
    for (int i = 0; i < enc_len; i++) {
        result[i] = enc[i];
    }

    std::cout << " Done!" << std::endl;
    return result;
}

unsigned char* decrypts(unsigned char* data, int len) {
    std::cout << "Starting test decrypts bytearray..." << std::endl;

    ByteArray key;
    init_key(key);
    std::cout << " Key initialized..." << std::endl;

    ByteArray dec;
    //init_enc(enc);
    //std::cout << " Encrypted initialized..." << std::endl;
    //decrypt(const ByteArray& key, const unsigned char* encrypted, const ByteArray::size_type encrypted_length, ByteArray& plain)
    ByteArray::size_type dec_len = Aes256::decrypt(key, data, len, dec);
    std::cout << " Decrypted..." << std::endl;


    unsigned  char *result = (unsigned char*)malloc(sizeof(unsigned char) * dec_len);
    for (int i = 0; i < dec_len; i++) {
        result[i] = dec[i];
    }

    std::cout << " Done!" << std::endl;
    return result;
}

/**
 * BABE64
 */
////////////////////////////////////////////////////////////////////////////////////////////////////
#if __cplusplus >= 201703L
#include <string_view>
#endif  // __cplusplus >= 201703L

std::string base64_encode     (std::string const& s, bool url = false);
std::string base64_encode_pem (std::string const& s);
std::string base64_encode_mime(std::string const& s);

std::string base64_decode(std::string const& s, bool remove_linebreaks = false);
std::string base64_encode(unsigned char const*, size_t len, bool url = false);

#if __cplusplus >= 201703L
//
// Interface with std::string_view rather than const std::string&
// Requires C++17
// Provided by Yannic Bonenberger (https://github.com/Yannic)
//
std::string base64_encode     (std::string_view s, bool url = false);
std::string base64_encode_pem (std::string_view s);
std::string base64_encode_mime(std::string_view s);

std::string base64_decode(std::string_view s, bool remove_linebreaks = false);
#endif  // __cplusplus >= 201703L
//
// Depending on the url parameter in base64_chars, one of
// two sets of base64 characters needs to be chosen.
// They differ in their last two characters.
//
const char* base64_chars[2] = {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "+/",

        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "-_"};

static unsigned int pos_of_char(const unsigned char chr) {
    //
    // Return the position of chr within base64_encode()
    //

    if      (chr >= 'A' && chr <= 'Z') return chr - 'A';
    else if (chr >= 'a' && chr <= 'z') return chr - 'a' + ('Z' - 'A')               + 1;
    else if (chr >= '0' && chr <= '9') return chr - '0' + ('Z' - 'A') + ('z' - 'a') + 2;
    else if (chr == '+' || chr == '-') return 62; // Be liberal with input and accept both url ('-') and non-url ('+') base 64 characters (
    else if (chr == '/' || chr == '_') return 63; // Ditto for '/' and '_'

    throw "If input is correct, this line should never be reached.";
}

static std::string insert_linebreaks(std::string str, size_t distance) {
    //
    // Provided by https://github.com/JomaCorpFX, adapted by me.
    //
    if (!str.length()) {
        return "";
    }

    size_t pos = distance;

    while (pos < str.size()) {
        str.insert(pos, "\n");
        pos += distance + 1;
    }

    return str;
}

template <typename String, unsigned int line_length>
static std::string encode_with_line_breaks(String s) {
    return insert_linebreaks(base64_encode(s, false), line_length);
}

template <typename String>
static std::string encode_pem(String s) {
    return encode_with_line_breaks<String, 64>(s);
}

template <typename String>
static std::string encode_mime(String s) {
    return encode_with_line_breaks<String, 76>(s);
}

template <typename String>
static std::string encode(String s, bool url) {
    return base64_encode(reinterpret_cast<const unsigned char*>(s.data()), s.length(), url);
}

std::string base64_encode(unsigned char const* bytes_to_encode, size_t in_len, bool url) {

    size_t len_encoded = (in_len +2) / 3 * 4;

    unsigned char trailing_char = url ? '.' : '=';

    //
    // Choose set of base64 characters. They differ
    // for the last two positions, depending on the url
    // parameter.
    // A bool (as is the parameter url) is guaranteed
    // to evaluate to either 0 or 1 in C++ therfore,
    // the correct character set is chosen by subscripting
    // base64_chars with url.
    //
    const char* base64_chars_ = base64_chars[url];

    std::string ret;
    ret.reserve(len_encoded);

    unsigned int pos = 0;

    while (pos < in_len) {
        ret.push_back(base64_chars_[(bytes_to_encode[pos + 0] & 0xfc) >> 2]);

        if (pos+1 < in_len) {
            ret.push_back(base64_chars_[((bytes_to_encode[pos + 0] & 0x03) << 4) + ((bytes_to_encode[pos + 1] & 0xf0) >> 4)]);

            if (pos+2 < in_len) {
                ret.push_back(base64_chars_[((bytes_to_encode[pos + 1] & 0x0f) << 2) + ((bytes_to_encode[pos + 2] & 0xc0) >> 6)]);
                ret.push_back(base64_chars_[  bytes_to_encode[pos + 2] & 0x3f]);
            }
            else {
                ret.push_back(base64_chars_[(bytes_to_encode[pos + 1] & 0x0f) << 2]);
                ret.push_back(trailing_char);
            }
        }
        else {

            ret.push_back(base64_chars_[(bytes_to_encode[pos + 0] & 0x03) << 4]);
            ret.push_back(trailing_char);
            ret.push_back(trailing_char);
        }

        pos += 3;
    }


    return ret;
}

template <typename String>
static std::string decode(String encoded_string, bool remove_linebreaks) {
    //
    // decode(…) is templated so that it can be used with String = const std::string&
    // or std::string_view (requires at least C++17)
    //

    if (remove_linebreaks) {

        if (! encoded_string.length() ) {
            return "";
        }

        std::string copy(encoded_string);

        size_t pos=0;
        while ((pos = copy.find("\n", pos)) != std::string::npos) {
            copy.erase(pos, 1);
        }

        return base64_decode(copy, false);

    }

    size_t length_of_string = encoded_string.length();
    if (!length_of_string) return std::string("");

    size_t in_len = length_of_string;
    size_t pos = 0;

    //
    // The approximate length (bytes) of the decoded string might be one ore
    // two bytes smaller, depending on the amount of trailing equal signs
    // in the encoded string. This approximation is needed to reserve
    // enough space in the string to be returned.
    //
    size_t approx_length_of_decoded_string = length_of_string / 4 * 3;
    std::string ret;
    ret.reserve(approx_length_of_decoded_string);

    while (pos < in_len) {

        unsigned int pos_of_char_1 = pos_of_char(encoded_string[pos+1] );

        ret.push_back(static_cast<std::string::value_type>( ( (pos_of_char(encoded_string[pos+0]) ) << 2 ) + ( (pos_of_char_1 & 0x30 ) >> 4)));

        if (encoded_string[pos+2] != '=' && encoded_string[pos+2] != '.') { // accept URL-safe base 64 strings, too, so check for '.' also.

            unsigned int pos_of_char_2 = pos_of_char(encoded_string[pos+2] );
            ret.push_back(static_cast<std::string::value_type>( (( pos_of_char_1 & 0x0f) << 4) + (( pos_of_char_2 & 0x3c) >> 2)));

            if (encoded_string[pos+3] != '=' && encoded_string[pos+3] != '.') {
                ret.push_back(static_cast<std::string::value_type>( ( (pos_of_char_2 & 0x03 ) << 6 ) + pos_of_char(encoded_string[pos+3])   ));
            }
        }

        pos += 4;
    }

    return ret;
}

std::string base64_decode(std::string const& s, bool remove_linebreaks) {
    return decode(s, remove_linebreaks);
}

std::string base64_encode(std::string const& s, bool url) {
    return encode(s, url);
}

std::string base64_encode_pem (std::string const& s) {
    return encode_pem(s);
}

std::string base64_encode_mime(std::string const& s) {
    return encode_mime(s);
}

#if __cplusplus >= 201703L
//
// Interface with std::string_view rather than const std::string&
// Requires C++17
// Provided by Yannic Bonenberger (https://github.com/Yannic)
//

std::string base64_encode(std::string_view s, bool url) {
   return encode(s, url);
}

std::string base64_encode_pem(std::string_view s) {
   return encode_pem(s);
}

std::string base64_encode_mime(std::string_view s) {
   return encode_mime(s);
}

std::string base64_decode(std::string_view s, bool remove_linebreaks) {
  return decode(s, remove_linebreaks);
}

#endif  // __cplusplus >= 201703L
////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////

jstring stringTojstring(JNIEnv *env, string data){
    return env->NewStringUTF(data.c_str());
}

string jstringTostring(JNIEnv *env,jstring jstr_input){
    char *input = const_cast<char *>((*env).GetStringUTFChars(jstr_input, JNI_FALSE));
    std::string inputstr = (char*)input;
    return inputstr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

extern "C"
JNIEXPORT jstring JNICALL
Java_com_neucore_neulink_aes_AesUtil_encrypt(JNIEnv *env, jclass clazz, jstring data) {
    string orig = jstringTostring(env,data);
    std::string encoded = base64_encode(orig, orig.length());

    unsigned char* input = (unsigned  char*)encoded.c_str();
//    printf("in c++ plain = %s\n", input);
    unsigned char * result = encrypts(input,strlen((char*)input));
    std::string resultStr = (char*)result;

    std::string encoded0 = base64_encode(resultStr, resultStr.length());
    unsigned char* encoded0c_str = (unsigned  char*)encoded0.c_str();
    jstring encoded0dist = stringTojstring(env,(const char *)encoded0c_str);
    return encoded0dist;
}extern "C"
JNIEXPORT jstring JNICALL
Java_com_neucore_neulink_aes_AesUtil_decrypt(JNIEnv *env, jclass clazz, jstring encoded0dist) {

    string encoded0str = jstringTostring(env,encoded0dist);
    std::string decoded0 = base64_decode(encoded0str);
    unsigned char* decodedc_str = (unsigned  char*)decoded0.c_str();

//    printf("in c++ encrypts = %s\n", result);
    unsigned char*  out = decrypts(decodedc_str,strlen((char*)decodedc_str));
//    printf("in c++ decrypts = %s\n", out);
    std::string outres = (char*)out;
    std::string orig0 = base64_decode(outres);

    unsigned char* c_str = (unsigned  char*)orig0.c_str();
    jstring dist = stringTojstring(env,(const char *)c_str);
    return dist;
}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_neucore_neulink_aes_AesUtil_encBase64(JNIEnv *env, jclass clazz, jstring data) {
    string orig = jstringTostring(env,data);
    std::string encoded = base64_encode(orig, orig.length());

    unsigned char* c_str = (unsigned  char*)encoded.c_str();
    jstring dist = stringTojstring(env,(const char *)c_str);

    return dist;
}extern "C"
JNIEXPORT jstring JNICALL
Java_com_neucore_neulink_aes_AesUtil_decBase64(JNIEnv *env, jclass clazz, jstring data) {
    string orig = jstringTostring(env,data);
    std::string decoded = base64_decode(orig);

    unsigned char* c_str = (unsigned  char*)decoded.c_str();
    jstring dist = stringTojstring(env,(const char *)c_str);
    return dist;
}extern "C"
JNIEXPORT jstring JNICALL
Java_com_neucore_neulink_aes_AesUtil_encrypt_00024decrypt(JNIEnv *env, jclass clazz,
                                                          jstring data) {
    string orig = jstringTostring(env,data);
    std::string encoded = base64_encode(orig, orig.length());

    unsigned char* input = (unsigned  char*)encoded.c_str();
//    printf("in c++ plain = %s\n", input);
    unsigned char * result = encrypts(input,strlen((char*)input));
    std::string resultStr = (char*)result;

    std::string encoded0 = base64_encode(resultStr, resultStr.length());
    unsigned char* encoded0c_str = (unsigned  char*)encoded0.c_str();
    jstring encoded0dist = stringTojstring(env,(const char *)encoded0c_str);

    string encoded0str = jstringTostring(env,encoded0dist);
    std::string decoded0 = base64_decode(encoded0str);
    unsigned char* decodedc_str = (unsigned  char*)decoded0.c_str();

//    printf("in c++ encrypts = %s\n", result);
    unsigned char*  out = decrypts(decodedc_str,strlen((char*)decodedc_str));
//    printf("in c++ decrypts = %s\n", out);
    std::string outres = (char*)out;
    std::string orig0 = base64_decode(outres);

    unsigned char* c_str = (unsigned  char*)orig0.c_str();
    jstring dist = stringTojstring(env,(const char *)c_str);
    return dist;
}extern "C"
JNIEXPORT jstring JNICALL
Java_com_neucore_neulink_aes_AesUtil_trans(JNIEnv *env, jclass clazz, jstring data) {

    string in = jstringTostring(env,data);
    unsigned char* c_str = (unsigned  char*)in.c_str();
    jstring dist = stringTojstring(env,(const char *)c_str);
    return dist;
}