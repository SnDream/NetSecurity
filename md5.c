/*
 * md5.c
 *
 * Copyright 2017 SnDream <xnight@outlook.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 *
 */


#include <stdio.h>
#include <string.h>

// 函数声明
void HMD5();
unsigned FGHI(unsigned B, unsigned C, unsigned D, int i);
unsigned rol(unsigned value, int times);
unsigned l2b(unsigned);

// 文件块，以32bit为一个单位
unsigned chunk[16];
// A B C D四个数，放于全局简化传递
unsigned A, B, C, D;
// 生成一个以8bit为一个单位的文件块指针，处理文件读写逻辑
char* chunkp = (char*)chunk;
// 生成一个以64bit为单位的指针，指向尾块写入文件大小时位置的位置
long unsigned* filesizep = (long unsigned*)(chunk + 14); // 14*32=448
// T表
// 数据与sin有关，由于数值固定，故建表
const unsigned T_TABLE[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};
// 移位表
// 每次左循环移位的位数
const int S_TABLE[] = {
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};
// X索引表
// 每次读取X的段号
const int XNO_TABLE[] = {
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    1,  6, 11,  0,  5, 10, 15,  4,  9, 14,  3,  8, 13,  2,  7, 12,
    5,  8, 11, 14,  1,  4,  7, 10, 13,  0,  3,  6,  9, 12, 15,  2,
    0,  7, 14,  5, 12,  3, 10,  1,  8, 15,  6, 13,  4, 11,  2,  9
};

// 主程序，通过命令行执行时附加参数作为输入
// 输入：N个文件名
// 输出：每个文件名对应文件的md5值
// 输出格式模仿md5sum，但没有实现其读取标准流的功能
// 由于python实现代码效率低下，特采用C重写代码，虽然效率不及md5sum，但是已可实用
// 计算400MB数据：md5sum用时2.8s md5.c用时6.0s md5.py用时9m17s
int main(int argc, char** argv)
{
    FILE* fp;
    int chunklen;
    long unsigned filesize;
    if (argc == 1) { // 当没有传入文件参数时，直接提示用法并返回
        printf("Usage: md5 [FILE]...\nPrint MD5 (128-bit) checksums.\n");
        return -1;
    }
    for (int i = 1; i < argc; ++i) {
        if ((fp = fopen(argv[i], "rb")) != NULL) {
            A = 0x67452301, B = 0xefcdab89, C = 0x98badcfe, D = 0x10325476;
            filesize = 0;
            chunklen = fread(chunkp, 1, 64, fp);
            while (chunklen == 64) { // 非末尾文件块，循环处理
                HMD5();
                filesize += 64;
                chunklen = fread(chunkp, 1, 64, fp);
            }
            filesize += chunklen;
            // 已处理到末尾文件块，生成其余部分
            chunkp[chunklen++] = 0x80;
            if (chunklen > 56) { // 当其余部分不足以放下文件长度时，需要再生成一个一块
                memset(chunkp + chunklen, 0, (64 - chunklen));
                HMD5();
                memset(chunkp, 0, 56);
            } else memset(chunkp + chunklen, 0, (56 - chunklen));
            // 上面计算的文件大小实际上是Byte大小，md5按Bit大小记录
            *filesizep = filesize << 3;
            HMD5();
            printf("%08x%08x%08x%08x  %s\n",
                   l2b(A), l2b(B), l2b(C), l2b(D), argv[i]);
            fclose(fp);
        } else printf("No such file: %s\n", argv[i]);
    }
    return 0;
}

// HMD5函数，核心函数
// ABCD四个数为了简便和效率，采用全局变量而非值传递方式
// C对数据的溢出处理等使得md5实现非常简便和快速，没必要像Python一样需要手动截断
void HMD5()
{
    unsigned Ao = A, Bo = B, Co = C, Do = D;
    unsigned tmp;
    for (int i = 0; i < 64; ++i) {
        tmp = rol(A + FGHI(B, C, D, i) + chunk[XNO_TABLE[i]] +
                  T_TABLE[i], S_TABLE[i]) + B;
        A = D;
        D = C;
        C = B;
        B = tmp;
    }
    A += Ao, B += Bo, C += Co, D += Do;
}

// F G H I四个函数
// 输入：B C D 轮次
// 输出：根据轮次选择对应的函数，计算结果并返回
unsigned FGHI(unsigned B, unsigned C, unsigned D, int i)
{
    if (i < 16)return ((B & C) | (~B & D));
    else if (i < 32)return ((B & D) | (C & ~D));
    else if (i < 48)return B ^ C ^ D;
    else return (C ^ (B | ~D));
}

// 简单32位循环左移
// 输入：原值 左移次数
// 输出：左移结果
unsigned rol(unsigned value, int times)
{
    return (value << times) | (value >> (32 - times));
}

// 小端序转大端序
// 输入：小端序数(32bit)
// 输出：大端序数(32bit)
// 虽然整个流程都是按小端序处理，显示时也是从小端以字节为单位依次显示
// 但是这里为了方便，将数字处理成大端序，一次性以16进制显示4个字节
unsigned l2b(unsigned value)
{
    return (value >> 24) | (((value >> 16) & 0xFF) << 8) |
           (((value >> 8) & 0xFF) << 16) | ((value & 0xFF) << 24);
}

