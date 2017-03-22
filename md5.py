#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  md5.py
#
#  Copyright 2017 SnDream <xnight@outlook.com>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#

# 限于python特性，无法实现加溢出，计算加法后需要适时计算模32弥补
# 模32改用与实现时的参数，专门命名简短程序长度
M32 = 0xFFFFFFFF
# IV表
# ABCD的预设值，注意是小端序
IV_TABLE = [
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
# T表
# 数据与sin有关，由于数值固定，故建表
T_TABLE = [
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
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391]
# 移位表
# 每次左循环移位的位数
S_TABLE = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21]
# X索引表
# 每次读取X的段号
XNO_TABLE = [
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    1,  6, 11,  0,  5, 10, 15,  4,  9, 14,  3,  8, 13,  2,  7, 12,
    5,  8, 11, 14,  1,  4,  7, 10, 13,  0,  3,  6,  9, 12, 15,  2,
    0,  7, 14,  5, 12,  3, 10,  1,  8, 15,  6, 13,  4, 11,  2,  9]


def main(args):
# 主程序，通过命令行执行时附加参数作为输入
# 输入：N个文件名
# 输出：每个文件名对应文件的md5值
# 输出格式模仿md5sum，但没有实现其读取标准流的功能
# 限于python特性（无法做加法溢出，需要执行额外指令弥补）效率也相当低
# 虽然考虑了大文件读入的问题，但是大文件的计算本身效率很差
    if len(args) == 1:
        print('Usage: md5.py [FILE]...')
        print('Print MD5 (128-bit) checksums.')
        return -1
    for filename in args[1::]:
        try:
            ABCD = IV_TABLE
            filesize = 0
            with open(filename, 'rb') as rawdata:
                chunk = rawdata.read(64)
                while len(chunk) == 64:
                    ABCD = HMD5(ABCD, chunk)
                    filesize += 64
                    chunk = rawdata.read(64)
                filesize = ((filesize + len(chunk)) << 3) & ((1 << 64) - 1)
                chunk += b'\x80'
                if len(chunk) >= 56:
                    chunk += bytes([0] * (64 - len(chunk)))
                    ABCD = HMD5(ABCD, chunk)
                    chunk = bytes([0] * 56)
                else:
                    chunk += bytes([0] * (56 - len(chunk)))
                chunk += filesize.to_bytes(8, byteorder='little', signed=False)
                ABCD = HMD5(ABCD, chunk)
            md5sum_bytes = b''
            md5sum = ''
            for i in ABCD:
                md5sum_bytes += i.to_bytes(4, 'little', signed=False)
            for byte in md5sum_bytes:
                md5sum += "%02x" % byte
            print(md5sum, '', filename)
        except FileNotFoundError as e:
            print('No such file:', filename)
    return 0


def HMD5(ABCD, chunk):
# HMD5函数，核心函数
# 输入：ABCD的list(4个数 各32bit) 文件块(512bit)
# 输出：ABCD的list(4个数 各32bit)
    A, B, C, D = ABCD[0], ABCD[1], ABCD[2], ABCD[3]
    X = []
    for i in range(0, 64, 4):
        X.append(
            int.from_bytes(chunk[i:i + 4], byteorder='little', signed=False))
    for i in range(0, 64):
        A, B, C, D = D, MA(A, B, C, D, i, X[XNO_TABLE[i]]), B, C
    return [(A + ABCD[0]) & M32, (B + ABCD[1]) & M32, (C + ABCD[2]) & M32, (D + ABCD[3]) & M32]


def MA(A, B, C, D, i, X):
# A的计算函数
# 输入：A B C D 轮次 本次计算的文件段(32位)
# 输出：本轮A的计算结果
    return (rol((A + FGHI(B, C, D, i) + X + T_TABLE[i]) & M32, S_TABLE[i]) + B) & M32


def FGHI(B, C, D, i):
# F G H I四个函数
# 输入：B C D 轮次
# 输出：根据轮次选择对应的函数，计算结果并返回
    if i < 16:
        return ((B & C) | (~B & D)) & M32
    elif i < 32:
        return ((B & D) | (C & ~D)) & M32
    elif i < 48:
        return (B ^ C ^ D) & M32
    elif i < 64:
        return (C ^ (B | ~D)) & M32
    else:
        raise Exception("Not F,G,H or I")


def rol(value, times):
# 简单32位循环左移
# 输入：原值 左移次数
# 输出：左移结果
    return ((value << times) | (value >> (32 - times))) & M32

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
