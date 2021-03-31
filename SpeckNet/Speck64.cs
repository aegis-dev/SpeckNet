//
// Copyright (c) 2021 Egidijus Lileika
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

using System;
using System.Diagnostics;

namespace SpeckNet
{
    public sealed class Speck64 : Speck
    {
        private uint[] _scheduledKey;

        internal Speck64(EncryptionType type, uint[] key) : base(type)
        {
            if (!IsKeyValid<uint>(type, key))
            {
                throw new SpeckException("Invalid key length");
            }
            _scheduledKey = KeySchedule(type, key);
        }

        protected override byte[] EncryptECB(byte[] plainText)
        {
            int blockSize = GetBlockSizeInBytes(_type);
            byte[] encrypted = new byte[plainText.Length];

            uint[] plainTextBlock = new uint[2];
            uint[] cipherTextBlock = new uint[2];
            for (int i = 0; i < plainText.Length; i += blockSize)
            {
                int j = i + (blockSize / 2);
                plainTextBlock[0] = BitConverter.ToUInt32(plainText, i);
                plainTextBlock[1] = BitConverter.ToUInt32(plainText, j);

                EncryptBlock(plainTextBlock, ref cipherTextBlock);

                byte[] firstHalf = BitConverter.GetBytes(cipherTextBlock[0]);
                byte[] secondHalf = BitConverter.GetBytes(cipherTextBlock[1]);
                Buffer.BlockCopy(firstHalf, 0, encrypted, i, firstHalf.Length);
                Buffer.BlockCopy(secondHalf, 0, encrypted, j, secondHalf.Length);
            }

            return encrypted;
        }

        protected override byte[] EncryptCBC(byte[] plainText)
        {
            int blockSize = GetBlockSizeInBytes(_type);
            byte[] encrypted = new byte[plainText.Length];

            uint[] plainTextBlock = new uint[2];
            uint[] cipherTextBlock = new uint[2];
            uint[] prevCipherTextBlock = new uint[] { 0, 0 };
            for (int i = 0; i < plainText.Length; i += blockSize)
            {
                int j = i + (blockSize / 2);
                plainTextBlock[0] = BitConverter.ToUInt32(plainText, i);
                plainTextBlock[1] = BitConverter.ToUInt32(plainText, j);

                plainTextBlock[0] ^= prevCipherTextBlock[0];
                plainTextBlock[1] ^= prevCipherTextBlock[1];

                EncryptBlock(plainTextBlock, ref cipherTextBlock);

                prevCipherTextBlock[0] = cipherTextBlock[0];
                prevCipherTextBlock[1] = cipherTextBlock[1];

                byte[] firstHalf = BitConverter.GetBytes(cipherTextBlock[0]);
                byte[] secondHalf = BitConverter.GetBytes(cipherTextBlock[1]);
                Buffer.BlockCopy(firstHalf, 0, encrypted, i, firstHalf.Length);
                Buffer.BlockCopy(secondHalf, 0, encrypted, j, secondHalf.Length);
            }

            return encrypted;
        }

        protected override byte[] DecryptECB(byte[] cipherText)
        {
            int blockSize = GetBlockSizeInBytes(_type);
            byte[] decrypted = new byte[cipherText.Length];

            uint[] plainTextBlock = new uint[2];
            uint[] cipherTextBlock = new uint[2];
            for (int i = 0; i < cipherText.Length; i += blockSize)
            {
                int j = i + (blockSize / 2);
                cipherTextBlock[0] = BitConverter.ToUInt32(cipherText, i);
                cipherTextBlock[1] = BitConverter.ToUInt32(cipherText, j);

                DecryptBlock(cipherTextBlock, ref plainTextBlock);

                byte[] firstHalf = BitConverter.GetBytes(plainTextBlock[0]);
                byte[] secondHalf = BitConverter.GetBytes(plainTextBlock[1]);
                Buffer.BlockCopy(firstHalf, 0, decrypted, i, firstHalf.Length);
                Buffer.BlockCopy(secondHalf, 0, decrypted, j, secondHalf.Length);
            }

            return decrypted;
        }

        protected override byte[] DecryptCBC(byte[] cipherText)
        {
            int blockSize = GetBlockSizeInBytes(_type);
            byte[] decrypted = new byte[cipherText.Length];

            uint[] plainTextBlock = new uint[2];
            uint[] cipherTextBlock = new uint[2];
            uint[] prevCipherTextBlock = new uint[] { 0, 0 };
            for (int i = 0; i < cipherText.Length; i += blockSize)
            {
                int j = i + (blockSize / 2);
                cipherTextBlock[0] = BitConverter.ToUInt32(cipherText, i);
                cipherTextBlock[1] = BitConverter.ToUInt32(cipherText, j);

                DecryptBlock(cipherTextBlock, ref plainTextBlock);

                plainTextBlock[0] ^= prevCipherTextBlock[0];
                plainTextBlock[1] ^= prevCipherTextBlock[1];

                prevCipherTextBlock[0] = cipherTextBlock[0];
                prevCipherTextBlock[1] = cipherTextBlock[1];

                byte[] firstHalf = BitConverter.GetBytes(plainTextBlock[0]);
                byte[] secondHalf = BitConverter.GetBytes(plainTextBlock[1]);
                Buffer.BlockCopy(firstHalf, 0, decrypted, i, firstHalf.Length);
                Buffer.BlockCopy(secondHalf, 0, decrypted, j, secondHalf.Length);
            }

            return decrypted;
        }

        private void EncryptBlock(uint[] plainTextBlock, ref uint[] cipherTextBlock)
        {
            Debug.Assert(plainTextBlock.Length == 2);
            Debug.Assert(cipherTextBlock.Length == 2);
            cipherTextBlock[0] = plainTextBlock[0];
            cipherTextBlock[1] = plainTextBlock[1];
            for (int i = 0; i < _rounds; ++i)
            {
                SpeckEncryptRound(ref cipherTextBlock[1], ref cipherTextBlock[0], _scheduledKey[i]);
            }
        }

        private void DecryptBlock(uint[] cipherTextBlock, ref uint[] plainTextBlock)
        {
            Debug.Assert(plainTextBlock.Length == 2);
            Debug.Assert(cipherTextBlock.Length == 2);
            plainTextBlock[0] = cipherTextBlock[0];
            plainTextBlock[1] = cipherTextBlock[1];
            for (long i = (long)_rounds - 1; i >= 0; --i)
            {
                SpeckDecryptRound(ref plainTextBlock[1], ref plainTextBlock[0], _scheduledKey[i]);
            }
        }

        private static uint RotateRight(uint x, int r)
        {
            return (x >> r) | (x << (32 - r)); ;
        }

        private static uint RotateLeft(uint x, int r)
        {
            return (x << r) | (x >> (32 - r));
        }

        private static void SpeckEncryptRound(ref uint x, ref uint y, uint k)
        {
            x = RotateRight(x, 8);
            x += y;
            x ^= k;
            y = RotateLeft(y, 3);
            y ^= x;
        }

        private static void SpeckDecryptRound(ref uint x, ref uint y, uint k)
        {
            y ^= x;
            y = RotateRight(y, 3);
            x ^= k;
            x -= y;
            x = RotateLeft(x, 8);
        }

        private static uint[] KeySchedule(EncryptionType type, uint[] key)
        {
            uint rounds = (uint)GetNumberOfRounds(type);
            uint[] scheduledKey = new uint[rounds];
            switch (type)
            {
                case EncryptionType.Speck_64_96:
                {
                    uint a = key[0];
                    uint b = key[1];
                    uint c = key[2];
                    for (uint i = 0; i < rounds;)
                    {
                        scheduledKey[i] = a;
                        SpeckEncryptRound(ref b, ref a, i++);
                        scheduledKey[i] = a;
                        SpeckEncryptRound(ref c, ref a, i++);
                    }

                    return scheduledKey;
                }
                case EncryptionType.Speck_64_128:
                {
                    uint a = key[0];
                    uint b = key[1];
                    uint c = key[2];
                    uint d = key[3];
                    for (uint i = 0; i < rounds;)
                    {
                        scheduledKey[i] = a;
                        SpeckEncryptRound(ref b, ref a, i++);
                        scheduledKey[i] = a;
                        SpeckEncryptRound(ref c, ref a, i++);
                        scheduledKey[i] = a;
                        SpeckEncryptRound(ref d, ref a, i++);
                    }

                    return scheduledKey;
                }
                default:
                    throw new SpeckException("Unimplemented mode");
            }
        }
    }
}
