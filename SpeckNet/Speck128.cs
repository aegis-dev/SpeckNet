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
    public sealed class Speck128 : Speck
    {
        private ulong[] _scheduledKey;

        internal Speck128(EncryptionType type, ulong[] key) : base(type)
        {
            if (!IsKeyValid<ulong>(type, key))
            {
                throw new SpeckException("Invalid key length");
            }
            _scheduledKey = KeySchedule(type, key);
        }
        protected override byte[] EncryptECB(byte[] plainText)
        {
            int blockSize = GetBlockSizeInBytes(_type);
            byte[] encrypted = new byte[plainText.Length];

            ulong[] plainTextBlock = new ulong[2];
            ulong[] cipherTextBlock = new ulong[2];
            for (int i = 0; i < plainText.Length; i += blockSize)
            {
                int j = i + (blockSize / 2);
                plainTextBlock[0] = BitConverter.ToUInt64(plainText, i);
                plainTextBlock[1] = BitConverter.ToUInt64(plainText, j);

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

            ulong[] plainTextBlock = new ulong[2];
            ulong[] cipherTextBlock = new ulong[2];
            ulong[] prevCipherTextBlock = new ulong[] { 0, 0 };
            for (int i = 0; i < plainText.Length; i += blockSize)
            {
                int j = i + (blockSize / 2);
                plainTextBlock[0] = BitConverter.ToUInt64(plainText, i);
                plainTextBlock[1] = BitConverter.ToUInt64(plainText, j);

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

            ulong[] plainTextBlock = new ulong[2];
            ulong[] cipherTextBlock = new ulong[2];
            for (int i = 0; i < cipherText.Length; i += blockSize)
            {
                int j = i + (blockSize / 2);
                cipherTextBlock[0] = BitConverter.ToUInt64(cipherText, i);
                cipherTextBlock[1] = BitConverter.ToUInt64(cipherText, j);

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

            ulong[] plainTextBlock = new ulong[2];
            ulong[] cipherTextBlock = new ulong[2];
            ulong[] prevCipherTextBlock = new ulong[] { 0, 0 };
            for (int i = 0; i < cipherText.Length; i += blockSize)
            {
                int j = i + (blockSize / 2);
                cipherTextBlock[0] = BitConverter.ToUInt64(cipherText, i);
                cipherTextBlock[1] = BitConverter.ToUInt64(cipherText, j);

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

        private void EncryptBlock(ulong[] plainTextBlock, ref ulong[] cipherTextBlock)
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

        private void DecryptBlock(ulong[] cipherTextBlock, ref ulong[] plainTextBlock)
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

        private static ulong RotateRight(ulong x, int r)
        {
            return (x >> r) | (x << (64 - r)); ;
        }

        private static ulong RotateLeft(ulong x, int r)
        {
            return (x << r) | (x >> (64 - r));
        }

        private static void SpeckEncryptRound(ref ulong x, ref ulong y, ulong k) 
        {
            x = RotateRight(x, 8);
            x += y;
            x ^= k;
            y = RotateLeft(y, 3);
            y ^= x;
        }

        private static void SpeckDecryptRound(ref ulong x, ref ulong y, ulong k)
        {
            y ^= x;
            y = RotateRight(y, 3);
            x ^= k;
            x -= y;
            x = RotateLeft(x, 8);
        }

        private static ulong[] KeySchedule(EncryptionType type, ulong[] key)
        {
            ulong rounds = (ulong)GetNumberOfRounds(type);
            ulong[] scheduledKey = new ulong[rounds];
            switch (type)
            {
                case EncryptionType.Speck_128_128:
                {
                    ulong i;
                    ulong a = key[0];
                    ulong b = key[1];
                    for (i = 0; i < rounds - 1;)
                    {
                        scheduledKey[i] = a;
                        SpeckEncryptRound(ref b, ref a, i++);
                    }
                    scheduledKey[i] = a;

                    return scheduledKey;
                }
                case EncryptionType.Speck_128_192:
                {
                    ulong i;
                    ulong a = key[0];
                    ulong b = key[1];
                    ulong c = key[2];
                    for (i = 0; i < rounds - 1;)
                    {
                        scheduledKey[i] = a;
                        SpeckEncryptRound(ref b, ref a, i++);
                        scheduledKey[i] = a;
                        SpeckEncryptRound(ref c, ref a, i++);
                    }
                    scheduledKey[i] = a;

                    return scheduledKey;
                }
                case EncryptionType.Speck_128_256:
                {
                    ulong i;
                    ulong a = key[0];
                    ulong b = key[1];
                    ulong c = key[2];
                    ulong d = key[3];
                    for (i = 0; i < rounds - 1;)
                    {
                        scheduledKey[i] = a;
                        SpeckEncryptRound(ref b, ref a, i++);
                        scheduledKey[i] = a;
                        SpeckEncryptRound(ref c, ref a, i++);
                        scheduledKey[i] = a;
                        SpeckEncryptRound(ref d, ref a, i++);
                    }
                    scheduledKey[i] = a;

                    return scheduledKey;
                }
                default:
                    throw new SpeckException("Unimplemented mode");
            }
        }

    }
}
