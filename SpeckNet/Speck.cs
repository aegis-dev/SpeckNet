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

namespace SpeckNet
{
    public abstract class Speck
    {
        protected readonly EncryptionType _type;
        protected readonly int _rounds;

        protected Speck(EncryptionType type)
        {
            _type = type;
            _rounds = GetNumberOfRounds(type);
        }

        public byte[] Encrypt(byte[] plainText, Padding padding)
        {
            return Encrypt(plainText, EncryptionMode.ECB, padding);
        }

        public byte[] Encrypt(byte[] plainText, EncryptionMode mode, Padding padding)
        {
            int blockSize = GetBlockSizeInBytes(_type);
            if (padding == Padding.None && plainText.Length % blockSize != 0)
            {
                throw new SpeckException("Input plain text needs padding to be applied");
            }

            plainText = ApplyPadding(plainText, _type, padding);

            return mode switch
            {
                EncryptionMode.ECB => EncryptECB(plainText),
                EncryptionMode.CBC => EncryptCBC(plainText),
                _ => throw new SpeckException("Unimplemented encryption mode"),
            };
        }

        protected abstract byte[] EncryptECB(byte[] plainText);
        protected abstract byte[] EncryptCBC(byte[] plainText);


        public byte[] Decrypt(byte[] cipherText, Padding padding)
        {
            return Decrypt(cipherText, EncryptionMode.ECB, padding);
        }

        public byte[] Decrypt(byte[] cipherText, EncryptionMode mode, Padding padding)
        {
            int blockSize = GetBlockSizeInBytes(_type);
            if (cipherText.Length % blockSize != 0)
            {
                throw new SpeckException("Cipher text is not block size aligned");
            }

            byte[] decrypted = mode switch
            {
                EncryptionMode.ECB => DecryptECB(cipherText),
                EncryptionMode.CBC => DecryptCBC(cipherText),
                _ => throw new SpeckException("Unimplemented decryption mode"),
            };

            decrypted = RemovePadding(decrypted, _type, padding);

            return decrypted;
        }

        protected abstract byte[] DecryptECB(byte[] cipherText);
        protected abstract byte[] DecryptCBC(byte[] cipherText);

        protected static bool IsKeyValid<T>(EncryptionType type, T[] key)
        {
            return GetKeyWordsCount(type) == key.Length;
        }

        protected static int GetKeyWordsCount(EncryptionType type)
        {
            return type switch
            {
                EncryptionType.Speck_64_96   => 3,
                EncryptionType.Speck_64_128  => 4,
                EncryptionType.Speck_128_128 => 2,
                EncryptionType.Speck_128_192 => 3,
                EncryptionType.Speck_128_256 => 4,
                _ => throw new SpeckException("Unimplemented speck algorithm type"),
            };
        }

        protected static int GetNumberOfRounds(EncryptionType type)
        {
            return type switch
            {
                EncryptionType.Speck_64_96   => 26,
                EncryptionType.Speck_64_128  => 27,
                EncryptionType.Speck_128_128 => 32,
                EncryptionType.Speck_128_192 => 33,
                EncryptionType.Speck_128_256 => 34,
                _ => throw new SpeckException("Unimplemented speck algorithm type"),
            };
        }

        protected static int GetBlockSizeInBytes(EncryptionType type)
        {
            switch (type)
            {
                case EncryptionType.Speck_64_96:
                case EncryptionType.Speck_64_128:
                    return 8;
                case EncryptionType.Speck_128_128:
                case EncryptionType.Speck_128_192:
                case EncryptionType.Speck_128_256:
                    return 16;
                default:
                    throw new SpeckException("Unimplemented speck algorithm type");
            }
        }

        protected static byte[] ApplyPadding(byte[] data, EncryptionType type, Padding padding)
        {
            if (padding == Padding.None)
            {
                return data;
            }

            int blockSize = GetBlockSizeInBytes(type);
            int remainder = data.Length % blockSize;
            int paddingSize = blockSize - remainder;
            int newDataSize = data.Length + paddingSize;

            byte[] paddingBytes = new byte[paddingSize];
            switch (padding)
            {
                case Padding.PKCS7:
                {
                    for (int idx = 0; idx < paddingSize; ++idx)
                    {
                        paddingBytes[idx] = (byte)paddingSize;
                    }
                    break;
                }
                default:
                    throw new SpeckException("Unsupported padding");
            }

            byte[] newData = new byte[newDataSize];
            Buffer.BlockCopy(data, 0, newData, 0, data.Length);
            Buffer.BlockCopy(paddingBytes, 0, newData, data.Length, paddingBytes.Length);

            return newData;
        }

        protected static byte[] RemovePadding(byte[] data, EncryptionType type, Padding padding)
        {
            if (padding == Padding.None)
            {
                return data;
            }

            int blockSize = GetBlockSizeInBytes(type);
            byte[] lastBlock = new byte[blockSize];
            Buffer.BlockCopy(data, data.Length - blockSize, lastBlock, 0, blockSize);

            switch (padding)
            {
                case Padding.PKCS7:
                {
                    int paddingSize = lastBlock[blockSize - 1];
                    if (paddingSize > blockSize)
                    {
                        return data;
                    }
                    for (int idx = paddingSize - 1; idx > blockSize - paddingSize; --idx)
                    {
                        if (lastBlock[idx] != paddingSize)
                        {
                            return data;
                        }
                    }
                    byte[] unpaddedData = new byte[data.Length - paddingSize];
                    Buffer.BlockCopy(data, 0, unpaddedData, 0, unpaddedData.Length);
                    data = unpaddedData;
                    break;
                }
                default:
                    throw new SpeckException("Unsupported padding");
            }

            return data;
        }
    }
}
