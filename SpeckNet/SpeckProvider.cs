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
    public static class SpeckProvider
    {
        public static Speck NewInstance(EncryptionType type, byte[] keyBytes)
        {
            switch (type)
            {
                case EncryptionType.Speck_64_96:
                case EncryptionType.Speck_64_128:
                {
                    int keyPartSize = sizeof(uint);
                    if (keyBytes.Length % keyPartSize != 0)
                    {
                        throw new SpeckException("Invalid amount of bytes in the key");
                    }

                    int numberOfKeyParts = keyBytes.Length / keyPartSize;
                    uint[] key = new uint[numberOfKeyParts];
                    int keyIdx = 0;
                    for (int offset = 0; offset < keyPartSize * numberOfKeyParts; offset += keyPartSize)
                    {
                        key[keyIdx++] = BitConverter.ToUInt32(keyBytes, offset);
                    }

                    return new Speck64(type, key);
                }
                case EncryptionType.Speck_128_128:
                case EncryptionType.Speck_128_192:
                case EncryptionType.Speck_128_256:
                {
                    int keyPartSize = sizeof(ulong);
                    if (keyBytes.Length % keyPartSize != 0)
                    {
                        throw new SpeckException("Invalid amount of bytes in the key");
                    }

                    int numberOfKeyParts = keyBytes.Length / keyPartSize;
                    ulong[] key = new ulong[numberOfKeyParts];
                    int keyIdx = 0;
                    for (int offset = 0; offset < keyPartSize * numberOfKeyParts; offset += keyPartSize)
                    {
                        key[keyIdx++] = BitConverter.ToUInt64(keyBytes, offset);
                    }

                    return new Speck128(type, key);
                }
                default:
                    break;
            }

            throw new SpeckException("Unimplemented speck algorithm type");
        }
    }
}
