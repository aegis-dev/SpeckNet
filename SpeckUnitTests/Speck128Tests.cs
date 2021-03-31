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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using SpeckNet;
using System;

namespace SpeckUnitTests
{
    // Implemnentation verified with official implementation guide distributed by NSA
    // https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf

    [TestClass]
    public class Speck128Tests
    {
        [TestMethod]
        public void SpeckEncryptionKey128NSATestVectors()
        {
            // Values taken from page 33
            byte[] payload = new byte[]
            {
                0x20, 0x6d, 0x61, 0x64, 0x65, 0x20, 0x69, 0x74, 
                0x20, 0x65, 0x71, 0x75, 0x69, 0x76, 0x61, 0x6c
            };

            byte[] expected = new byte[] {
                0x18, 0x0d, 0x57, 0x5c, 0xdf, 0xfe, 0x60, 0x78, 
                0x65, 0x32, 0x78, 0x79, 0x51, 0x98, 0x5d, 0xa6
            };

            byte[] keyBytes = new byte[] 
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_128_128, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.None);

            CollectionAssert.AreEqual(encrypted, expected);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionKey128()
        {
            byte[] payload = new byte[]
            {
                0x20, 0x6d, 0x61, 0x64, 0x65, 0x20, 0x69, 0x74,
                0x20, 0x65, 0x71, 0x75, 0x69, 0x76, 0x61, 0x6c
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_128_128, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.None);
            byte[] decrypted = speck.Decrypt(encrypted, Padding.None);

            CollectionAssert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionPaddedKey128()
        {
            byte[] payload = new byte[]
            {
                0x20, 0x6d, 0x61, 0x64, 0x65, 0x20, 0x69, 0x74,
                0x20, 0x65, 0x71, 0x75, 0x69, 0x76, 0x61, 0x6c
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_128_128, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.PKCS7);
            byte[] decrypted = speck.Decrypt(encrypted, Padding.PKCS7);

            CollectionAssert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionPadded2Key128()
        {
            byte[] payload = new byte[]
            {
                0x20, 0x6d, 0x61, 0x64, 0x65, 0x20, 0x69, 0x74,
                0x20, 0x65, 0x71, 0x75, 0x69
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_128_128, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.PKCS7);
            byte[] decrypted = speck.Decrypt(encrypted, Padding.PKCS7);

            CollectionAssert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionCBCKey128()
        {
            byte[] payload = new byte[]
            {
                0x20, 0x6d, 0x61, 0x64, 0x65, 0x20, 0x69, 0x74,
                0x20, 0x65, 0x71, 0x75, 0x69, 0x76, 0x61, 0x6c
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_128_128, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, EncryptionMode.CBC, Padding.None);
            byte[] decrypted = speck.Decrypt(encrypted, EncryptionMode.CBC, Padding.None);

            CollectionAssert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void SpeckEncryptionKey192NSATestVectors()
        {
            // Values taken from page 34
            byte[] payload = new byte[]
            {
                0x65, 0x6e, 0x74, 0x20, 0x74, 0x6f, 0x20, 0x43, 
                0x68, 0x69, 0x65, 0x66, 0x20, 0x48, 0x61, 0x72
            };

            byte[] expected = new byte[] {
                0x86, 0x18, 0x3c, 0xe0, 0x5d, 0x18, 0xbc, 0xf9,
                0x66, 0x55, 0x13, 0x13, 0x3a, 0xcf, 0xe4, 0x1b
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_128_192, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.None);

            CollectionAssert.AreEqual(encrypted, expected);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionKey192()
        {
            byte[] payload = new byte[]
            {
                0x65, 0x6e, 0x74, 0x20, 0x74, 0x6f, 0x20, 0x43,
                0x68, 0x69, 0x65, 0x66, 0x20, 0x48, 0x61, 0x72
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_128_192, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.None);
            byte[] decrypted = speck.Decrypt(encrypted, Padding.None);

            CollectionAssert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionPaddedKey192()
        {
            byte[] payload = new byte[]
            {
                0x65, 0x6e, 0x74, 0x20, 0x74, 0x6f, 0x20, 0x43,
                0x68, 0x69, 0x65, 0x66, 0x20, 0x48, 0x61, 0x72
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_128_192, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.PKCS7);
            byte[] decrypted = speck.Decrypt(encrypted, Padding.PKCS7);

            CollectionAssert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionPadded2Key192()
        {
            byte[] payload = new byte[]
            {
                0x65, 0x6e, 0x74, 0x20, 0x74, 0x6f, 0x20, 0x43,
                0x68, 0x69, 0x65, 0x66, 0x20, 0x48
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_128_192, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.PKCS7);
            byte[] decrypted = speck.Decrypt(encrypted, Padding.PKCS7);

            CollectionAssert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionCBCKey192()
        {
            byte[] payload = new byte[]
            {
                0x65, 0x6e, 0x74, 0x20, 0x74, 0x6f, 0x20, 0x43,
                0x68, 0x69, 0x65, 0x66, 0x20, 0x48, 0x61, 0x72
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_128_192, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, EncryptionMode.CBC, Padding.None);
            byte[] decrypted = speck.Decrypt(encrypted, EncryptionMode.CBC, Padding.None);

            CollectionAssert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void SpeckEncryptionKey256NSATestVectors()
        {
            // Values taken from page 35
            byte[] payload = new byte[]
            {
                0x70, 0x6f, 0x6f, 0x6e, 0x65, 0x72, 0x2e, 0x20, 
                0x49, 0x6e, 0x20, 0x74, 0x68, 0x6f, 0x73, 0x65
            };

            byte[] expected = new byte[] {
                0x43, 0x8f, 0x18, 0x9c, 0x8d, 0xb4, 0xee, 0x4e, 
                0x3e, 0xf5, 0xc0, 0x05, 0x04, 0x01, 0x09, 0x41
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_128_256, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.None);

            CollectionAssert.AreEqual(encrypted, expected);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionKey256()
        {
            byte[] payload = new byte[]
            {
                0x70, 0x6f, 0x6f, 0x6e, 0x65, 0x72, 0x2e, 0x20,
                0x49, 0x6e, 0x20, 0x74, 0x68, 0x6f, 0x73, 0x65
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_128_256, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.None);
            byte[] decrypted = speck.Decrypt(encrypted, Padding.None);

            CollectionAssert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionPaddedKey256()
        {
            byte[] payload = new byte[]
            {
                0x70, 0x6f, 0x6f, 0x6e, 0x65, 0x72, 0x2e, 0x20,
                0x49, 0x6e, 0x20, 0x74, 0x68, 0x6f, 0x73, 0x65
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_128_256, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.PKCS7);
            byte[] decrypted = speck.Decrypt(encrypted, Padding.PKCS7);

            CollectionAssert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionPadded2Key256()
        {
            byte[] payload = new byte[]
            {
                0x70, 0x6f, 0x6f, 0x6e, 0x65, 0x72, 0x2e, 0x20,
                0x49, 0x6e, 0x20, 0x74, 0x68,
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_128_256, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.PKCS7);
            byte[] decrypted = speck.Decrypt(encrypted, Padding.PKCS7);

            CollectionAssert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionCBCKey256()
        {
            byte[] payload = new byte[]
            {
                0x70, 0x6f, 0x6f, 0x6e, 0x65, 0x72, 0x2e, 0x20,
                0x49, 0x6e, 0x20, 0x74, 0x68, 0x6f, 0x73, 0x65
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_128_256, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, EncryptionMode.CBC, Padding.None);
            byte[] decrypted = speck.Decrypt(encrypted, EncryptionMode.CBC, Padding.None);

            CollectionAssert.AreEqual(payload, decrypted);
        }
    }
}
