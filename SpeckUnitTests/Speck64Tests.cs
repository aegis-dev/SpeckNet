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
    public class Speck64Tests
    {
        [TestMethod]
        public void SpeckEncryptionKey96NSATestVectors()
        {
            // Values taken from page 31
            byte[] payload = new byte[]
            {
                0x65, 0x61, 0x6e, 0x73, 0x20, 0x46, 0x61, 0x74
            };

            byte[] expected = new byte[] {
                 0x6c, 0x94, 0x75, 0x41, 0xec, 0x52, 0x79, 0x9f
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
                0x10, 0x11, 0x12, 0x13
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_64_96, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.None);

            CollectionAssert.AreEqual(encrypted, expected);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionKey96()
        {
            byte[] payload = new byte[]
            {
                0x65, 0x61, 0x6e, 0x73, 0x20, 0x46, 0x61, 0x74
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
                0x10, 0x11, 0x12, 0x13
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_64_96, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.None);
            byte[] decrypted = speck.Decrypt(encrypted, Padding.None);

            CollectionAssert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionPaddedKey96()
        {
            byte[] payload = new byte[]
            {
                0x65, 0x61, 0x6e, 0x73, 0x20, 0x46, 0x61, 0x74
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
                0x10, 0x11, 0x12, 0x13
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_64_96, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.PKCS7);
            byte[] decrypted = speck.Decrypt(encrypted, Padding.PKCS7);

            CollectionAssert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionPadded2Key96()
        {
            byte[] payload = new byte[]
            {
                0x65, 0x61, 0x6e, 0x73, 0x20, 0x46, 0x61, 0x74
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
                0x10, 0x11, 0x12, 0x13
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_64_96, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.PKCS7);
            byte[] decrypted = speck.Decrypt(encrypted, Padding.PKCS7);

            CollectionAssert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionCBCKey96()
        {
            byte[] payload = new byte[]
            {
                0x65, 0x61, 0x6e, 0x73, 0x20, 0x46, 0x61, 0x74
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
                0x10, 0x11, 0x12, 0x13
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_64_96, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, EncryptionMode.CBC, Padding.None);
            byte[] decrypted = speck.Decrypt(encrypted, EncryptionMode.CBC, Padding.None);

            CollectionAssert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void SpeckEncryptionKey128NSATestVectors()
        {
            // Values taken from page 32
            byte[] payload = new byte[]
            {
                0x2d, 0x43, 0x75, 0x74, 0x74, 0x65, 0x72, 0x3b
            };

            byte[] expected = new byte[] {
                 0x8b, 0x02, 0x4e, 0x45, 0x48, 0xa5, 0x6f, 0x8c
            };

            byte[] keyBytes = new byte[] 
            {
                0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
                0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1a, 0x1b,
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_64_128, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.None);

            CollectionAssert.AreEqual(encrypted, expected);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionKey128()
        {
            byte[] payload = new byte[]
            {
                0x2d, 0x43, 0x75, 0x74, 0x74, 0x65, 0x72, 0x3b
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
                0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1a, 0x1b,
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_64_128, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.None);
            byte[] decrypted = speck.Decrypt(encrypted, Padding.None);

            CollectionAssert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionPaddedKey128()
        {
            byte[] payload = new byte[]
            {
                0x2d, 0x43, 0x75, 0x74, 0x74, 0x65, 0x72, 0x3b
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
                0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1a, 0x1b,
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_64_128, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.PKCS7);
            byte[] decrypted = speck.Decrypt(encrypted, Padding.PKCS7);

            CollectionAssert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionPadded2Key128()
        {
            byte[] payload = new byte[]
            {
                0x2d, 0x43, 0x75, 0x74, 0x74, 0x65, 0x72, 0x3b
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
                0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1a, 0x1b,
            };
            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_64_128, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, Padding.PKCS7);
            byte[] decrypted = speck.Decrypt(encrypted, Padding.PKCS7);

            CollectionAssert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void SpeckEncryptionDecryptionCBCKey128()
        {
            byte[] payload = new byte[]
            {
                0x2d, 0x43, 0x75, 0x74, 0x74, 0x65, 0x72, 0x3b
            };

            byte[] keyBytes = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
                0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1a, 0x1b,
            };

            Speck speck = SpeckProvider.NewInstance(EncryptionType.Speck_64_128, keyBytes);

            byte[] encrypted = speck.Encrypt(payload, EncryptionMode.CBC, Padding.PKCS7);
            byte[] decrypted = speck.Decrypt(encrypted, EncryptionMode.CBC, Padding.PKCS7);

            CollectionAssert.AreEqual(payload, decrypted);
        }
    }
}
