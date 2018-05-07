using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FileEncryptionTool;

namespace Tests {
    [TestClass]
    public class EncryptionTest {
        [TestMethod]
        public void HashPassword_ExampleString_returnEqual() {
            //arrange
            string password = "Testtest123";
            byte[] expectedResult = {161,197,195,94,68,48,156,35,26,5,53,129,72,183,200,228,65,84,166,16,193,23,17,8,130,41,177,49,198,129,144,47};
            PrivateType type = new PrivateType(typeof(RSA));
            //act
            byte[] result = (byte[])type.InvokeStatic("generateHash", new []{ password });

            //assert
            CollectionAssert.AreEqual(expectedResult, result);
        }

        [TestMethod]
        public void ValidatePassword_CorrectPassword_returnNull() {
            //arrange
            string password = "CorrectPassword!123";
            PrivateType type = new PrivateType("FileEncryptionTool", "FileEncryptionTool.User");
            string expectedResult = null;

            //act
            string result = (string)type.InvokeStatic("validatePassword", new[] { password });

            //assert
            Assert.AreEqual(expectedResult, result);
        }

        [TestMethod]
        public void GetAnuBytes_CorrectLength_correctLengthReturned() {
            //arrange
            int length = 10;

            //act
            byte[] result = MainWindow.GetAnuBytes(length);

            //assert
            Assert.AreEqual(length, result.Length);
        }
    }
}
