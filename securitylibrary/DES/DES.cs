using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {

        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public string BinToHex(string Binary)
        {
            string hex = "";
            Dictionary<string, char> binToHex = new Dictionary<string, char>
            {
            {"0000", '0'}, {"0001", '1'}, {"0010", '2'}, {"0011", '3'},
            {"0100", '4'}, {"0101", '5'}, {"0110", '6'}, {"0111", '7'},
            {"1000", '8'}, {"1001", '9'}, {"1010", 'A'}, {"1011", 'B'},
            {"1100", 'C'}, {"1101", 'D'}, {"1110", 'E'}, {"1111", 'F'}
            };
            while (Binary.Length % 4 != 0)
            {
                Binary = "0" + Binary;
            }

            for (int i = 0; i < Binary.Length; i += 4)
            {
                string bits = Binary.Substring(i, 4);
                if (binToHex.ContainsKey(bits))
                    hex += binToHex[bits];
            }

            return hex;

        }
        public string HexToBin(string Hexa)
        {
            string bin = "";
            Dictionary<char, string> hexToBin = new Dictionary<char, string>
            {
            {'0', "0000"}, {'1', "0001"}, {'2', "0010"}, {'3', "0011"},
            {'4', "0100"}, {'5', "0101"}, {'6', "0110"}, {'7', "0111"},
            {'8', "1000"}, {'9', "1001"}, {'A', "1010"}, {'B', "1011"},
            {'C', "1100"}, {'D', "1101"}, {'E', "1110"}, {'F', "1111"}
            };
            for (int i = 0; i < Hexa.Length; i++)
            {
                char x = Hexa[i];
                bin += hexToBin[x];
            }

            return bin;

        }
        //returns string (0 to 27) for C and (28 to 55) for D

        public string PermutationChoice_1(string hexa_key)
        {
            // C and D tables
            Dictionary<int, int> C_table = new Dictionary<int, int>{
            { 0, 57 }, { 1, 49 }, { 2, 41 }, { 3, 33 }, { 4, 25 }, { 5, 17 }, { 6, 9 },
            { 7, 1 }, { 8, 58 }, { 9, 50 }, { 10, 42 }, { 11, 34 }, { 12, 26 }, { 13, 18 },
            { 14, 10 }, { 15, 2 }, { 16, 59 }, { 17, 51 }, { 18, 43 }, { 19, 35 }, { 20, 27 },
            { 21, 19 }, { 22, 11 }, { 23, 3 }, { 24, 60 }, { 25, 52 }, { 26, 44 }, { 27, 36 }
            };
            Dictionary<int, int> D_table = new Dictionary<int, int>{
            { 28, 63 }, { 29, 55 }, { 30, 47 }, { 31, 39 }, { 32, 31 }, { 33, 23 }, { 34, 15 },
            { 35, 7 }, { 36, 62 }, { 37, 54 }, { 38, 46 }, { 39, 38 }, { 40, 30 }, { 41, 22 },
            { 42, 14 }, { 43, 6 }, { 44, 61 }, { 45, 53 }, { 46, 45 }, { 47, 37 }, { 48, 29 },
            { 49, 21 }, { 50, 13 }, { 51, 5 }, { 52, 28 }, { 53, 20 }, { 54, 12 }, { 55, 4 }
            };


            //converted hexa to binary
            string binary_key = HexToBin(hexa_key);
            string pc1 = "";
            for (int i = 0; i < 28; i++)
            {
                pc1 += binary_key[C_table[i] - 1];

            }
            for (int i = 28; i < 56; i++)
            {
                pc1 += binary_key[D_table[i] - 1];

            }
            return pc1;
        }
        public string Permute_AfterSBox(string permute)
        {
            Dictionary<int, int> permute_table = new Dictionary<int, int>{
            { 0, 16 }, { 1, 7 }, { 2, 20 }, { 3, 21 },
            { 4, 29 }, { 5, 12 }, { 6, 28 }, { 7, 17 },
            { 8, 1 }, { 9, 15 }, { 10, 23 }, { 11, 26 },
            { 12, 5 }, { 13, 18 }, { 14, 31 }, { 15, 10 },
            { 16, 2 }, { 17, 8 }, { 18, 24 }, { 19, 14 },
            { 20, 32 }, { 21, 27 }, { 22, 3 }, { 23, 9 },
            { 24, 19 }, { 25, 13 }, { 26, 30 }, { 27, 6 },
            { 28, 22 }, { 29, 11 }, { 30, 4 }, { 31, 25 }
            };

            string permuted = "";

            for (int i = 0; i < 32; i++)
            {
                permuted += permute[permute_table[i] - 1];

            }
            return permuted;
        }

        public string LeftCircularShift( string after_pc1, int round)
        {
            Dictionary<int, int> circular_table = new Dictionary<int, int>{
            { 1, 1 }, { 2, 1 }, { 3, 2 },
            { 4, 2 }, { 5, 2 }, { 6, 2 }, { 7, 2 },
            { 8, 2 }, { 9, 1 }, { 10, 2 }, { 11, 2 },
            { 12, 2 }, { 13, 2 }, { 14, 2 }, { 15, 2 },
            { 16, 1 },
            };
            int num = circular_table[round];
            string left = after_pc1.Substring(0,28);
            for (int i = 0; i < num; i++)
            {
                char temp = left[0];
                left = left.Substring(1) + temp;
                
                
            }
            string right = after_pc1.Substring(28, 28);
            for (int i = 0; i < num; i++)
            {
                char temp = right[0];
                right = right.Substring(1) + temp;
            }
          
            return left+right;

        }


                //////////// Declare and Initialize permutation table 1 & 2 /////////////
        static int[] PC1 = {
    57, 49, 41, 33, 25, 17, 9,  1, 58, 50, 42, 34, 26, 18,
    10, 2,  59, 51, 43, 35, 27, 19, 11, 3,  60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7,  62, 54, 46, 38, 30, 22,
    14, 6,  61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4
};

        static int[] PC2 = {
    14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10,
    23, 19, 12, 4,  26, 8,  16, 7,  27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

        /////// Required Function for generate subkey: /////////
        //1.permute(Done)
        //2.shiftRotate(Done)
        //3.Converting hex to binary(Done)

        //////////////// Permute //////////////////
        static string Permute(string key, int[] permutationTable)
        {
            int size = permutationTable.Length;
            char[] permutedKey = new char[size];
            for (int i = 0; i < size; i++)
            {
                permutedKey[i] = key[permutationTable[i] - 1];
            }
            return new string(permutedKey);
        }



       ///// To shift left C & D seperately /////
  public string LeftCircularShift2(string keyPart, int shiftAmount)
  {
      if (shiftAmount != 1 && shiftAmount != 2)
          throw new ArgumentException("Shift amount must be 1 or 2");

      if (keyPart.Length != 28)
          throw new ArgumentException("Key part must be 28 bits long");

      return keyPart.Substring(shiftAmount) + keyPart.Substring(0, shiftAmount);
  }

  ////////// Generate Subkeys //////////
  public string[] GenerateSubkeys(string key)
  {
      key = HexToBin(key);
      string[] subkeys = new string[16];

      //First permute the key and get a key of 56 bits
      string permutedKey = Permute(key, PC1);

      //Second split into C and D(28 - bit each)
      string C = permutedKey.Substring(0, 28); //left Side
      string D = permutedKey.Substring(28, 28);//right side


      int[] shifts = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

      for (int round = 0; round < 16; round++)
      {
          C = LeftCircularShift2(C, shifts[round]);
          D = LeftCircularShift2(D, shifts[round]);
          subkeys[round] = Permute(C + D, PC2);
      }
      return subkeys;

  }


    }
}
