using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)

            //check key is valid or not
        { int size1 = key.Length;
            string alphabets = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            char[] arr = new char[26];
            //check size of key consist of 26 letters
            if (size1 != 26){return null;}
            //check if one letter exist more than one
            for (int i = 0; i < size1; i++)
            {       //loop and compare
                for (int j = i + 1; j < size1; j++)
                {
                    if (key[i] == key[j])
                    { 
                        return null; 
                    }
                }
            }



            //each letter in key corresponding to what letter in plaintext?
            for (int i = 0; i < 26; i++)
            {   //to make sure all letters of key in upper case
                char givenkey = char.ToUpper(key[i]);
                //alphabets Ascending order in ASCII so when i do (givenkey - 'A')
                //i will get the right corresponding letter in alphabets 
                int idx = givenkey - 'A'; 
                arr[idx] = alphabets[i]; 
            }

            //because i know the ciphertxt so i can get its length 
            int size2 = cipherText.Length;
            //and make arr to store each letter of the plaintxt in the end (size of arr = number of letters of ciphertxt )
            char[] plainText = new char[size2];

            for (int i = 0; i < size2; i++)
            //store each letter inciphertxt
            {   char letter = cipherText[i];
                //check if any leter in lower case or not
                bool isLower = char.IsLower(letter);
                //convert letter to uppercase
                char letter_converted_to_upper = char.ToUpper(letter);

                // to make sure that we decrypted letters only 
              if (letter_converted_to_upper >= 'A' && letter_converted_to_upper <= 'Z')
                {
                    //when i do (givenkey - 'A').i will get the right corresponding letter in alphabets
                char plntxt = arr[letter_converted_to_upper - 'A'];
                 // return the letter to the original case(upper or lower)
                if (isLower)
                {
                        plainText[i] = char.ToLower(plntxt);
                }
                else
                {
                        plainText[i] = plntxt;
                }
              } 
              // if we found anything other letters
              else
              {     //write as it             
                    plainText[i] = letter;                 
              }
            }

            return new string(plainText);
        }


        public string Encrypt(string plainText, string key)
        { 
            string alphabets = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            //convert plaintxt to uppercase to avoid Case Sensitivity
            plainText = plainText.ToUpper();
            //to store the result
            string cipherText = "";
            int size = plainText.Length;
            //loop in plaintxt
            for (int i = 0; i < size; i++)
            {   //to get the letter in key that corresponding letter of plaintxt
                int idx = alphabets.IndexOf(plainText[i]);
                // to check if the letter exist in alphabets or not
                if (idx >= 0)
                    //get the letter in key that corresponding letter of plaintxt
                { cipherText += key[idx];}
                else
                //write as it
                {cipherText += plainText[i];}
            } return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            throw new NotImplementedException();
        }
    }
}
