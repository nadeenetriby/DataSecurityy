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
                    //throw new NotImplementedException();

        Dictionary<char, char> permutations = new Dictionary<char, char>();

        plainText = plainText.ToUpper();
        cipherText = cipherText.ToUpper();

        for (int i = 0; i < plainText.Length; i++)
        {
            char plainChar = plainText[i];
            char cipherChar = cipherText[i];

            // Map only if not already mapped
            if (!permutations.ContainsKey(plainChar))
            {
                permutations[plainChar] = cipherChar;
            }
        }

        // Step 2: Create a list of the full alphabet
        List<char> alphabet = new List<char>
{
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
};

        char[] key = new char[26];
        List<char> usedLetters = new List<char>();

        foreach (var pair in permutations)
        {
            usedLetters.Add(pair.Value);

            if (pair.Key >= 'A' && pair.Key <= 'Z')
            {
                //I convert the pair.key to an index and assign it to it's corresponding value
                key[pair.Key - 'A'] = pair.Value;
            }
        }

        List<char> availableLetters = alphabet.Except(usedLetters).ToList();

        int index = 0;
        for (int i = 0; i < 26; i++)
        {
            //if a letter doesn't have a letter permutation assign it to any available one
            if (key[i] == '\0')  
            {
                key[i] = availableLetters[index++];
            }
        }

        return new string(key).ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
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
            //throw new NotImplementedException();
            string frequentLetterOrder = "ETAOINSRHLDCUMFPGWYBVKXJQZ"; 

            Dictionary<char, int> cipherFrequency = new Dictionary<char, int>();

           // Count each letter in cipher text frequency and store them in a dictionary
            foreach (char c in cipher)
             {
                if (char.IsLetter(c))
                {
                  if (cipherFrequency.ContainsKey(c))
                    cipherFrequency[c]++;
                  else
                cipherFrequency[c] = 1;
             }
           }

         // Sort letters by frequency in descending order
          var sortedCipherLetters = cipherFrequency.OrderByDescending(x => x.Value).Select(x => x.Key).ToList();
          
         Dictionary<char, char> substitutionMap = new Dictionary<char, char>();

        // Map each letter in sortedCipherLetters to the frequentLetterOrder
        for (int i = 0; i < sortedCipherLetters.Count; i++)
         {
             substitutionMap[sortedCipherLetters[i]] = frequentLetterOrder[i];
         }

        StringBuilder decryptedText = new StringBuilder();

        foreach (char c in cipher)
        {
           if (substitutionMap.ContainsKey(c))
             decryptedText.Append(substitutionMap[c]);
           else
             decryptedText.Append(c);
        }

         return decryptedText.ToString().ToLower();
        }
    }
}
