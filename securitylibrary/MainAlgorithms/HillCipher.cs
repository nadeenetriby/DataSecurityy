using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            
           
            throw new NotImplementedException();
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<List<int>> keyMatrix = new List<List<int>>();
            int m = (int)Math.Sqrt(key.Count);
            //getting matrix shape from key
            for(int i = 0; i < m; i++)
            {
                keyMatrix.Add(new List<int>());
                for(int j = 0; j < m; j++)
                {
                    keyMatrix[i].Add(key[j+(i*m)]);
                }
            }
            //step 1-get deteriminant
            int det = Determinant(keyMatrix, m);
            int moddet = det % 26;
            if (moddet < 0) moddet += 26;

            //step 2 Calculate b = det(k)^-1 ==> ( b x det(k) mod 26 =1 )
            int b = -1;
           for(int i = 1; i < 26; i++)
           {
                if ((moddet * i) % 26 == 1)
                {
                    b = i;
                    break;
                }

           }
            if (moddet == 0 || b == -1|| (int)BigInteger.GreatestCommonDivisor(26, moddet) != 1)
            {

                throw new InvalidOperationException("invalidd");

            }
            // step 3 Apply rule kij ={b x (-1)i+j * Dij mod 26} mod 26
            List<List<int>> for_trans = new List<List<int>>();
            int sign = 1;
            for (int i=0; i < m; i++)
            {
                for_trans.Add(new List<int>());
                for (int j = 0; j <m; j++)
                {
                    List<List<int>> submatrix = Get_submatrix(m, keyMatrix,i,j);
                    if ((i + j) % 2 == 0) sign = 1;
                    else sign = -1;
                    int x = (sign *  Determinant(submatrix,m-1) )% 26;
                    if (x < 0) x += 26;
                    int val = (b * x) % 26;
                    for_trans[i].Add(val);
                    
                }
            }
             List<List<int>> Transpose = new List<List<int>>();
            //step 4 TRANSPOSE
            for (int i = 0; i < m; i++)
            {
                Transpose.Add(new List<int>());
                for (int j = 0; j < m; j++)
                {
                    Transpose[i].Add(for_trans[j][i]);
                }
            }

            //step 5 get plain text
            List<int> cipher = new List<int>(cipherText);
            List<int> final_plainText = new List<int>();
            for (int i = 0; i < cipherText.Count; i += m)
            {
                for (int j = 0; j < m; j++)
                {
                    int sum = 0;
                    for (int l = 0; l < m; l++)
                    {
                        if (i + l < cipherText.Count )
                        {
                            
                            sum += cipher[i + l] * Transpose[l][j];

                        }
                    }
                    sum = sum % 26;

                    final_plainText.Add(sum);
                }
            }

            return final_plainText;
        }
        public int Determinant(List<List<int>> keyMatrix,int m)
        {
            if (m == 1) return keyMatrix[0][0] ;
            if (m == 2) return keyMatrix[0][0] * keyMatrix[1][1] - keyMatrix[0][1] * keyMatrix[1][0];

            int sign = 1;
            int det = 0;
            for(int i = 0; i < m; i++)
            {
               
                List<List<int>> submatrix = Get_submatrix(m, keyMatrix, i ,0);
                det += (sign)*keyMatrix[0][i] * Determinant(submatrix, m-1);
                sign *= -1;
                
            }
            return  det;
        }

        //get submatrix2 for skipping each row for step 3 for decryption
        public List<List<int>> Get_submatrix(int m, List<List<int>> keyMatrix, int startCol,int row)
        {
            int rowindex = 0;
            List<List<int>> sub_keyMatrix = new List<List<int>>();
            for (int i = 0; i < m; i++)
            {
                if (row == i) continue;
                sub_keyMatrix.Add(new List<int>());
                for (int j = 0; j < m; j++)
                { 
                    if (startCol == j) continue;
                    sub_keyMatrix[rowindex].Add(keyMatrix[i][j]);
                }
                rowindex++;
            }
            return sub_keyMatrix;
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            Dictionary<char, int> mapping_letter = new Dictionary<char, int>();
            Dictionary<int, char> mapping_number = new Dictionary<int, char>();
            List<int> pt_to_num=new List<int>(plainText);
            List<int> final_plainText = new List<int>();

            int m=0;
            for (int i = 0; i < 26; i++)
            {
                mapping_letter.Add((char)('A' + i), i);
                mapping_number.Add(i, (char)('A' + i));
            }
            m = (int)Math.Sqrt(key.Count);
           
            for (int i = 0; i < plainText.Count; i++)
            {
                if (plainText[i] == ' ')
                {
                    continue;
                }
                char text = char.ToUpper((char)plainText[i]);
                if (!mapping_letter.ContainsKey(text))
                {
                    continue;
                }
                pt_to_num.Add(mapping_letter[text]);
            }
            if (pt_to_num.Count % m != 0)
            {
                for (int i = 0; i < pt_to_num.Count % m; i++)
                {
                    pt_to_num.Add(mapping_letter['X']);
                }
            }
            //this is for the repeatition of the matrices with the rest of the plain text
            for (int i = 0; i < pt_to_num.Count; i+=m)
            {
                for (int j = 0; j < m; j++)
                {
                    int sum = 0;
                    for (int k = 0; k < m; k++)
                    { 
                        if(i + k<pt_to_num.Count && j * m + k< key.Count)
                        {

                            sum += pt_to_num[i + k] * key[j *m  + k];   

                        }
                    }
                    sum = sum % 26;
                   
                    final_plainText.Add(sum);
                }
            }
            return final_plainText;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }

    }
}
