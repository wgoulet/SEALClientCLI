using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Microsoft.Research.SEAL;
using System.Text;
using System.IO;
using System.Buffers.Text;
using System.Globalization;
using System.Numerics;
using System.Collections.Generic;

namespace SEALClientCLI
{
    [JsonObject(MemberSerialization.Fields)]
    public class FHEParams
    {
        [JsonProperty]
        public Ciphertext param1 { get; set; }
        [JsonProperty]
        public Ciphertext param2 { get; set; }
        [JsonProperty]
        public Ciphertext result { get; set; }
        [JsonProperty]
        public string operation { get; set; }
    }
    public class SEALTransport
    {
        public string Operation { get; set; }
        public string FHEParam1 { get; set; }
        public string FHEParam2 { get; set; }
        public string FHEResult { get; set; }
        public string ContextParams { get; set; }
    }
    class Program
    {

        static HttpClient client = new HttpClient();

        static void ShowResult(FHEParams fHEParams)
        {
            Console.WriteLine($"Param1: {fHEParams.param1}\tParam2: " +
                $"{fHEParams.param2}\tresult: {fHEParams.result}");
        }


        static async Task<SEALTransport> PostFHEResultAsync(string path,SEALTransport transport)
        {
            SEALTransport fHEParams = null;
            string jsonObject = JsonConvert.SerializeObject(transport);
            var content = new StringContent(jsonObject, Encoding.UTF8, "application/json");

            HttpResponseMessage response = await client.PostAsync(path, content);
            if (response.IsSuccessStatusCode)
            {
                string tmp = await response.Content.ReadAsStringAsync();
                fHEParams = JsonConvert.DeserializeObject<SEALTransport>(tmp);

            }
            return fHEParams;
        }

        static void Main()
        {
            RunAsync().GetAwaiter().GetResult();
        }

        static public string SerializeSEAL(object srcObject)
        {
            MemoryStream str;
            if(srcObject is Ciphertext)
            {
                str = new MemoryStream();
                ((Ciphertext)srcObject).Save(str);
                byte[] buffer = new byte[str.Length];
                str.Seek(0, SeekOrigin.Begin);
                str.Read(buffer, 0, (int)str.Length);
                return System.Convert.ToBase64String(buffer);
            }
            else if(srcObject is Plaintext)
            {
                str = new MemoryStream();
                ((Plaintext)srcObject).Save(str);
                byte[] buffer = new byte[str.Length];
                str.Seek(0, SeekOrigin.Begin);
                str.Read(buffer, 0, (int)str.Length);
                return System.Convert.ToBase64String(buffer);
            }
            else if(srcObject is EncryptionParameters)
            {
                str = new MemoryStream();
                ((EncryptionParameters)srcObject).Save(str);
                byte[] buffer = new byte[str.Length];
                str.Seek(0, SeekOrigin.Begin);
                str.Read(buffer, 0, (int)str.Length);
                return System.Convert.ToBase64String(buffer);
            }
            return null;
        }

        private static BigInteger createBigIntFromPoly(int degree, int coeff, int baseVal, int constant, out List<int> terms)
        {
            BigInteger result = new BigInteger();
            terms = new List<int>();
            for(int i=degree;i>0; i--)
            {
                BigInteger temp = new BigInteger(baseVal);
                temp = BigInteger.Pow(temp, i);
                temp = BigInteger.Multiply(temp, new BigInteger(coeff));
                result = BigInteger.Add(result, temp);
                terms.Add(i); 
            }

            result = BigInteger.Add(result, constant);
            return result;
        }

        static async Task RunAsync()
        {
            // Update port # in the following line.
            client.BaseAddress = new Uri("http://localhost/");
            //client.BaseAddress = new Uri("https://sealserver20200623225403.azurewebsites.net/");
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/octet-stream"));
            UriBuilder builder = new UriBuilder();
            builder.Port = 50755;
            builder.Path = "sealoperation";
            using EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            ulong polyModulusDegree = 4096;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            parms.PlainModulus = new Modulus(4096);
            using SEALContext context = new SEALContext(parms);
            using Evaluator evaluator = new Evaluator(context);
            using KeyGenerator keygen = new KeyGenerator(context);
            using PublicKey publicKey = keygen.PublicKey;
            using SecretKey secretKey = keygen.SecretKey;
            using Encryptor encryptor = new Encryptor(context, publicKey);
            using Decryptor decryptor = new Decryptor(context, secretKey);


            //BigInteger bint = BigInteger.Parse("97391909619002370737223511047161666878854921822310726371156754097341907215981");
            BigInteger bint = BigInteger.Parse("998745113");
            //int xVal = 625;
            //int degree = 10;
            //int coeff = 25;
            // These are good starting points for small numbers < 100mil
            /*
            int tConst = 121;
            int xVal = 10;
            int degree = 2;
            int coeff = 3;
            */
            int tConst = 1210;
            int xVal = 25;
            int degree = 4;
            int coeff = 3;


            // Candidate first result from initial polynomial
            List<int> terms; 
            BigInteger res = createBigIntFromPoly(degree, coeff, xVal, tConst,out terms);

            // compare res to target BigInteger, if way smaller, then create a new
            // result after increasing any of the polynomial values
            while(BigInteger.Compare(res,bint) <0) // res is less than bint
            {
                BigInteger halfVal = BigInteger.Divide(bint, new BigInteger(2));
                BigInteger onePercent = BigInteger.Divide(bint, new BigInteger(100));
                BigInteger tenPercent = BigInteger.Multiply(onePercent, new BigInteger(10));
                //BigInteger quarterVal = BigInteger.Divide(bint, new BigInteger(4));
                if(BigInteger.Compare(halfVal,res) > 0)
                {
                    //coeff += 1;
                    int len = halfVal.ToString().Length;
                    int len2 = res.ToString().Length;
                    if(len == len2)
                    {
                        coeff *= 2;
                    }
                    else
                    {
                        degree += 2;
                    }
                    res = createBigIntFromPoly(degree, coeff, xVal, tConst, out terms);
                }
                else
                {
                    BigInteger difference = BigInteger.Subtract(bint, res);
                    if (BigInteger.Compare(tenPercent, difference) > 0)
                    {
                        tConst += 1111;
                    }
                    else
                    {
                        coeff += 1;
                    }
                    res = createBigIntFromPoly(degree, coeff, xVal, tConst, out terms);
                }
                //Console.WriteLine(res.ToString());
                Console.WriteLine("...");
            }
            // Res is now equal or greater to bint
            tConst = tConst - (int)BigInteger.Subtract(res, bint);
            // Now check the polynomial
            BigInteger testPoly = createBigIntFromPoly(degree, coeff, xVal, tConst, out terms);
            Console.WriteLine("For Big Integer {0}", bint.ToString());
            foreach(int term in terms)
            {
                Console.WriteLine("Polynomial term is {0}x^{1}", coeff, term);
            }
            Console.WriteLine("Final term is constant {0} with x={1}", tConst, xVal);
            byte[] bytespan = bint.ToByteArray();
            byte[] newspan = new byte[bytespan.Length];
            newspan[0] = bytespan[0];
            BigInteger binttemp = new BigInteger(bytespan);
            // Pick an 'x' value for the polynomial that is big enough to represent the upper 10 digits of the value
            BigInteger bint2 = BigInteger.Parse("7983012132846067729184195556448685457666384473549591845215215701504271855338012801306119587019479688581971723759499902125851173348207536911525267617909811");
            BigInteger bintres = bint * bint2;
            using Plaintext bPlainB = new Plaintext(bint.ToString());
            int x = 9;
            Console.WriteLine("Plain x value to set");
            Console.WriteLine(x.ToString());
            using Plaintext xPlainX = new Plaintext(Convert.ToString(x,16));
            Console.WriteLine("Hex value being set");
            Console.WriteLine(xPlainX.ToString());
            using Ciphertext xEncrypted = new Ciphertext();
            Console.WriteLine("Encrypt xPlain to xEncrypted.");
            encryptor.Encrypt(xPlainX, xEncrypted);
            int y = 5;
            Console.WriteLine("Plain y value to set");
            Console.WriteLine(y.ToString());
            using Plaintext xPlainY = new Plaintext(Convert.ToString(y, 16));
            Console.WriteLine("Hex y value being set");
            Console.WriteLine(xPlainY.ToString());
            using Ciphertext yEncrypted = new Ciphertext();
            encryptor.Encrypt(xPlainY, yEncrypted);

            FHEParams fHEParams = new FHEParams();
            fHEParams.param1 = xEncrypted;
            fHEParams.param2 = yEncrypted;
            fHEParams.result = new Ciphertext();
            // DEBUG ONLY
            Ciphertext mAnswer = new Ciphertext();
            evaluator.Multiply(fHEParams.param1, fHEParams.param2, mAnswer);
            evaluator.Add(fHEParams.param1, fHEParams.param2, fHEParams.result);
            string expAnswer = SerializeSEAL(fHEParams.result);
            using Plaintext xDecrypted2= new Plaintext();
            decryptor.Decrypt(mAnswer, xDecrypted2);
            Console.WriteLine(xDecrypted2.ToString());
            decryptor.Decrypt(fHEParams.result, xDecrypted2);
            string answer = xDecrypted2.ToString();
            int num = 0;
            Int32.TryParse(answer,System.Globalization.NumberStyles.HexNumber,CultureInfo.InvariantCulture,out num);
            Console.WriteLine("Local answer");
            Console.WriteLine(answer);
            Console.WriteLine(num.ToString());

            // END DEBUG

            //fHEParams.param1.

            fHEParams.operation = "add";

            SEALTransport transport = new SEALTransport();
            transport.ContextParams = SerializeSEAL(parms);

            transport.FHEParam1 = SerializeSEAL(fHEParams.param1);
            // Console.WriteLine(transport.FHEParam1);
            transport.FHEParam2 = SerializeSEAL(fHEParams.param2);
            transport.FHEResult = SerializeSEAL(fHEParams.result);
            transport.Operation = fHEParams.operation;

            try
            {
                // Get the parameters,
                SEALTransport response = await PostFHEResultAsync(builder.Uri.AbsoluteUri,transport);

                Ciphertext result = new Ciphertext();
                byte[] fp1 = System.Convert.FromBase64String(response.FHEResult);
                string recAnswer = response.FHEResult;
                if(expAnswer == recAnswer)
                {
                    Console.WriteLine("Expected answer matches received answer");
                }
                MemoryStream mst = new MemoryStream(fp1);
                result.Load(context, mst);
                Plaintext xDecrypted3 = new Plaintext();
                decryptor.Decrypt(result, xDecrypted3);
                answer = xDecrypted3.ToString();
                Console.WriteLine(answer);
                Console.WriteLine("Remote Decimal answer");
                Int32.TryParse(answer,System.Globalization.NumberStyles.HexNumber,CultureInfo.InvariantCulture,out num);
                Console.WriteLine(num.ToString());

            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            Console.ReadLine();
        }
    }
}

