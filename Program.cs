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

        static async Task RunAsync()
        {
            // Update port # in the following line.
            client.BaseAddress = new Uri("http://localhost/");
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
            parms.PlainModulus = new Modulus(1024);
            using SEALContext context = new SEALContext(parms);
            using Evaluator evaluator = new Evaluator(context);
            using KeyGenerator keygen = new KeyGenerator(context);
            using PublicKey publicKey = keygen.PublicKey;
            using SecretKey secretKey = keygen.SecretKey;
            using Encryptor encryptor = new Encryptor(context, publicKey);
            using Decryptor decryptor = new Decryptor(context, secretKey);


            int x = 70;
            using Plaintext xPlainX = new Plaintext(x.ToString());
            using Ciphertext xEncrypted = new Ciphertext();
            Console.WriteLine("Encrypt xPlain to xEncrypted.");
            encryptor.Encrypt(xPlainX, xEncrypted);
            int y = 29;
            using Plaintext xPlainY = new Plaintext(y.ToString());
            using Ciphertext yEncrypted = new Ciphertext();
            encryptor.Encrypt(xPlainY, yEncrypted);

            FHEParams fHEParams = new FHEParams();
            fHEParams.param1 = xEncrypted;
            fHEParams.param2 = yEncrypted;
            fHEParams.result = new Ciphertext();
            // DEBUG ONLY
            evaluator.Add(fHEParams.param1, fHEParams.param2, fHEParams.result);
            string expAnswer = SerializeSEAL(fHEParams.result);
            using Plaintext xDecrypted2= new Plaintext();
            decryptor.Decrypt(fHEParams.result, xDecrypted2);
            string answer = xDecrypted2.ToString();
            Console.WriteLine(answer);

            // END DEBUG

            //fHEParams.param1.

            fHEParams.operation = "add";

            SEALTransport transport = new SEALTransport();
            transport.ContextParams = SerializeSEAL(parms);

            // Serialize the fHEParams for sending over the wire; Save method of Ciphertext
            // is used to write the object to a stream that we'll use as a field in SEALTransport

            MemoryStream str = new MemoryStream();
            fHEParams.param1.Save(str);
            byte[] buffer = new byte[str.Length];
            str.Seek(0, SeekOrigin.Begin);
            await str.ReadAsync(buffer, 0, (int)str.Length);
            transport.FHEParam1 = System.Convert.ToBase64String(buffer);
            // Console.WriteLine(transport.FHEParam1);
            str.SetLength(0);
            fHEParams.param2.Save(str);
            buffer = new byte[str.Length];
            str.Seek(0, SeekOrigin.Begin);
            await str.ReadAsync(buffer, 0, (int)str.Length);
            transport.FHEParam2 = System.Convert.ToBase64String(buffer);
            str.SetLength(0);
            fHEParams.result.Save(str);
            buffer = new byte[str.Length];
            str.Seek(0, SeekOrigin.Begin);
            await str.ReadAsync(buffer, 0, (int)str.Length);
            transport.FHEResult = System.Convert.ToBase64String(buffer);
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

            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            Console.ReadLine();
        }
    }
}

