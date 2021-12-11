public class Script: ScriptBase
{
    public override async Task<HttpResponseMessage> ExecuteAsync()
    {
        await Task.CompletedTask;
        return Context.OperationId switch
        {
            "Enc" => await Encrypt(),
            "Dec" => await Decrypt(),
            _ => new HttpResponseMessage(HttpStatusCode.OK)
        };
    }

    private async Task<HttpResponseMessage> Decrypt()
    {
        var contentAsJson = JObject.Parse(await Context.Request.Content.ReadAsStringAsync().ConfigureAwait(false));
        var password = (string)contentAsJson["password"];
        var salt = (string)contentAsJson["salt"];
        var iv = (string)contentAsJson["iv"];
        var encrypted = (string)contentAsJson["encrypted"];

        var decrypted = DecryptString(password, salt, iv, encrypted);

        var response = new HttpResponseMessage(HttpStatusCode.OK);
        response.Content = CreateJsonContent((new JObject
        {
            ["decrypted"] = decrypted
        }).ToString());
        return response;
    }

    private async Task<HttpResponseMessage> Encrypt()
    {
        var contentAsJson = JObject.Parse(await Context.Request.Content.ReadAsStringAsync().ConfigureAwait(false));
        var password = (string)contentAsJson["password"];
        var salt = (string)contentAsJson["salt"];
        var plaintext = (string)contentAsJson["plaintext"];

        var (iv, encrypted) = EncryptString(password, salt, plaintext);

        var response = new HttpResponseMessage(HttpStatusCode.OK);
        response.Content = CreateJsonContent((new JObject
        {
            ["iv"] = iv,
            ["encrypted"] = encrypted
        }).ToString());
        return response;
    }


	public static (string iv, string encrypted) EncryptString(string password, string salt, string plaintext)
	{
		var rijndael = new System.Security.Cryptography.RijndaelManaged();

		byte[] keyb, ivb;
		(keyb, ivb) = GenerateKeyFromPassword(password, salt, rijndael.KeySize, rijndael.BlockSize);
		rijndael.Key = keyb;
		rijndael.IV = ivb;

		byte[] strBytes = System.Text.Encoding.UTF8.GetBytes(plaintext);

		System.Security.Cryptography.ICryptoTransform encryptor = rijndael.CreateEncryptor();
		byte[] encBytes = encryptor.TransformFinalBlock(strBytes, 0, strBytes.Length);
		encryptor.Dispose();

		string iv = System.Convert.ToBase64String(ivb);
		string encrypted = System.Convert.ToBase64String(encBytes);

		return (iv, encrypted);
	}

	public static string DecryptString(string password, string salt, string iv, string encrypted)
	{
		var rijndael = new System.Security.Cryptography.RijndaelManaged();

		byte[] keyb, ivb;
		(keyb, ivb) = GenerateKeyFromPassword(password, salt, rijndael.KeySize, rijndael.BlockSize);
		rijndael.Key = keyb;
		rijndael.IV = System.Convert.FromBase64String(iv);

		byte[] strBytes = System.Convert.FromBase64String(encrypted);

		System.Security.Cryptography.ICryptoTransform decryptor = rijndael.CreateDecryptor();
		byte[] decBytes = decryptor.TransformFinalBlock(strBytes, 0, strBytes.Length);
		decryptor.Dispose();

		return System.Text.Encoding.UTF8.GetString(decBytes);
	}

	private static (byte[] keyb, byte[] ivb) GenerateKeyFromPassword(string password, string salt, int keySize, int blockSize)
	{
		byte[] saltByte = System.Text.Encoding.UTF8.GetBytes(salt);
		System.Security.Cryptography.Rfc2898DeriveBytes deriveBytes = new System.Security.Cryptography.Rfc2898DeriveBytes(password, saltByte);
		deriveBytes.IterationCount = 1000;

		byte[] keyb = deriveBytes.GetBytes(keySize / 8);
		byte[] ivb = deriveBytes.GetBytes(blockSize / 8);

		return (keyb, ivb);
	}
}