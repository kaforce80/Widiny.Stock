using System.Security.Cryptography;
using System.Text;

namespace Widiny.Stock.Web.Models.Auth;

public static class TotpUtility
{
    public static bool VerifyCode(string base32Secret, string code, int timestepSeconds = 30, int digits = 6, int allowedDriftWindows = 1)
    {
        if (string.IsNullOrWhiteSpace(base32Secret) || string.IsNullOrWhiteSpace(code) || code.Length != digits)
        {
            return false;
        }

        var secret = DecodeBase32(base32Secret);
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var timestep = timestamp / timestepSeconds;

        for (var offset = -allowedDriftWindows; offset <= allowedDriftWindows; offset++)
        {
            var generatedCode = GenerateCode(secret, timestep + offset, digits);
            if (CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(generatedCode), Encoding.ASCII.GetBytes(code)))
            {
                return true;
            }
        }

        return false;
    }

    public static string GenerateSecret(int numBytes = 20)
    {
        var secretBytes = RandomNumberGenerator.GetBytes(numBytes);
        return EncodeBase32(secretBytes);
    }

    private static string GenerateCode(byte[] key, long timestep, int digits)
    {
        Span<byte> counter = stackalloc byte[8];
        for (var i = 7; i >= 0; i--)
        {
            counter[i] = (byte)(timestep & 0xFF);
            timestep >>= 8;
        }

        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(counter.ToArray());
        var offset = hash[^1] & 0x0F;

        var binaryCode = ((hash[offset] & 0x7F) << 24)
            | (hash[offset + 1] << 16)
            | (hash[offset + 2] << 8)
            | hash[offset + 3];

        var otp = binaryCode % (int)Math.Pow(10, digits);
        return otp.ToString(new string('0', digits));
    }

    private static string EncodeBase32(byte[] data)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        var output = new StringBuilder();
        var value = 0;
        var bits = 0;

        foreach (var b in data)
        {
            value = (value << 8) | b;
            bits += 8;

            while (bits >= 5)
            {
                output.Append(alphabet[(value >> (bits - 5)) & 0x1F]);
                bits -= 5;
            }
        }

        if (bits > 0)
        {
            output.Append(alphabet[(value << (5 - bits)) & 0x1F]);
        }

        return output.ToString();
    }

    private static byte[] DecodeBase32(string input)
    {
        var cleanedInput = input.Trim().TrimEnd('=').ToUpperInvariant();
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        var bits = 0;
        var value = 0;
        var output = new List<byte>();

        foreach (var c in cleanedInput)
        {
            var index = alphabet.IndexOf(c);
            if (index < 0)
            {
                throw new FormatException("Base32 비밀키 형식이 올바르지 않습니다.");
            }

            value = (value << 5) | index;
            bits += 5;

            if (bits >= 8)
            {
                output.Add((byte)((value >> (bits - 8)) & 0xFF));
                bits -= 8;
            }
        }

        return output.ToArray();
    }
}
